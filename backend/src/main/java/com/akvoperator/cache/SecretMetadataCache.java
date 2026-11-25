package com.akvoperator.cache;

import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.dto.SecretListSnapshotResponse;
import com.akvoperator.common.dto.SecretMetadataDto;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Bounded, TTL-governed Caffeine cache storing secret metadata snapshots only (never secret values).
 * Enforces monotonic generation IDs per vault cache key so an older in-flight background refresh
 * cannot overwrite a newer snapshot or post-mutation update.
 */
@Component
public class SecretMetadataCache {

    private static final int LOCK_STRIPES = 64;

    private final Cache<VaultCacheKey, SecretSnapshotState> snapshotCache;
    private final Cache<VaultCacheKey, Long> activeGenerations;
    private final AtomicLong generationSequence = new AtomicLong(0);
    private final Object[] stripeLocks;

    @Autowired
    public SecretMetadataCache(AppProperties appProperties) {
        this(
                Math.max(1, appProperties.getCache().getMaxVaultEntries()),
                appProperties.getMetadataTtl() != null ? appProperties.getMetadataTtl() : Duration.ofMinutes(5),
                Ticker.systemTicker()
        );
    }

    public SecretMetadataCache(int maxVaultEntries, Duration ttl, Ticker ticker) {
        int boundedMax = Math.max(1, maxVaultEntries);
        Duration effectiveTtl = (ttl == null || ttl.isNegative() || ttl.isZero())
                ? Duration.ofMinutes(5)
                : ttl;
        Ticker effectiveTicker = ticker != null ? ticker : Ticker.systemTicker();

        this.snapshotCache = Caffeine.newBuilder()
                .maximumSize(boundedMax)
                .expireAfterWrite(effectiveTtl)
                .ticker(effectiveTicker)
                .build();

        this.activeGenerations = Caffeine.newBuilder()
                .maximumSize(Math.max(10_000L, boundedMax * 10L))
                .ticker(effectiveTicker)
                .build();

        this.stripeLocks = new Object[LOCK_STRIPES];
        for (int i = 0; i < LOCK_STRIPES; i++) {
            this.stripeLocks[i] = new Object();
        }
    }

    public Optional<SecretSnapshotState> get(VaultCacheKey key) {
        Objects.requireNonNull(key, "key must not be null");
        return Optional.ofNullable(snapshotCache.getIfPresent(key));
    }

    public long currentGeneration(VaultCacheKey key) {
        Objects.requireNonNull(key, "key must not be null");
        Long gen = activeGenerations.getIfPresent(key);
        return gen != null ? gen : 0L;
    }

    public long nextGeneration(VaultCacheKey key) {
        Objects.requireNonNull(key, "key must not be null");
        synchronized (lockFor(key)) {
            long next = generationSequence.incrementAndGet();
            activeGenerations.put(key, next);
            return next;
        }
    }

    /**
     * Atomically publishes {@code state} only if {@code expectedGen} is still the active generation for {@code key}.
     * Prevents an older in-flight pagination job from overwriting a newer refresh or post-mutation update.
     */
    public boolean publishIfCurrentGeneration(VaultCacheKey key, long expectedGen, SecretSnapshotState state) {
        Objects.requireNonNull(key, "key must not be null");
        Objects.requireNonNull(state, "state must not be null");
        synchronized (lockFor(key)) {
            Long current = activeGenerations.getIfPresent(key);
            if (current == null || current != expectedGen) {
                return false;
            }
            snapshotCache.put(key, state);
            return true;
        }
    }

    /**
     * Advances the vault generation ID (invalidating any older in-flight refresh) and upserts the
     * mutated secret metadata in the cached snapshot if one is present.
     */
    public long applyMutationUpsert(VaultCacheKey key, SecretMetadataDto updatedItem) {
        Objects.requireNonNull(key, "key must not be null");
        Objects.requireNonNull(updatedItem, "updatedItem must not be null");
        synchronized (lockFor(key)) {
            long newGen = generationSequence.incrementAndGet();
            activeGenerations.put(key, newGen);

            SecretSnapshotState existing = snapshotCache.getIfPresent(key);
            if (existing != null) {
                List<SecretMetadataDto> updatedItems = upsertByName(existing.items(), updatedItem);
                List<SecretMetadataDto> updatedLastSuccess = existing.lastSuccessfulItems().isEmpty()
                        ? existing.lastSuccessfulItems()
                        : upsertByName(existing.lastSuccessfulItems(), updatedItem);

                SecretSnapshotState nextState = new SecretSnapshotState(
                        existing.vaultId(),
                        existing.status(),
                        newGen,
                        updatedItems.size(),
                        existing.pagesLoaded(),
                        existing.stale(),
                        existing.lastSuccessfulSyncAt(),
                        existing.lastAttemptAt(),
                        existing.errorCode(),
                        existing.errorMessage(),
                        updatedItems,
                        updatedLastSuccess
                );
                snapshotCache.put(key, nextState);
            }
            return newGen;
        }
    }

    /**
     * Advances the vault generation ID (invalidating any older in-flight refresh) and removes the
     * deleted secret from the cached snapshot if one is present.
     */
    public long applyMutationDelete(VaultCacheKey key, String secretName) {
        Objects.requireNonNull(key, "key must not be null");
        Objects.requireNonNull(secretName, "secretName must not be null");
        synchronized (lockFor(key)) {
            long newGen = generationSequence.incrementAndGet();
            activeGenerations.put(key, newGen);

            SecretSnapshotState existing = snapshotCache.getIfPresent(key);
            if (existing != null) {
                List<SecretMetadataDto> updatedItems = removeByName(existing.items(), secretName);
                List<SecretMetadataDto> updatedLastSuccess = existing.lastSuccessfulItems().isEmpty()
                        ? existing.lastSuccessfulItems()
                        : removeByName(existing.lastSuccessfulItems(), secretName);

                SecretSnapshotState nextState = new SecretSnapshotState(
                        existing.vaultId(),
                        existing.status(),
                        newGen,
                        updatedItems.size(),
                        existing.pagesLoaded(),
                        existing.stale(),
                        existing.lastSuccessfulSyncAt(),
                        existing.lastAttemptAt(),
                        existing.errorCode(),
                        existing.errorMessage(),
                        updatedItems,
                        updatedLastSuccess
                );
                snapshotCache.put(key, nextState);
            }
            return newGen;
        }
    }

    /**
     * Advances the vault generation ID and invalidates the cached snapshot entry.
     */
    public long invalidate(VaultCacheKey key) {
        Objects.requireNonNull(key, "key must not be null");
        synchronized (lockFor(key)) {
            long newGen = generationSequence.incrementAndGet();
            activeGenerations.put(key, newGen);
            snapshotCache.invalidate(key);
            return newGen;
        }
    }

    public SecretListSnapshotResponse toResponse(SecretSnapshotState state) {
        Objects.requireNonNull(state, "state must not be null");
        return new SecretListSnapshotResponse(
                state.vaultId(),
                state.status(),
                state.generationId(),
                state.loadedCount(),
                state.pagesLoaded(),
                state.stale(),
                state.lastSuccessfulSyncAt(),
                state.lastAttemptAt(),
                state.errorCode(),
                state.errorMessage(),
                state.items()
        );
    }

    public void cleanUp() {
        snapshotCache.cleanUp();
    }

    public long estimatedSize() {
        return snapshotCache.estimatedSize();
    }

    private Object lockFor(VaultCacheKey key) {
        int index = key.hashCode() & (LOCK_STRIPES - 1);
        return stripeLocks[index];
    }

    private static List<SecretMetadataDto> upsertByName(List<SecretMetadataDto> source, SecretMetadataDto item) {
        List<SecretMetadataDto> result = new ArrayList<>(source.size() + 1);
        boolean replaced = false;
        for (SecretMetadataDto existing : source) {
            if (existing.name().equals(item.name())) {
                result.add(item);
                replaced = true;
            } else {
                result.add(existing);
            }
        }
        if (!replaced) {
            result.add(item);
        }
        return result;
    }

    private static List<SecretMetadataDto> removeByName(List<SecretMetadataDto> source, String secretName) {
        List<SecretMetadataDto> result = new ArrayList<>(source.size());
        for (SecretMetadataDto existing : source) {
            if (!existing.name().equals(secretName)) {
                result.add(existing);
            }
        }
        return result;
    }
}
