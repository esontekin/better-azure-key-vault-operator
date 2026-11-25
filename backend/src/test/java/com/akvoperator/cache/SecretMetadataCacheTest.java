package com.akvoperator.cache;

import com.akvoperator.common.dto.SecretListSnapshotResponse;
import com.akvoperator.common.dto.SecretMetadataDto;
import com.akvoperator.common.dto.SyncStatus;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

class SecretMetadataCacheTest {

    @Test
    void isolatesEntriesByTenantVaultAndCredentialContext() {
        SecretMetadataCache cache = new SecretMetadataCache(10, Duration.ofMinutes(5), System::nanoTime);

        VaultCacheKey keyTenantA = new VaultCacheKey("tenant-a", "vault-1", "ctx-1");
        VaultCacheKey keyTenantB = new VaultCacheKey("tenant-b", "vault-1", "ctx-1");
        VaultCacheKey keyCtx2 = new VaultCacheKey("tenant-a", "vault-1", "ctx-2");

        long genA = cache.nextGeneration(keyTenantA);
        long genB = cache.nextGeneration(keyTenantB);
        long genC = cache.nextGeneration(keyCtx2);

        cache.publishIfCurrentGeneration(keyTenantA, genA, completeSnapshot("vault-1", genA, List.of(metadata("sec-a", "v1"))));
        cache.publishIfCurrentGeneration(keyTenantB, genB, completeSnapshot("vault-1", genB, List.of(metadata("sec-b", "v1"))));
        cache.publishIfCurrentGeneration(keyCtx2, genC, completeSnapshot("vault-1", genC, List.of(metadata("sec-c", "v1"))));

        assertThat(cache.get(keyTenantA).orElseThrow().items()).extracting(SecretMetadataDto::name).containsExactly("sec-a");
        assertThat(cache.get(keyTenantB).orElseThrow().items()).extracting(SecretMetadataDto::name).containsExactly("sec-b");
        assertThat(cache.get(keyCtx2).orElseThrow().items()).extracting(SecretMetadataDto::name).containsExactly("sec-c");
    }

    @Test
    void expiresEntriesAfterConfiguredTtl() {
        AtomicLong fakeNanos = new AtomicLong(0L);
        SecretMetadataCache cache = new SecretMetadataCache(10, Duration.ofMinutes(5), fakeNanos::get);
        VaultCacheKey key = new VaultCacheKey("tenant-1", "vault-1", "ctx-1");

        long gen = cache.nextGeneration(key);
        cache.publishIfCurrentGeneration(key, gen, completeSnapshot("vault-1", gen, List.of(metadata("db-pass", "v1"))));
        assertThat(cache.get(key)).isPresent();

        // Advance 4m59s — still valid
        fakeNanos.addAndGet(Duration.ofSeconds(299).toNanos());
        cache.cleanUp();
        assertThat(cache.get(key)).isPresent();

        // Advance past 5m TTL — expired
        fakeNanos.addAndGet(Duration.ofSeconds(2).toNanos());
        cache.cleanUp();
        assertThat(cache.get(key)).isEmpty();
    }

    @Test
    void enforcesBoundedMaximumSize() {
        SecretMetadataCache cache = new SecretMetadataCache(2, Duration.ofMinutes(5), System::nanoTime);

        for (int i = 0; i < 10; i++) {
            VaultCacheKey key = new VaultCacheKey("tenant-1", "vault-" + i, "ctx-1");
            long gen = cache.nextGeneration(key);
            cache.publishIfCurrentGeneration(key, gen, completeSnapshot("vault-" + i, gen, List.of(metadata("s-" + i, "v1"))));
        }
        cache.cleanUp();

        assertThat(cache.estimatedSize()).isLessThanOrEqualTo(2L);
    }

    @Test
    void generationIdPreventsStaleRefreshFromOverwritingNewerMutationOrSnapshot() {
        SecretMetadataCache cache = new SecretMetadataCache(10, Duration.ofMinutes(5), System::nanoTime);
        VaultCacheKey key = new VaultCacheKey("tenant-1", "vault-1", "ctx-1");

        long staleGen = cache.nextGeneration(key);
        assertThat(cache.publishIfCurrentGeneration(
                key,
                staleGen,
                completeSnapshot("vault-1", staleGen, List.of(metadata("alpha", "v1")))
        )).isTrue();

        // Mutation bumps generation and upserts beta
        long mutationGen = cache.applyMutationUpsert(key, metadata("beta", "v1"));
        assertThat(mutationGen).isGreaterThan(staleGen);

        // Stale in-flight refresh tries to overwrite with staleGen -> rejected!
        boolean published = cache.publishIfCurrentGeneration(
                key,
                staleGen,
                completeSnapshot("vault-1", staleGen, List.of(metadata("alpha", "v1")))
        );
        assertThat(published).isFalse();

        SecretSnapshotState current = cache.get(key).orElseThrow();
        assertThat(current.generationId()).isEqualTo(mutationGen);
        assertThat(current.items()).extracting(SecretMetadataDto::name).containsExactly("alpha", "beta");

        // Delete removes alpha and advances generation again
        long deleteGen = cache.applyMutationDelete(key, "alpha");
        assertThat(deleteGen).isGreaterThan(mutationGen);
        SecretListSnapshotResponse response = cache.toResponse(cache.get(key).orElseThrow());
        assertThat(response.items()).extracting(SecretMetadataDto::name).containsExactly("beta");
        assertThat(response.loadedCount()).isEqualTo(1);
    }

    private static SecretSnapshotState completeSnapshot(String vaultId, long gen, List<SecretMetadataDto> items) {
        Instant now = Instant.now();
        return new SecretSnapshotState(
                vaultId,
                SyncStatus.COMPLETE,
                gen,
                items.size(),
                1,
                false,
                now,
                now,
                null,
                null,
                items,
                items
        );
    }

    private static SecretMetadataDto metadata(String name, String version) {
        Instant now = Instant.now();
        return new SecretMetadataDto(name, version, true, now, now, null, null, "text/plain", Map.of(), false);
    }
}
