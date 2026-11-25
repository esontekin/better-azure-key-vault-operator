package com.akvoperator.secret;

import com.akvoperator.azure.AzureExceptionTranslator;
import com.akvoperator.azure.SecretClientProvider;
import com.akvoperator.cache.SecretMetadataCache;
import com.akvoperator.cache.SecretSnapshotState;
import com.akvoperator.cache.VaultCacheKey;
import com.akvoperator.common.dto.SecretMetadataDto;
import com.akvoperator.common.dto.SyncStatus;
import com.akvoperator.common.exception.AppException;
import com.akvoperator.vault.VaultDescriptor;
import com.azure.core.http.rest.PagedResponse;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.SecretProperties;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Progressive multi-page background loader for Azure Key Vault secret metadata.
 * Walks all continuation pages via {@code listPropertiesOfSecrets().iterableByPage()},
 * publishes progressive snapshots after every page, coalesces concurrent refreshes per vault,
 * and never fetches secret values.
 */
@Service
public class SecretPaginationService {

    private static final Logger log = LoggerFactory.getLogger(SecretPaginationService.class);
    private static final int DEFAULT_POOL_SIZE = 4;

    private final SecretClientProvider secretClientProvider;
    private final SecretMetadataCache cache;
    private final AzureExceptionTranslator exceptionTranslator;
    private final ExecutorService executor;
    private final boolean ownsExecutor;
    private final ConcurrentHashMap<VaultCacheKey, CompletableFuture<Void>> inFlight = new ConcurrentHashMap<>();

    @Autowired
    public SecretPaginationService(
            SecretClientProvider secretClientProvider,
            SecretMetadataCache cache,
            AzureExceptionTranslator exceptionTranslator
    ) {
        this(secretClientProvider, cache, exceptionTranslator, createDefaultExecutor(), true);
    }

    SecretPaginationService(
            SecretClientProvider secretClientProvider,
            SecretMetadataCache cache,
            AzureExceptionTranslator exceptionTranslator,
            ExecutorService executor
    ) {
        this(secretClientProvider, cache, exceptionTranslator, executor, false);
    }

    private SecretPaginationService(
            SecretClientProvider secretClientProvider,
            SecretMetadataCache cache,
            AzureExceptionTranslator exceptionTranslator,
            ExecutorService executor,
            boolean ownsExecutor
    ) {
        this.secretClientProvider = secretClientProvider;
        this.cache = cache;
        this.exceptionTranslator = exceptionTranslator;
        this.executor = executor;
        this.ownsExecutor = ownsExecutor;
    }

    public VaultCacheKey cacheKeyFor(VaultDescriptor vault) {
        return new VaultCacheKey(
                secretClientProvider.getTenantId(),
                vault.opaqueId(),
                secretClientProvider.getCredentialContextId()
        );
    }

    public SecretSnapshotState getOrStartRefresh(VaultDescriptor vault) {
        VaultCacheKey key = cacheKeyFor(vault);
        Optional<SecretSnapshotState> cached = cache.get(key);
        if (cached.isPresent() && cached.get().status() != SyncStatus.IDLE) {
            return cached.get();
        }
        return startOrCoalesceRefresh(vault);
    }

    /**
     * Starts a background pagination refresh for the vault, or coalesces into an already-running
     * refresh for the same {@link VaultCacheKey}.
     */
    public SecretSnapshotState startOrCoalesceRefresh(VaultDescriptor vault) {
        VaultCacheKey key = cacheKeyFor(vault);
        AtomicBoolean startedByCaller = new AtomicBoolean(false);
        RefreshContext[] contextHolder = new RefreshContext[1];

        CompletableFuture<Void> future = inFlight.compute(key, (k, existing) -> {
            if (existing != null && !existing.isDone()) {
                return existing;
            }
            SecretSnapshotState previous = cache.get(k).orElse(null);
            List<SecretMetadataDto> previousSuccessfulItems = previous != null
                    ? previous.lastSuccessfulItems()
                    : List.of();
            Instant previousSuccessfulSyncAt = previous != null
                    ? previous.lastSuccessfulSyncAt()
                    : null;

            long generationId = cache.nextGeneration(k);
            Instant attemptAt = Instant.now();
            SecretSnapshotState initialLoading = new SecretSnapshotState(
                    vault.opaqueId(),
                    SyncStatus.LOADING,
                    generationId,
                    0,
                    0,
                    false,
                    previousSuccessfulSyncAt,
                    attemptAt,
                    null,
                    null,
                    List.of(),
                    previousSuccessfulItems
            );
            cache.publishIfCurrentGeneration(k, generationId, initialLoading);

            contextHolder[0] = new RefreshContext(
                    generationId,
                    attemptAt,
                    previousSuccessfulSyncAt,
                    previousSuccessfulItems,
                    initialLoading
            );
            startedByCaller.set(true);
            return new CompletableFuture<>();
        });

        if (startedByCaller.get()) {
            RefreshContext ctx = contextHolder[0];
            try {
                executor.execute(() -> {
                    try {
                        runPagination(vault, key, ctx);
                        future.complete(null);
                    } catch (Throwable t) {
                        future.completeExceptionally(t);
                    } finally {
                        inFlight.remove(key, future);
                    }
                });
            } catch (RuntimeException rejected) {
                inFlight.remove(key, future);
                future.completeExceptionally(rejected);
                AppException translated = exceptionTranslator.translate(rejected, "Key Vault secrets");
                publishFailureSnapshot(vault, key, ctx, 0, List.of(), translated);
            }
            return cache.get(key).orElse(ctx.initialState());
        }

        return cache.get(key)
                .orElseGet(() -> SecretSnapshotState.idle(vault.opaqueId(), cache.currentGeneration(key)));
    }

    Optional<CompletableFuture<Void>> getInFlightRefresh(VaultCacheKey key) {
        return Optional.ofNullable(inFlight.get(key));
    }

    private void runPagination(VaultDescriptor vault, VaultCacheKey key, RefreshContext ctx) {
        LinkedHashMap<String, SecretMetadataDto> accumulated = new LinkedHashMap<>();
        int pagesLoaded = 0;

        try {
            SecretClient readClient = secretClientProvider.getReadClient(vault);
            Iterable<PagedResponse<SecretProperties>> pages = readClient.listPropertiesOfSecrets().iterableByPage();

            for (PagedResponse<SecretProperties> page : pages) {
                if (cache.currentGeneration(key) != ctx.generationId()) {
                    log.debug("Aborting superseded pagination refresh [vaultId={}, generationId={}]",
                            vault.opaqueId(), ctx.generationId());
                    return;
                }

                pagesLoaded++;
                List<SecretProperties> values = page != null ? page.getValue() : null;
                if (values != null) {
                    for (SecretProperties props : values) {
                        if (props == null || props.getName() == null || props.getName().isBlank()) {
                            continue;
                        }
                        accumulated.put(props.getName(), SecretDtoMapper.toMetadataDto(props));
                    }
                }

                List<SecretMetadataDto> currentItems = List.copyOf(accumulated.values());
                SecretSnapshotState progressState = new SecretSnapshotState(
                        vault.opaqueId(),
                        SyncStatus.LOADING,
                        ctx.generationId(),
                        currentItems.size(),
                        pagesLoaded,
                        false,
                        ctx.previousSuccessfulSyncAt(),
                        ctx.attemptAt(),
                        null,
                        null,
                        currentItems,
                        ctx.previousSuccessfulItems()
                );

                if (!cache.publishIfCurrentGeneration(key, ctx.generationId(), progressState)) {
                    log.debug("Stopping superseded pagination refresh after page {} [vaultId={}, generationId={}]",
                            pagesLoaded, vault.opaqueId(), ctx.generationId());
                    return;
                }
            }

            Instant completedAt = Instant.now();
            List<SecretMetadataDto> finalItems = List.copyOf(accumulated.values());
            SecretSnapshotState completeState = new SecretSnapshotState(
                    vault.opaqueId(),
                    SyncStatus.COMPLETE,
                    ctx.generationId(),
                    finalItems.size(),
                    pagesLoaded,
                    false,
                    completedAt,
                    ctx.attemptAt(),
                    null,
                    null,
                    finalItems,
                    finalItems
            );
            cache.publishIfCurrentGeneration(key, ctx.generationId(), completeState);
        } catch (Throwable ex) {
            AppException translated = exceptionTranslator.translate(ex, "Key Vault secrets");
            log.warn("Secret metadata pagination failed [vaultId={}, generationId={}, pagesLoaded={}, errorCode={}]",
                    vault.opaqueId(), ctx.generationId(), pagesLoaded, translated.getErrorCode());
            publishFailureSnapshot(vault, key, ctx, pagesLoaded, List.copyOf(accumulated.values()), translated);
        }
    }

    private void publishFailureSnapshot(
            VaultDescriptor vault,
            VaultCacheKey key,
            RefreshContext ctx,
            int pagesLoaded,
            List<SecretMetadataDto> partialItems,
            AppException translated
    ) {
        if (pagesLoaded > 0) {
            SecretSnapshotState partialErrorState = new SecretSnapshotState(
                    vault.opaqueId(),
                    SyncStatus.PARTIAL_ERROR,
                    ctx.generationId(),
                    partialItems.size(),
                    pagesLoaded,
                    true,
                    ctx.previousSuccessfulSyncAt(),
                    ctx.attemptAt(),
                    translated.getErrorCode(),
                    translated.getSafeMessage(),
                    partialItems,
                    ctx.previousSuccessfulItems()
            );
            cache.publishIfCurrentGeneration(key, ctx.generationId(), partialErrorState);
        } else {
            boolean hasPriorSuccess = ctx.previousSuccessfulItems() != null && !ctx.previousSuccessfulItems().isEmpty();
            List<SecretMetadataDto> fallbackItems = hasPriorSuccess ? ctx.previousSuccessfulItems() : List.of();
            SecretSnapshotState errorState = new SecretSnapshotState(
                    vault.opaqueId(),
                    SyncStatus.ERROR,
                    ctx.generationId(),
                    fallbackItems.size(),
                    0,
                    hasPriorSuccess,
                    ctx.previousSuccessfulSyncAt(),
                    ctx.attemptAt(),
                    translated.getErrorCode(),
                    translated.getSafeMessage(),
                    fallbackItems,
                    ctx.previousSuccessfulItems()
            );
            cache.publishIfCurrentGeneration(key, ctx.generationId(), errorState);
        }
    }

    @PreDestroy
    public void shutdown() {
        if (!ownsExecutor) {
            return;
        }
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            executor.shutdownNow();
        }
    }

    private static ExecutorService createDefaultExecutor() {
        AtomicInteger counter = new AtomicInteger(1);
        return Executors.newFixedThreadPool(DEFAULT_POOL_SIZE, runnable -> {
            Thread thread = new Thread(runnable, "akv-pagination-" + counter.getAndIncrement());
            thread.setDaemon(true);
            return thread;
        });
    }

    private record RefreshContext(
            long generationId,
            Instant attemptAt,
            Instant previousSuccessfulSyncAt,
            List<SecretMetadataDto> previousSuccessfulItems,
            SecretSnapshotState initialState
    ) {
    }
}
