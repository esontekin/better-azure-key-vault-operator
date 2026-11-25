package com.akvoperator.secret;

import com.akvoperator.audit.AuditLogger;
import com.akvoperator.azure.AzureExceptionTranslator;
import com.akvoperator.common.correlation.CorrelationIdHolder;
import com.akvoperator.common.dto.OperationState;
import com.akvoperator.common.dto.OperationStatusResponse;
import com.akvoperator.common.dto.OperationType;
import com.akvoperator.common.dto.Permission;
import com.akvoperator.common.exception.AppException;
import com.akvoperator.security.AppPrincipal;
import com.akvoperator.security.VaultAuthorizationService;
import com.azure.core.util.polling.LongRunningOperationStatus;
import com.azure.core.util.polling.PollResponse;
import com.azure.core.util.polling.SyncPoller;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Tracks asynchronous Azure Key Vault soft-delete and recover operations using a bounded Caffeine cache
 * and daemon poller pool. Never reports SUCCEEDED until Azure's SyncPoller confirms
 * {@link LongRunningOperationStatus#SUCCESSFULLY_COMPLETED}.
 */
@Service
public class AsyncOperationTracker {

    private static final Logger log = LoggerFactory.getLogger(AsyncOperationTracker.class);
    private static final int MAX_TRACKED_OPERATIONS = 2_000;
    private static final Duration OPERATION_TTL = Duration.ofHours(1);
    private static final Duration DEFAULT_POLL_TIMEOUT = Duration.ofMinutes(5);
    private static final int DEFAULT_POOL_SIZE = 4;

    private final VaultAuthorizationService vaultAuthorizationService;
    private final AzureExceptionTranslator exceptionTranslator;
    private final AuditLogger auditLogger;
    private final ExecutorService executor;
    private final boolean ownsExecutor;
    private final Duration pollTimeout;
    private final Cache<String, TrackedOperation> operations;
    private final ConcurrentHashMap<String, CompletableFuture<Void>> activeFutures = new ConcurrentHashMap<>();

    @Autowired
    public AsyncOperationTracker(
            VaultAuthorizationService vaultAuthorizationService,
            AzureExceptionTranslator exceptionTranslator,
            AuditLogger auditLogger
    ) {
        this(
                vaultAuthorizationService,
                exceptionTranslator,
                auditLogger,
                createDefaultExecutor(),
                true,
                DEFAULT_POLL_TIMEOUT
        );
    }

    AsyncOperationTracker(
            VaultAuthorizationService vaultAuthorizationService,
            AzureExceptionTranslator exceptionTranslator,
            AuditLogger auditLogger,
            ExecutorService executor,
            Duration pollTimeout
    ) {
        this(vaultAuthorizationService, exceptionTranslator, auditLogger, executor, false, pollTimeout);
    }

    private AsyncOperationTracker(
            VaultAuthorizationService vaultAuthorizationService,
            AzureExceptionTranslator exceptionTranslator,
            AuditLogger auditLogger,
            ExecutorService executor,
            boolean ownsExecutor,
            Duration pollTimeout
    ) {
        this.vaultAuthorizationService = vaultAuthorizationService;
        this.exceptionTranslator = exceptionTranslator;
        this.auditLogger = auditLogger;
        this.executor = executor;
        this.ownsExecutor = ownsExecutor;
        this.pollTimeout = pollTimeout != null ? pollTimeout : DEFAULT_POLL_TIMEOUT;
        this.operations = Caffeine.newBuilder()
                .maximumSize(MAX_TRACKED_OPERATIONS)
                .expireAfterWrite(OPERATION_TTL)
                .build();
    }

    public <T, U> OperationStatusResponse trackPoller(
            String ownerSubject,
            String vaultId,
            String secretName,
            OperationType operationType,
            Permission requiredPermission,
            String correlationId,
            SyncPoller<T, U> poller,
            Runnable onSuccess,
            Consumer<AppException> onFailure
    ) {
        String operationId = UUID.randomUUID().toString();
        Instant now = Instant.now();
        TrackedOperation initial = new TrackedOperation(
                operationId,
                ownerSubject,
                vaultId,
                secretName,
                operationType,
                requiredPermission,
                OperationState.PENDING,
                now,
                now,
                null,
                null
        );
        operations.put(operationId, initial);

        CompletableFuture<Void> future = new CompletableFuture<>();
        activeFutures.put(operationId, future);

        try {
            executor.execute(() -> {
                CorrelationIdHolder.set(correlationId);
                try {
                    updateState(initial, OperationState.IN_PROGRESS, null, null);
                    PollResponse<T> finalResponse = poller.waitForCompletion(pollTimeout);
                    LongRunningOperationStatus status = finalResponse != null ? finalResponse.getStatus() : null;

                    if (LongRunningOperationStatus.SUCCESSFULLY_COMPLETED.equals(status)) {
                        if (onSuccess != null) {
                            onSuccess.run();
                        }
                        updateState(initial, OperationState.SUCCEEDED, null, null);
                    } else {
                        String message = (status == LongRunningOperationStatus.IN_PROGRESS
                                || status == LongRunningOperationStatus.NOT_STARTED)
                                ? "Azure Key Vault operation timed out before completion was confirmed."
                                : "Azure Key Vault operation did not complete successfully.";
                        AppException failure = AppException.azureUpstreamError(
                                HttpStatus.SERVICE_UNAVAILABLE,
                                message,
                                null
                        );
                        if (onFailure != null) {
                            onFailure.accept(failure);
                        }
                        updateState(initial, OperationState.FAILED, failure.getErrorCode(), failure.getSafeMessage());
                    }
                    future.complete(null);
                } catch (Throwable ex) {
                    AppException translated = exceptionTranslator.translate(ex, "Key Vault secret operation");
                    log.warn("Async operation failed [operationId={}, vaultId={}, type={}, errorCode={}]",
                            operationId, vaultId, operationType, translated.getErrorCode());
                    if (onFailure != null) {
                        try {
                            onFailure.accept(translated);
                        } catch (Throwable callbackEx) {
                            log.warn("Async operation failure callback raised an error [operationId={}]", operationId);
                        }
                    }
                    updateState(initial, OperationState.FAILED, translated.getErrorCode(), translated.getSafeMessage());
                    future.complete(null);
                } finally {
                    activeFutures.remove(operationId, future);
                    CorrelationIdHolder.clear();
                }
            });
        } catch (RuntimeException rejected) {
            activeFutures.remove(operationId, future);
            AppException translated = exceptionTranslator.translate(rejected, "Key Vault secret operation");
            updateState(initial, OperationState.FAILED, translated.getErrorCode(), translated.getSafeMessage());
            future.completeExceptionally(rejected);
        }

        return toResponse(initial);
    }

    public OperationStatusResponse getOperationStatus(String operationId) {
        AppPrincipal principal = vaultAuthorizationService.requireCurrentPrincipal();
        String correlationId = CorrelationIdHolder.getOrGenerate();

        if (operationId == null || operationId.isBlank()) {
            auditLogger.logFailure(
                    principal.subject(),
                    null,
                    null,
                    null,
                    "OPERATION_STATUS_READ",
                    "OPERATION_NOT_FOUND",
                    correlationId
            );
            throw AppException.notFound("OPERATION_NOT_FOUND", "Asynchronous operation was not found or has expired.");
        }

        TrackedOperation operation = operations.getIfPresent(operationId);
        if (operation == null) {
            auditLogger.logFailure(
                    principal.subject(),
                    null,
                    null,
                    null,
                    "OPERATION_STATUS_READ",
                    "OPERATION_NOT_FOUND",
                    correlationId
            );
            throw AppException.notFound("OPERATION_NOT_FOUND", "Asynchronous operation was not found or has expired.");
        }

        vaultAuthorizationService.requireOperationAccess(
                operation.ownerSubject(),
                operation.vaultId(),
                operation.requiredPermission()
        );

        auditLogger.logSuccess(
                principal.subject(),
                operation.vaultId(),
                operation.secretName(),
                null,
                "OPERATION_STATUS_READ",
                correlationId
        );

        return toResponse(operation);
    }

    Optional<CompletableFuture<Void>> getOperationFuture(String operationId) {
        return Optional.ofNullable(activeFutures.get(operationId));
    }

    private void updateState(TrackedOperation base, OperationState newState, String errorCode, String errorMessage) {
        TrackedOperation updated = new TrackedOperation(
                base.operationId(),
                base.ownerSubject(),
                base.vaultId(),
                base.secretName(),
                base.operationType(),
                base.requiredPermission(),
                newState,
                base.createdAt(),
                Instant.now(),
                errorCode,
                errorMessage
        );
        operations.put(base.operationId(), updated);
    }

    private static OperationStatusResponse toResponse(TrackedOperation op) {
        return new OperationStatusResponse(
                op.operationId(),
                op.vaultId(),
                op.secretName(),
                op.operationType(),
                op.state(),
                op.createdAt(),
                op.updatedAt(),
                op.errorCode(),
                op.errorMessage()
        );
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
            Thread thread = new Thread(runnable, "akv-op-poller-" + counter.getAndIncrement());
            thread.setDaemon(true);
            return thread;
        });
    }

    record TrackedOperation(
            String operationId,
            String ownerSubject,
            String vaultId,
            String secretName,
            OperationType operationType,
            Permission requiredPermission,
            OperationState state,
            Instant createdAt,
            Instant updatedAt,
            String errorCode,
            String errorMessage
    ) {
    }
}
