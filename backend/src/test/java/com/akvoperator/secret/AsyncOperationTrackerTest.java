package com.akvoperator.secret;

import com.akvoperator.audit.AuditLogger;
import com.akvoperator.azure.AzureExceptionTranslator;
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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import java.time.Duration;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AsyncOperationTrackerTest {

    private ExecutorService executor;
    private VaultAuthorizationService authorizationService;
    private AuditLogger auditLogger;
    private AsyncOperationTracker tracker;

    @BeforeEach
    void setUp() {
        executor = Executors.newFixedThreadPool(2);
        authorizationService = mock(VaultAuthorizationService.class);
        auditLogger = mock(AuditLogger.class);
        tracker = new AsyncOperationTracker(
                authorizationService,
                new AzureExceptionTranslator(),
                auditLogger,
                executor,
                Duration.ofSeconds(5)
        );
    }

    @AfterEach
    void tearDown() {
        executor.shutdownNow();
    }

    @Test
    void deniesCrossUserOrCrossVaultOperationStatusAccess() throws Exception {
        @SuppressWarnings("unchecked")
        SyncPoller<String, Void> poller = mock(SyncPoller.class);
        when(poller.waitForCompletion(any(Duration.class)))
                .thenReturn(new PollResponse<>(LongRunningOperationStatus.SUCCESSFULLY_COMPLETED, "done"));

        OperationStatusResponse op = tracker.trackPoller(
                "alice",
                "vault-a",
                "sec-1",
                OperationType.SOFT_DELETE,
                Permission.SECRET_DELETE_RECOVER,
                "corr-1",
                poller,
                () -> {
                },
                err -> {
                }
        );

        CompletableFuture<Void> future = tracker.getOperationFuture(op.operationId()).orElse(null);
        if (future != null) {
            future.get(5, TimeUnit.SECONDS);
        }

        // Bob tries to read Alice's operation -> authorization service denies
        AppPrincipal bob = new AppPrincipal("bob", "Bob", "https://idp.example.com", Set.of(), false);
        when(authorizationService.requireCurrentPrincipal()).thenReturn(bob);
        doThrow(AppException.forbidden("OPERATION_ACCESS_DENIED", "Forbidden"))
                .when(authorizationService)
                .requireOperationAccess("alice", "vault-a", Permission.SECRET_DELETE_RECOVER);

        assertThatThrownBy(() -> tracker.getOperationStatus(op.operationId()))
                .isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getStatus()).isEqualTo(HttpStatus.FORBIDDEN);
                    assertThat(appEx.getErrorCode()).isEqualTo("OPERATION_ACCESS_DENIED");
                });

        verify(authorizationService).requireOperationAccess("alice", "vault-a", Permission.SECRET_DELETE_RECOVER);
    }

    @Test
    void returns404ForUnknownOperationIdAfterRequiringAuthentication() {
        AppPrincipal alice = new AppPrincipal("alice", "Alice", "https://idp.example.com", Set.of(), false);
        when(authorizationService.requireCurrentPrincipal()).thenReturn(alice);

        assertThatThrownBy(() -> tracker.getOperationStatus("non-existent-id"))
                .isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
                    assertThat(appEx.getErrorCode()).isEqualTo("OPERATION_NOT_FOUND");
                });
    }

    @Test
    void marksOperationFailedWhenPollerThrowsException() throws Exception {
        @SuppressWarnings("unchecked")
        SyncPoller<String, Void> poller = mock(SyncPoller.class);
        when(poller.waitForCompletion(any(Duration.class)))
                .thenThrow(new RuntimeException("upstream boom"));

        OperationStatusResponse op = tracker.trackPoller(
                "alice",
                "vault-a",
                "sec-1",
                OperationType.RECOVER,
                Permission.SECRET_DELETE_RECOVER,
                "corr-2",
                poller,
                () -> {
                },
                err -> {
                }
        );

        CompletableFuture<Void> future = tracker.getOperationFuture(op.operationId()).orElse(null);
        if (future != null) {
            future.get(5, TimeUnit.SECONDS);
        }

        AppPrincipal alice = new AppPrincipal("alice", "Alice", "local", Set.of(), true);
        when(authorizationService.requireCurrentPrincipal()).thenReturn(alice);

        OperationStatusResponse status = tracker.getOperationStatus(op.operationId());
        assertThat(status.state()).isEqualTo(OperationState.FAILED);
        assertThat(status.errorCode()).isEqualTo("AZURE_UPSTREAM_ERROR");
        assertThat(status.errorMessage()).doesNotContain("upstream boom");
    }
}
