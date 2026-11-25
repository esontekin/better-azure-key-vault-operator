package com.akvoperator.secret;

import com.akvoperator.audit.AuditEvent;
import com.akvoperator.audit.AuditLogger;
import com.akvoperator.azure.AzureExceptionTranslator;
import com.akvoperator.azure.SecretClientProvider;
import com.akvoperator.cache.SecretMetadataCache;
import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.dto.CreateSecretRequest;
import com.akvoperator.common.dto.DeleteSecretRequest;
import com.akvoperator.common.dto.DeletedSecretDto;
import com.akvoperator.common.dto.OperationState;
import com.akvoperator.common.dto.OperationStatusResponse;
import com.akvoperator.common.dto.OperationType;
import com.akvoperator.common.dto.Permission;
import com.akvoperator.common.dto.SecretMetadataDto;
import com.akvoperator.common.dto.SecretValueResponse;
import com.akvoperator.common.dto.SecretVersionDto;
import com.akvoperator.common.dto.UpdateSecretPropertiesRequest;
import com.akvoperator.common.dto.UpdateSecretRequest;
import com.akvoperator.common.dto.VaultSource;
import com.akvoperator.common.exception.AppException;
import com.akvoperator.security.AppPrincipal;
import com.akvoperator.security.VaultAuthorizationService;
import com.akvoperator.vault.VaultDescriptor;
import com.azure.core.exception.ResourceNotFoundException;
import com.azure.core.http.HttpResponse;
import com.azure.core.http.rest.PagedIterable;
import com.azure.core.http.rest.PagedResponse;
import com.azure.core.util.polling.LongRunningOperationStatus;
import com.azure.core.util.polling.PollResponse;
import com.azure.core.util.polling.SyncPoller;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.DeletedSecret;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.azure.security.keyvault.secrets.models.SecretProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SecretServiceTest {

    private static final String CANARY_SECRET_VALUE = "CANARY_TOP_SECRET_VALUE_987654321";

    private ExecutorService executor;
    private VaultAuthorizationService authorizationService;
    private SecretClientProvider clientProvider;
    private SecretClient readClient;
    private SecretClient mutationClient;
    private SecretMetadataCache cache;
    private SecretPaginationService paginationService;
    private AsyncOperationTracker operationTracker;
    private List<AuditEvent> auditEvents;
    private AppProperties appProperties;
    private SecretService secretService;
    private VaultDescriptor vault;
    private AppPrincipal principal;

    @BeforeEach
    void setUp() {
        executor = Executors.newFixedThreadPool(4);
        authorizationService = mock(VaultAuthorizationService.class);
        clientProvider = mock(SecretClientProvider.class);
        readClient = mock(SecretClient.class);
        mutationClient = mock(SecretClient.class);
        cache = new SecretMetadataCache(50, Duration.ofMinutes(5), System::nanoTime);
        AzureExceptionTranslator translator = new AzureExceptionTranslator();
        paginationService = new SecretPaginationService(clientProvider, cache, translator, executor);

        auditEvents = new ArrayList<>();
        AuditLogger auditLogger = auditEvents::add;

        operationTracker = new AsyncOperationTracker(
                authorizationService,
                translator,
                auditLogger,
                executor,
                Duration.ofSeconds(10)
        );
        appProperties = new AppProperties();
        appProperties.setDeleteEnabled(false);

        secretService = new SecretService(
                authorizationService,
                clientProvider,
                cache,
                paginationService,
                new SecretInputValidator(),
                new SecretLockManager(),
                operationTracker,
                translator,
                auditLogger,
                appProperties
        );

        vault = new VaultDescriptor(
                "vault_opaque_01",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/kv-test",
                "kv-test",
                "sub-1",
                "rg-1",
                "westeurope",
                "https://kv-test.vault.azure.net",
                "dev",
                false,
                VaultSource.ARM_DISCOVERY
        );
        principal = new AppPrincipal("user-admin", "Admin User", "local", Set.of(), true);

        when(authorizationService.requireCurrentPrincipal()).thenReturn(principal);
        when(authorizationService.requireVaultPermission(eq(vault.opaqueId()), any(Permission.class))).thenReturn(vault);
        when(clientProvider.getTenantId()).thenReturn("tenant-1");
        when(clientProvider.getCredentialContextId()).thenReturn("ctx-1");
        when(clientProvider.getReadClient(vault)).thenReturn(readClient);
        when(clientProvider.getMutationClient(vault)).thenReturn(mutationClient);
    }

    @AfterEach
    void tearDown() {
        executor.shutdownNow();
    }

    @Test
    void revealCallsGetSecretLatestAndSpecificVersionAndNeverLogsCanaryInAudit() {
        KeyVaultSecret latestSecret = mockKeyVaultSecret("api-key", "v2", CANARY_SECRET_VALUE);
        KeyVaultSecret specificSecret = mockKeyVaultSecret("api-key", "v1", CANARY_SECRET_VALUE + "_OLD");
        when(readClient.getSecret("api-key")).thenReturn(latestSecret);
        when(readClient.getSecret("api-key", "v1")).thenReturn(specificSecret);

        SecretValueResponse latestResp = secretService.revealSecret(vault.opaqueId(), "api-key", null);
        assertThat(latestResp.name()).isEqualTo("api-key");
        assertThat(latestResp.version()).isEqualTo("v2");
        assertThat(latestResp.value()).isEqualTo(CANARY_SECRET_VALUE);

        SecretValueResponse versionResp = secretService.revealSecret(vault.opaqueId(), "api-key", "v1");
        assertThat(versionResp.version()).isEqualTo("v1");
        assertThat(versionResp.value()).isEqualTo(CANARY_SECRET_VALUE + "_OLD");

        assertThat(auditEvents).hasSize(2);
        assertThat(auditEvents).allSatisfy(event -> {
            assertThat(event.action()).isEqualTo("SECRET_REVEAL");
            assertThat(event.outcome()).isEqualTo("SUCCESS");
            assertThat(event.toString()).doesNotContain(CANARY_SECRET_VALUE);
        });
    }

    @Test
    void nonRevealMetadataAndVersionReadsNeverCallGetSecret() {
        SecretProperties v1 = spyProps("db-url", "v1", Instant.parse("2026-01-01T00:00:00Z"), true);
        SecretProperties v2 = spyProps("db-url", "v2", Instant.parse("2026-02-01T00:00:00Z"), true);
        SecretProperties v3 = spyProps("db-url", "v3", Instant.parse("2026-03-01T00:00:00Z"), true);

        PagedIterable<SecretProperties> multiPageVersions = mockPagedIterable(List.of(
                mockPage(List.of(v1, v3)),
                mockPage(List.of(v2))
        ));
        when(readClient.listPropertiesOfSecretVersions("db-url")).thenReturn(multiPageVersions);

        SecretMetadataDto meta = secretService.getSecretMetadata(vault.opaqueId(), "db-url");
        assertThat(meta.version()).isEqualTo("v3");

        List<SecretVersionDto> versions = secretService.listSecretVersions(vault.opaqueId(), "db-url");
        assertThat(versions).extracting(SecretVersionDto::version).containsExactly("v3", "v2", "v1");
        assertThat(versions.get(0).latest()).isTrue();
        assertThat(versions.get(1).latest()).isFalse();
        assertThat(versions.get(2).latest()).isFalse();

        verify(readClient, never()).getSecret(anyString());
        verify(readClient, never()).getSecret(anyString(), anyString());
        verify(mutationClient, never()).getSecret(anyString());
        verify(mutationClient, never()).getSecret(anyString(), anyString());
    }

    @Test
    void createPreservesMultilineAndWhitespaceAndUpdatesCache() {
        String rawMultiline = "  leading spaces\nline-2\r\ntrailing spaces   ";
        PagedIterable<SecretProperties> emptyVersions = mockPagedIterable(List.of());
        HttpResponse notFoundResp = mock404Response();
        when(readClient.listPropertiesOfSecretVersions("multiline-secret")).thenReturn(emptyVersions);
        when(readClient.getDeletedSecret("multiline-secret"))
                .thenThrow(new ResourceNotFoundException("Not found", notFoundResp));

        ArgumentCaptor<KeyVaultSecret> captor = ArgumentCaptor.forClass(KeyVaultSecret.class);
        when(mutationClient.setSecret(captor.capture())).thenAnswer(invocation -> {
            KeyVaultSecret sent = invocation.getArgument(0);
            return mockKeyVaultSecret(sent.getName(), "v1", sent.getValue());
        });

        SecretMetadataDto created = secretService.createSecret(
                vault.opaqueId(),
                new CreateSecretRequest(
                        "multiline-secret",
                        rawMultiline,
                        true,
                        "text/plain",
                        Instant.parse("2027-01-01T00:00:00Z"),
                        Instant.parse("2026-01-01T00:00:00Z"),
                        Map.of("env", "dev")
                )
        );

        assertThat(captor.getValue().getValue()).isEqualTo(rawMultiline);
        assertThat(created.name()).isEqualTo("multiline-secret");
        assertThat(created.version()).isEqualTo("v1");
        verify(readClient, never()).getSecret(anyString());
    }

    @Test
    void createValidatesNameUtf8ByteLimitAndDateRange() {
        // Invalid name (underscore disallowed by Azure Key Vault)
        assertThatThrownBy(() -> secretService.createSecret(
                vault.opaqueId(),
                new CreateSecretRequest("invalid_name", "val", true, null, null, null, null)
        )).isInstanceOf(AppException.class)
                .extracting("errorCode").isEqualTo("INVALID_SECRET_NAME");

        // Exact 25,600 UTF-8 bytes allowed
        String exact25600 = "a".repeat(25_600);
        PagedIterable<SecretProperties> emptyVersions = mockPagedIterable(List.of());
        HttpResponse notFoundResp = mock404Response();
        KeyVaultSecret createdSecret = mockKeyVaultSecret("exact-size", "v1", exact25600);
        when(readClient.listPropertiesOfSecretVersions("exact-size")).thenReturn(emptyVersions);
        when(readClient.getDeletedSecret("exact-size"))
                .thenThrow(new ResourceNotFoundException("Not found", notFoundResp));
        when(mutationClient.setSecret(any(KeyVaultSecret.class))).thenReturn(createdSecret);

        SecretMetadataDto ok = secretService.createSecret(
                vault.opaqueId(),
                new CreateSecretRequest("exact-size", exact25600, true, null, null, null, null)
        );
        assertThat(ok.name()).isEqualTo("exact-size");

        // 25,601 UTF-8 bytes via multi-byte UTF-8 characters rejected (12,800 * 2-byte 'é' + 1 'a' = 25,601 bytes)
        String multiByteTooLarge = "é".repeat(12_800) + "a";
        assertThat(multiByteTooLarge.getBytes(StandardCharsets.UTF_8).length).isEqualTo(25_601);
        assertThatThrownBy(() -> secretService.createSecret(
                vault.opaqueId(),
                new CreateSecretRequest("too-large", multiByteTooLarge, true, null, null, null, null)
        )).isInstanceOf(AppException.class)
                .extracting("errorCode").isEqualTo("SECRET_VALUE_TOO_LARGE");

        // notBefore >= expiresOn rejected
        Instant ts = Instant.parse("2026-06-01T00:00:00Z");
        assertThatThrownBy(() -> secretService.createSecret(
                vault.opaqueId(),
                new CreateSecretRequest("bad-dates", "val", true, null, ts, ts, null)
        )).isInstanceOf(AppException.class)
                .extracting("errorCode").isEqualTo("INVALID_DATE_RANGE");
    }

    @Test
    void createRejectsDuplicateActiveAndSoftDeletedConflictsWith409() {
        // Active duplicate
        SecretProperties existing = spyProps("dup-secret", "v1", Instant.now(), true);
        PagedIterable<SecretProperties> dupVersions = mockPagedIterable(List.of(mockPage(List.of(existing))));
        when(readClient.listPropertiesOfSecretVersions("dup-secret")).thenReturn(dupVersions);

        assertThatThrownBy(() -> secretService.createSecret(
                vault.opaqueId(),
                new CreateSecretRequest("dup-secret", "val", true, null, null, null, null)
        )).isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getStatus()).isEqualTo(HttpStatus.CONFLICT);
                    assertThat(appEx.getErrorCode()).isEqualTo("SECRET_ALREADY_EXISTS");
                });

        // Soft-deleted conflict
        PagedIterable<SecretProperties> emptyVersions = mockPagedIterable(List.of());
        when(readClient.listPropertiesOfSecretVersions("deleted-name")).thenReturn(emptyVersions);
        DeletedSecret deletedSecret = mock(DeletedSecret.class);
        when(deletedSecret.getName()).thenReturn("deleted-name");
        when(readClient.getDeletedSecret("deleted-name")).thenReturn(deletedSecret);

        assertThatThrownBy(() -> secretService.createSecret(
                vault.opaqueId(),
                new CreateSecretRequest("deleted-name", "val", true, null, null, null, null)
        )).isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getStatus()).isEqualTo(HttpStatus.CONFLICT);
                    assertThat(appEx.getErrorCode()).isEqualTo("SECRET_SOFT_DELETED_CONFLICT");
                });
    }

    @Test
    void updateDetectsOptimisticVersionConflictAndPreservesExistingMetadataOnMatch() {
        SecretProperties latest = spyProps("app-token", "v2", Instant.parse("2026-02-01T00:00:00Z"), true);
        latest.setContentType("application/json");
        latest.setExpiresOn(OffsetDateTime.parse("2027-02-01T00:00:00Z"));
        latest.setTags(Map.of("owner", "platform", "tier", "core"));

        PagedIterable<SecretProperties> latestVersions = mockPagedIterable(List.of(mockPage(List.of(latest))));
        when(readClient.listPropertiesOfSecretVersions("app-token")).thenReturn(latestVersions);

        // Stale version -> 409 conflict
        assertThatThrownBy(() -> secretService.updateSecret(
                vault.opaqueId(),
                "app-token",
                new UpdateSecretRequest("new-val", "v1", true, null, null, null, null, null)
        )).isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getStatus()).isEqualTo(HttpStatus.CONFLICT);
                    assertThat(appEx.getErrorCode()).isEqualTo("SECRET_VERSION_CONFLICT");
                });

        // Matching version -> preserves existing tags & expiresOn while overriding contentType
        ArgumentCaptor<KeyVaultSecret> captor = ArgumentCaptor.forClass(KeyVaultSecret.class);
        when(mutationClient.setSecret(captor.capture())).thenAnswer(invocation -> {
            KeyVaultSecret sent = invocation.getArgument(0);
            SecretProperties resultProps = spy(sent.getProperties());
            doReturn("v3").when(resultProps).getVersion();
            KeyVaultSecret result = mock(KeyVaultSecret.class);
            when(result.getName()).thenReturn(sent.getName());
            when(result.getProperties()).thenReturn(resultProps);
            return result;
        });

        SecretMetadataDto updated = secretService.updateSecret(
                vault.opaqueId(),
                "app-token",
                new UpdateSecretRequest("new-val", "v2", true, null, "text/plain", null, null, null)
        );

        assertThat(updated.version()).isEqualTo("v3");
        assertThat(captor.getValue().getProperties().getContentType()).isEqualTo("text/plain");
        assertThat(captor.getValue().getProperties().getTags()).containsEntry("owner", "platform");
        assertThat(captor.getValue().getProperties().getExpiresOn()).isEqualTo(OffsetDateTime.parse("2027-02-01T00:00:00Z"));
        verify(readClient, never()).getSecret(anyString());
    }

    @Test
    void updateSecretPropertiesUpdatesTargetVersionClearsDatesAndRejectsInvalidRange() {
        SecretProperties v1 = spyProps("cert-pass", "v1", Instant.parse("2026-01-01T00:00:00Z"), true);
        v1.setExpiresOn(OffsetDateTime.parse("2027-01-01T00:00:00Z"));
        v1.setNotBefore(OffsetDateTime.parse("2026-01-01T00:00:00Z"));

        SecretProperties v2 = spyProps("cert-pass", "v2", Instant.parse("2026-02-01T00:00:00Z"), true);
        v2.setExpiresOn(OffsetDateTime.parse("2026-06-01T00:00:00Z"));

        PagedIterable<SecretProperties> certVersions = mockPagedIterable(List.of(mockPage(List.of(v1, v2))));
        when(readClient.listPropertiesOfSecretVersions("cert-pass")).thenReturn(certVersions);
        when(mutationClient.updateSecretProperties(any(SecretProperties.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // Update specific older version v1 and clear expiresOn
        SecretMetadataDto updatedV1 = secretService.updateSecretProperties(
                vault.opaqueId(),
                "cert-pass",
                new UpdateSecretPropertiesRequest("v1", false, "text/plain", null, null, true, false, Map.of("k", "v"))
        );

        assertThat(updatedV1.version()).isEqualTo("v1");
        assertThat(updatedV1.enabled()).isFalse();
        assertThat(updatedV1.expiresOn()).isNull();
        assertThat(updatedV1.notBefore()).isEqualTo(Instant.parse("2026-01-01T00:00:00Z"));

        // Invalid date range against existing expiresOn on v2
        assertThatThrownBy(() -> secretService.updateSecretProperties(
                vault.opaqueId(),
                "cert-pass",
                new UpdateSecretPropertiesRequest(
                        null,
                        null,
                        null,
                        null,
                        Instant.parse("2026-07-01T00:00:00Z"),
                        false,
                        false,
                        null
                )
        )).isInstanceOf(AppException.class)
                .extracting("errorCode").isEqualTo("INVALID_DATE_RANGE");
    }

    @Test
    void softDeleteEnforcesFeatureFlagConfirmationNameAndTracksPollerCompletionAndFailure() throws Exception {
        // Feature flag disabled by default -> 403 FEATURE_DISABLED
        assertThatThrownBy(() -> secretService.softDeleteSecret(
                vault.opaqueId(),
                "old-secret",
                new DeleteSecretRequest("old-secret")
        )).isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getStatus()).isEqualTo(HttpStatus.FORBIDDEN);
                    assertThat(appEx.getErrorCode()).isEqualTo("FEATURE_DISABLED");
                });

        // Enable soft-delete
        appProperties.setDeleteEnabled(true);

        // Confirmation mismatch -> 400 DELETE_CONFIRMATION_MISMATCH
        assertThatThrownBy(() -> secretService.softDeleteSecret(
                vault.opaqueId(),
                "old-secret",
                new DeleteSecretRequest("wrong-name")
        )).isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                    assertThat(appEx.getErrorCode()).isEqualTo("DELETE_CONFIRMATION_MISMATCH");
                });

        // Successful async soft-delete
        @SuppressWarnings("unchecked")
        SyncPoller<DeletedSecret, Void> okPoller = mock(SyncPoller.class);
        when(okPoller.waitForCompletion(any(Duration.class)))
                .thenReturn(new PollResponse<>(LongRunningOperationStatus.SUCCESSFULLY_COMPLETED, null));
        when(mutationClient.beginDeleteSecret("old-secret")).thenReturn(okPoller);
        PagedIterable<SecretProperties> emptySecrets = mockPagedIterable(List.of());
        when(readClient.listPropertiesOfSecrets()).thenReturn(emptySecrets);

        OperationStatusResponse accepted = secretService.softDeleteSecret(
                vault.opaqueId(),
                "old-secret",
                new DeleteSecretRequest("old-secret")
        );
        assertThat(accepted.operationType()).isEqualTo(OperationType.SOFT_DELETE);

        awaitOperation(accepted.operationId());
        OperationStatusResponse finished = operationTracker.getOperationStatus(accepted.operationId());
        assertThat(finished.state()).isEqualTo(OperationState.SUCCEEDED);

        // Failed poller transitions to FAILED
        @SuppressWarnings("unchecked")
        SyncPoller<DeletedSecret, Void> failedPoller = mock(SyncPoller.class);
        when(failedPoller.waitForCompletion(any(Duration.class)))
                .thenReturn(new PollResponse<>(LongRunningOperationStatus.FAILED, null));
        when(mutationClient.beginDeleteSecret("fail-secret")).thenReturn(failedPoller);

        OperationStatusResponse failedAccepted = secretService.softDeleteSecret(
                vault.opaqueId(),
                "fail-secret",
                new DeleteSecretRequest("fail-secret")
        );
        awaitOperation(failedAccepted.operationId());
        OperationStatusResponse failedStatus = operationTracker.getOperationStatus(failedAccepted.operationId());
        assertThat(failedStatus.state()).isEqualTo(OperationState.FAILED);
        assertThat(failedStatus.errorCode()).isNotBlank();
    }

    @Test
    void listDeletedSecretsWalksAllPagesAndRecoverTracksPoller() throws Exception {
        DeletedSecret d1 = mock(DeletedSecret.class);
        when(d1.getName()).thenReturn("del-1");
        when(d1.getDeletedOn()).thenReturn(OffsetDateTime.parse("2026-01-10T00:00:00Z"));
        when(d1.getScheduledPurgeDate()).thenReturn(OffsetDateTime.parse("2026-04-10T00:00:00Z"));

        DeletedSecret d2 = mock(DeletedSecret.class);
        when(d2.getName()).thenReturn("del-2");
        when(d2.getDeletedOn()).thenReturn(OffsetDateTime.parse("2026-01-11T00:00:00Z"));

        @SuppressWarnings("unchecked")
        PagedResponse<DeletedSecret> p1 = mock(PagedResponse.class);
        when(p1.getValue()).thenReturn(List.of(d1));
        @SuppressWarnings("unchecked")
        PagedResponse<DeletedSecret> p2 = mock(PagedResponse.class);
        when(p2.getValue()).thenReturn(List.of(d2));
        @SuppressWarnings("unchecked")
        PagedIterable<DeletedSecret> deletedIterable = mock(PagedIterable.class);
        when(deletedIterable.iterableByPage()).thenReturn(List.of(p1, p2));
        when(readClient.listDeletedSecrets()).thenReturn(deletedIterable);

        List<DeletedSecretDto> deletedList = secretService.listDeletedSecrets(vault.opaqueId());
        assertThat(deletedList).extracting(DeletedSecretDto::name).containsExactly("del-1", "del-2");

        @SuppressWarnings("unchecked")
        SyncPoller<KeyVaultSecret, Void> recoverPoller = mock(SyncPoller.class);
        when(recoverPoller.waitForCompletion(any(Duration.class)))
                .thenReturn(new PollResponse<>(LongRunningOperationStatus.SUCCESSFULLY_COMPLETED, null));
        when(mutationClient.beginRecoverDeletedSecret("del-1")).thenReturn(recoverPoller);
        PagedIterable<SecretProperties> emptySecrets = mockPagedIterable(List.of());
        when(readClient.listPropertiesOfSecrets()).thenReturn(emptySecrets);

        OperationStatusResponse accepted = secretService.recoverDeletedSecret(vault.opaqueId(), "del-1");
        assertThat(accepted.operationType()).isEqualTo(OperationType.RECOVER);

        awaitOperation(accepted.operationId());
        OperationStatusResponse finished = operationTracker.getOperationStatus(accepted.operationId());
        assertThat(finished.state()).isEqualTo(OperationState.SUCCEEDED);
    }

    private void awaitOperation(String operationId) throws Exception {
        CompletableFuture<Void> future = operationTracker.getOperationFuture(operationId).orElse(null);
        if (future != null) {
            future.get(5, TimeUnit.SECONDS);
        }
    }

    private static HttpResponse mock404Response() {
        HttpResponse response = mock(HttpResponse.class);
        when(response.getStatusCode()).thenReturn(404);
        return response;
    }

    private static KeyVaultSecret mockKeyVaultSecret(String name, String version, String value) {
        SecretProperties props = spyProps(name, version, Instant.now(), true);
        KeyVaultSecret secret = mock(KeyVaultSecret.class);
        when(secret.getName()).thenReturn(name);
        when(secret.getValue()).thenReturn(value);
        when(secret.getProperties()).thenReturn(props);
        return secret;
    }

    private static SecretProperties spyProps(String name, String version, Instant createdOn, boolean enabled) {
        SecretProperties props = spy(new KeyVaultSecret(name, "").getProperties());
        doReturn(version).when(props).getVersion();
        OffsetDateTime odt = createdOn.atOffset(ZoneOffset.UTC);
        doReturn(odt).when(props).getCreatedOn();
        doReturn(odt).when(props).getUpdatedOn();
        props.setEnabled(enabled);
        return props;
    }

    @SuppressWarnings("unchecked")
    private static PagedResponse<SecretProperties> mockPage(List<SecretProperties> items) {
        PagedResponse<SecretProperties> page = mock(PagedResponse.class);
        when(page.getValue()).thenReturn(items);
        return page;
    }

    @SuppressWarnings("unchecked")
    private static PagedIterable<SecretProperties> mockPagedIterable(List<PagedResponse<SecretProperties>> pages) {
        PagedIterable<SecretProperties> iterable = mock(PagedIterable.class);
        when(iterable.iterableByPage()).thenReturn(pages);
        return iterable;
    }
}
