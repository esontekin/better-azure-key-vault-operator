package com.akvoperator.secret;

import com.akvoperator.audit.AuditLogger;
import com.akvoperator.azure.AzureExceptionTranslator;
import com.akvoperator.azure.SecretClientProvider;
import com.akvoperator.cache.SecretMetadataCache;
import com.akvoperator.cache.SecretSnapshotState;
import com.akvoperator.cache.VaultCacheKey;
import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.correlation.CorrelationIdHolder;
import com.akvoperator.common.dto.CreateSecretRequest;
import com.akvoperator.common.dto.DeleteSecretRequest;
import com.akvoperator.common.dto.DeletedSecretDto;
import com.akvoperator.common.dto.OperationStatusResponse;
import com.akvoperator.common.dto.OperationType;
import com.akvoperator.common.dto.Permission;
import com.akvoperator.common.dto.SecretListSnapshotResponse;
import com.akvoperator.common.dto.SecretMetadataDto;
import com.akvoperator.common.dto.SecretValueResponse;
import com.akvoperator.common.dto.SecretVersionDto;
import com.akvoperator.common.dto.UpdateSecretPropertiesRequest;
import com.akvoperator.common.dto.UpdateSecretRequest;
import com.akvoperator.common.exception.AppException;
import com.akvoperator.security.AppPrincipal;
import com.akvoperator.security.VaultAuthorizationService;
import com.akvoperator.vault.VaultDescriptor;
import com.azure.core.http.rest.PagedResponse;
import com.azure.core.util.polling.SyncPoller;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.DeletedSecret;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.azure.security.keyvault.secrets.models.SecretProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Core Azure Key Vault secret management service enforcing RBAC, input validation,
 * in-process locking, metadata-only caching, audit logging, and strict separation between
 * metadata reads and explicit secret value reveals.
 *
 * <p>CRITICAL INVARIANT: {@link SecretClient#getSecret} is ONLY invoked inside {@link #revealSecret}.
 * Permanent purge operations are intentionally excluded.</p>
 */
@Service
public class SecretService {

    private static final Logger log = LoggerFactory.getLogger(SecretService.class);

    private final VaultAuthorizationService vaultAuthorizationService;
    private final SecretClientProvider secretClientProvider;
    private final SecretMetadataCache cache;
    private final SecretPaginationService paginationService;
    private final SecretInputValidator validator;
    private final SecretLockManager lockManager;
    private final AsyncOperationTracker operationTracker;
    private final AzureExceptionTranslator exceptionTranslator;
    private final AuditLogger auditLogger;
    private final AppProperties appProperties;

    public SecretService(
            VaultAuthorizationService vaultAuthorizationService,
            SecretClientProvider secretClientProvider,
            SecretMetadataCache cache,
            SecretPaginationService paginationService,
            SecretInputValidator validator,
            SecretLockManager lockManager,
            AsyncOperationTracker operationTracker,
            AzureExceptionTranslator exceptionTranslator,
            AuditLogger auditLogger,
            AppProperties appProperties
    ) {
        this.vaultAuthorizationService = vaultAuthorizationService;
        this.secretClientProvider = secretClientProvider;
        this.cache = cache;
        this.paginationService = paginationService;
        this.validator = validator;
        this.lockManager = lockManager;
        this.operationTracker = operationTracker;
        this.exceptionTranslator = exceptionTranslator;
        this.auditLogger = auditLogger;
        this.appProperties = appProperties;
    }

    public SecretListSnapshotResponse getSnapshot(String vaultId) {
        VaultDescriptor vault = vaultAuthorizationService.requireVaultPermission(vaultId, Permission.SECRET_LIST);
        AppPrincipal principal = vaultAuthorizationService.requireCurrentPrincipal();
        String correlationId = CorrelationIdHolder.getOrGenerate();

        SecretSnapshotState state = paginationService.getOrStartRefresh(vault);
        auditLogger.logSuccess(principal.subject(), vault.opaqueId(), null, null, "SECRET_LIST_SNAPSHOT", correlationId);
        return cache.toResponse(state);
    }

    public SecretListSnapshotResponse triggerRefresh(String vaultId) {
        VaultDescriptor vault = vaultAuthorizationService.requireVaultPermission(vaultId, Permission.SECRET_LIST);
        AppPrincipal principal = vaultAuthorizationService.requireCurrentPrincipal();
        String correlationId = CorrelationIdHolder.getOrGenerate();

        SecretSnapshotState state = paginationService.startOrCoalesceRefresh(vault);
        auditLogger.logSuccess(principal.subject(), vault.opaqueId(), null, null, "SECRET_LIST_REFRESH", correlationId);
        return cache.toResponse(state);
    }

    public SecretMetadataDto getSecretMetadata(String vaultId, String secretName) {
        VaultDescriptor vault = vaultAuthorizationService.requireVaultPermission(vaultId, Permission.SECRET_LIST);
        AppPrincipal principal = vaultAuthorizationService.requireCurrentPrincipal();
        String correlationId = CorrelationIdHolder.getOrGenerate();

        try {
            validator.validateSecretName(secretName);
            SecretClient readClient = secretClientProvider.getReadClient(vault);
            SecretProperties latest = resolveLatestProperties(readClient, secretName)
                    .orElseThrow(() -> AppException.azureNotFound("Secret", null));

            auditLogger.logSuccess(
                    principal.subject(),
                    vault.opaqueId(),
                    secretName,
                    latest.getVersion(),
                    "SECRET_GET_METADATA",
                    correlationId
            );
            return SecretDtoMapper.toMetadataDto(latest);
        } catch (Throwable ex) {
            AppException translated = exceptionTranslator.translate(ex, "Secret");
            auditLogger.logFailure(
                    principal.subject(),
                    vault.opaqueId(),
                    secretName,
                    null,
                    "SECRET_GET_METADATA",
                    translated.getErrorCode(),
                    correlationId
            );
            throw translated;
        }
    }

    /**
     * Explicitly retrieves a secret value from Azure Key Vault (latest or specific version).
     * This is the ONLY method permitted to invoke {@link SecretClient#getSecret}.
     */
    public SecretValueResponse revealSecret(String vaultId, String secretName, String version) {
        VaultDescriptor vault = vaultAuthorizationService.requireVaultPermission(vaultId, Permission.SECRET_REVEAL);
        AppPrincipal principal = vaultAuthorizationService.requireCurrentPrincipal();
        String correlationId = CorrelationIdHolder.getOrGenerate();

        String normalizedVersion = (version != null && !version.isBlank()) ? version.trim() : null;
        try {
            validator.validateSecretName(secretName);
            validator.validateVersion(normalizedVersion);

            SecretClient readClient = secretClientProvider.getReadClient(vault);
            KeyVaultSecret secret = (normalizedVersion == null)
                    ? readClient.getSecret(secretName)
                    : readClient.getSecret(secretName, normalizedVersion);

            String resolvedVersion = secret.getProperties() != null
                    ? secret.getProperties().getVersion()
                    : normalizedVersion;

            auditLogger.logSuccess(
                    principal.subject(),
                    vault.opaqueId(),
                    secretName,
                    resolvedVersion,
                    "SECRET_REVEAL",
                    correlationId
            );
            return SecretDtoMapper.toValueResponse(secret);
        } catch (Throwable ex) {
            AppException translated = exceptionTranslator.translate(ex, "Secret");
            auditLogger.logFailure(
                    principal.subject(),
                    vault.opaqueId(),
                    secretName,
                    normalizedVersion,
                    "SECRET_REVEAL",
                    translated.getErrorCode(),
                    correlationId
            );
            throw translated;
        }
    }

    public SecretMetadataDto createSecret(String vaultId, CreateSecretRequest request) {
        VaultDescriptor vault = vaultAuthorizationService.requireVaultPermission(vaultId, Permission.SECRET_WRITE);
        AppPrincipal principal = vaultAuthorizationService.requireCurrentPrincipal();
        String correlationId = CorrelationIdHolder.getOrGenerate();
        String secretName = request != null ? request.name() : null;

        try {
            if (request == null) {
                throw AppException.badRequest("INVALID_REQUEST", "Create secret request body is required.");
            }
            validator.validateSecretName(request.name());
            validator.validateSecretValue(request.value());
            validator.validateContentType(request.contentType());
            validator.validateDateRange(request.notBefore(), request.expiresOn());
            validator.validateTags(request.tags());

            return lockManager.executeWithLock(vault.opaqueId(), request.name(), () -> {
                SecretClient readClient = secretClientProvider.getReadClient(vault);

                // Non-atomic pre-check for active secret conflict (in-JVM serialized by lockManager;
                // external concurrent writers can still race because Azure setSecret is an upsert).
                if (resolveLatestProperties(readClient, request.name()).isPresent()) {
                    throw AppException.conflict(
                            "SECRET_ALREADY_EXISTS",
                            "A secret with this name already exists in the vault."
                    );
                }

                checkSoftDeletedConflict(readClient, vault, request.name(), correlationId);

                KeyVaultSecret toCreate = new KeyVaultSecret(request.name(), request.value());
                SecretProperties props = toCreate.getProperties();
                props.setEnabled(request.enabled() == null || request.enabled());
                if (request.contentType() != null) {
                    props.setContentType(request.contentType());
                }
                if (request.expiresOn() != null) {
                    props.setExpiresOn(SecretDtoMapper.toOffsetDateTime(request.expiresOn()));
                }
                if (request.notBefore() != null) {
                    props.setNotBefore(SecretDtoMapper.toOffsetDateTime(request.notBefore()));
                }
                if (request.tags() != null) {
                    props.setTags(new LinkedHashMap<>(request.tags()));
                }

                // Uses no-blind-retry mutation client to avoid duplicate versions on ambiguous outcomes.
                SecretClient mutationClient = secretClientProvider.getMutationClient(vault);
                KeyVaultSecret created = mutationClient.setSecret(toCreate);
                SecretMetadataDto dto = SecretDtoMapper.toMetadataDto(created.getProperties());

                cache.applyMutationUpsert(paginationService.cacheKeyFor(vault), dto);
                auditLogger.logSuccess(
                        principal.subject(),
                        vault.opaqueId(),
                        request.name(),
                        dto.version(),
                        "SECRET_CREATE",
                        correlationId
                );
                return dto;
            });
        } catch (Throwable ex) {
            AppException translated = exceptionTranslator.translate(ex, "Secret");
            auditLogger.logFailure(
                    principal.subject(),
                    vault.opaqueId(),
                    secretName,
                    null,
                    "SECRET_CREATE",
                    translated.getErrorCode(),
                    correlationId
            );
            throw translated;
        }
    }

    public SecretMetadataDto updateSecret(String vaultId, String secretName, UpdateSecretRequest request) {
        VaultDescriptor vault = vaultAuthorizationService.requireVaultPermission(vaultId, Permission.SECRET_WRITE);
        AppPrincipal principal = vaultAuthorizationService.requireCurrentPrincipal();
        String correlationId = CorrelationIdHolder.getOrGenerate();

        try {
            if (request == null) {
                throw AppException.badRequest("INVALID_REQUEST", "Update secret request body is required.");
            }
            validator.validateSecretName(secretName);
            validator.validateSecretValue(request.value());
            validator.validateContentType(request.contentType());
            validator.validateTags(request.tags());
            validator.validateVersion(request.expectedLatestVersion());

            return lockManager.executeWithLock(vault.opaqueId(), secretName, () -> {
                SecretClient readClient = secretClientProvider.getReadClient(vault);
                SecretProperties currentLatest = resolveLatestProperties(readClient, secretName)
                        .orElseThrow(() -> AppException.azureNotFound("Secret", null));

                // Non-atomic optimistic version check (in-JVM serialized via lockManager)
                if (request.expectedLatestVersion() != null && !request.expectedLatestVersion().isBlank()) {
                    String actualVersion = currentLatest.getVersion();
                    if (!request.expectedLatestVersion().trim().equals(actualVersion)) {
                        throw AppException.conflict(
                                "SECRET_VERSION_CONFLICT",
                                "The secret was updated by another session since you opened it. Reload the latest version before saving."
                        );
                    }
                }

                boolean effectiveEnabled;
                String effectiveContentType;
                Instant effectiveExpiresOn;
                Instant effectiveNotBefore;
                Map<String, String> effectiveTags;

                if (request.shouldPreserveMetadata()) {
                    boolean currentEnabled = !Boolean.FALSE.equals(currentLatest.isEnabled());
                    effectiveEnabled = request.enabled() != null ? request.enabled() : currentEnabled;
                    effectiveContentType = request.contentType() != null
                            ? request.contentType()
                            : currentLatest.getContentType();
                    effectiveExpiresOn = request.expiresOn() != null
                            ? request.expiresOn()
                            : SecretDtoMapper.toInstant(currentLatest.getExpiresOn());
                    effectiveNotBefore = request.notBefore() != null
                            ? request.notBefore()
                            : SecretDtoMapper.toInstant(currentLatest.getNotBefore());
                    effectiveTags = request.tags() != null
                            ? new LinkedHashMap<>(request.tags())
                            : (currentLatest.getTags() != null ? new LinkedHashMap<>(currentLatest.getTags()) : null);
                } else {
                    effectiveEnabled = request.enabled() == null || request.enabled();
                    effectiveContentType = request.contentType();
                    effectiveExpiresOn = request.expiresOn();
                    effectiveNotBefore = request.notBefore();
                    effectiveTags = request.tags() != null ? new LinkedHashMap<>(request.tags()) : null;
                }

                validator.validateDateRange(effectiveNotBefore, effectiveExpiresOn);

                KeyVaultSecret toWrite = new KeyVaultSecret(secretName, request.value());
                SecretProperties props = toWrite.getProperties();
                props.setEnabled(effectiveEnabled);
                if (effectiveContentType != null) {
                    props.setContentType(effectiveContentType);
                }
                if (effectiveExpiresOn != null) {
                    props.setExpiresOn(SecretDtoMapper.toOffsetDateTime(effectiveExpiresOn));
                }
                if (effectiveNotBefore != null) {
                    props.setNotBefore(SecretDtoMapper.toOffsetDateTime(effectiveNotBefore));
                }
                if (effectiveTags != null) {
                    props.setTags(effectiveTags);
                }

                SecretClient mutationClient = secretClientProvider.getMutationClient(vault);
                KeyVaultSecret updated = mutationClient.setSecret(toWrite);
                SecretMetadataDto dto = SecretDtoMapper.toMetadataDto(updated.getProperties());

                cache.applyMutationUpsert(paginationService.cacheKeyFor(vault), dto);
                auditLogger.logSuccess(
                        principal.subject(),
                        vault.opaqueId(),
                        secretName,
                        dto.version(),
                        "SECRET_UPDATE",
                        correlationId
                );
                return dto;
            });
        } catch (Throwable ex) {
            AppException translated = exceptionTranslator.translate(ex, "Secret");
            auditLogger.logFailure(
                    principal.subject(),
                    vault.opaqueId(),
                    secretName,
                    null,
                    "SECRET_UPDATE",
                    translated.getErrorCode(),
                    correlationId
            );
            throw translated;
        }
    }

    public SecretMetadataDto updateSecretProperties(
            String vaultId,
            String secretName,
            UpdateSecretPropertiesRequest request
    ) {
        VaultDescriptor vault = vaultAuthorizationService.requireVaultPermission(vaultId, Permission.SECRET_WRITE);
        AppPrincipal principal = vaultAuthorizationService.requireCurrentPrincipal();
        String correlationId = CorrelationIdHolder.getOrGenerate();
        String requestedVersion = request != null && request.version() != null && !request.version().isBlank()
                ? request.version().trim()
                : null;

        try {
            if (request == null) {
                throw AppException.badRequest("INVALID_REQUEST", "Update properties request body is required.");
            }
            validator.validateSecretName(secretName);
            validator.validateVersion(requestedVersion);
            validator.validateContentType(request.contentType());
            validator.validateTags(request.tags());

            return lockManager.executeWithLock(vault.opaqueId(), secretName, () -> {
                SecretClient readClient = secretClientProvider.getReadClient(vault);
                List<SecretProperties> versions = listAllVersionProperties(readClient, secretName);
                if (versions.isEmpty()) {
                    throw AppException.azureNotFound("Secret", null);
                }

                SecretProperties latestProps = versions.get(0);
                SecretProperties target;
                if (requestedVersion != null) {
                    target = versions.stream()
                            .filter(v -> requestedVersion.equals(v.getVersion()))
                            .findFirst()
                            .orElseThrow(() -> AppException.azureNotFound("Secret version", null));
                } else {
                    target = latestProps;
                }

                if (request.enabled() != null) {
                    target.setEnabled(request.enabled());
                }
                if (request.contentType() != null) {
                    target.setContentType(request.contentType());
                }
                if (request.clearExpiresOn()) {
                    target.setExpiresOn(null);
                } else if (request.expiresOn() != null) {
                    target.setExpiresOn(SecretDtoMapper.toOffsetDateTime(request.expiresOn()));
                }
                if (request.clearNotBefore()) {
                    target.setNotBefore(null);
                } else if (request.notBefore() != null) {
                    target.setNotBefore(SecretDtoMapper.toOffsetDateTime(request.notBefore()));
                }
                if (request.tags() != null) {
                    target.setTags(new LinkedHashMap<>(request.tags()));
                }

                validator.validateDateRange(
                        SecretDtoMapper.toInstant(target.getNotBefore()),
                        SecretDtoMapper.toInstant(target.getExpiresOn())
                );

                SecretClient mutationClient = secretClientProvider.getMutationClient(vault);
                SecretProperties updated = mutationClient.updateSecretProperties(target);
                SecretMetadataDto dto = SecretDtoMapper.toMetadataDto(updated);

                if (Objects.equals(latestProps.getVersion(), target.getVersion())) {
                    cache.applyMutationUpsert(paginationService.cacheKeyFor(vault), dto);
                }

                auditLogger.logSuccess(
                        principal.subject(),
                        vault.opaqueId(),
                        secretName,
                        dto.version(),
                        "SECRET_UPDATE_PROPERTIES",
                        correlationId
                );
                return dto;
            });
        } catch (Throwable ex) {
            AppException translated = exceptionTranslator.translate(ex, "Secret");
            auditLogger.logFailure(
                    principal.subject(),
                    vault.opaqueId(),
                    secretName,
                    requestedVersion,
                    "SECRET_UPDATE_PROPERTIES",
                    translated.getErrorCode(),
                    correlationId
            );
            throw translated;
        }
    }

    public List<SecretVersionDto> listSecretVersions(String vaultId, String secretName) {
        VaultDescriptor vault = vaultAuthorizationService.requireVaultPermission(vaultId, Permission.SECRET_LIST);
        AppPrincipal principal = vaultAuthorizationService.requireCurrentPrincipal();
        String correlationId = CorrelationIdHolder.getOrGenerate();

        try {
            validator.validateSecretName(secretName);
            SecretClient readClient = secretClientProvider.getReadClient(vault);
            List<SecretProperties> versions = listAllVersionProperties(readClient, secretName);
            if (versions.isEmpty()) {
                throw AppException.azureNotFound("Secret", null);
            }

            List<SecretVersionDto> result = new ArrayList<>(versions.size());
            for (int i = 0; i < versions.size(); i++) {
                result.add(SecretDtoMapper.toVersionDto(versions.get(i), i == 0));
            }

            auditLogger.logSuccess(
                    principal.subject(),
                    vault.opaqueId(),
                    secretName,
                    null,
                    "SECRET_LIST_VERSIONS",
                    correlationId
            );
            return List.copyOf(result);
        } catch (Throwable ex) {
            AppException translated = exceptionTranslator.translate(ex, "Secret");
            auditLogger.logFailure(
                    principal.subject(),
                    vault.opaqueId(),
                    secretName,
                    null,
                    "SECRET_LIST_VERSIONS",
                    translated.getErrorCode(),
                    correlationId
            );
            throw translated;
        }
    }

    public List<DeletedSecretDto> listDeletedSecrets(String vaultId) {
        VaultDescriptor vault = vaultAuthorizationService.requireVaultPermission(vaultId, Permission.SECRET_DELETE_RECOVER);
        AppPrincipal principal = vaultAuthorizationService.requireCurrentPrincipal();
        String correlationId = CorrelationIdHolder.getOrGenerate();

        try {
            SecretClient readClient = secretClientProvider.getReadClient(vault);
            LinkedHashMap<String, DeletedSecretDto> result = new LinkedHashMap<>();

            Iterable<PagedResponse<DeletedSecret>> pages = readClient.listDeletedSecrets().iterableByPage();
            for (PagedResponse<DeletedSecret> page : pages) {
                List<DeletedSecret> values = page != null ? page.getValue() : null;
                if (values == null) {
                    continue;
                }
                for (DeletedSecret deleted : values) {
                    if (deleted == null || deleted.getName() == null || deleted.getName().isBlank()) {
                        continue;
                    }
                    result.put(deleted.getName(), SecretDtoMapper.toDeletedDto(deleted));
                }
            }

            auditLogger.logSuccess(
                    principal.subject(),
                    vault.opaqueId(),
                    null,
                    null,
                    "SECRET_LIST_DELETED",
                    correlationId
            );
            return List.copyOf(result.values());
        } catch (Throwable ex) {
            AppException translated = exceptionTranslator.translate(ex, "Deleted secrets");
            auditLogger.logFailure(
                    principal.subject(),
                    vault.opaqueId(),
                    null,
                    null,
                    "SECRET_LIST_DELETED",
                    translated.getErrorCode(),
                    correlationId
            );
            throw translated;
        }
    }

    public OperationStatusResponse softDeleteSecret(String vaultId, String secretName, DeleteSecretRequest request) {
        VaultDescriptor vault = vaultAuthorizationService.requireVaultPermission(vaultId, Permission.SECRET_DELETE_RECOVER);
        AppPrincipal principal = vaultAuthorizationService.requireCurrentPrincipal();
        String correlationId = CorrelationIdHolder.getOrGenerate();

        if (!appProperties.isDeleteEnabled()) {
            auditLogger.logDenied(
                    principal.subject(),
                    vault.opaqueId(),
                    secretName,
                    null,
                    "SECRET_SOFT_DELETE",
                    "FEATURE_DISABLED",
                    correlationId
            );
            throw AppException.featureDisabled("Soft-delete is disabled by APP_DELETE_ENABLED=false.");
        }

        try {
            validator.validateSecretName(secretName);
            if (request == null
                    || request.confirmSecretName() == null
                    || !request.confirmSecretName().equals(secretName)) {
                throw AppException.badRequest(
                        "DELETE_CONFIRMATION_MISMATCH",
                        "Confirmation secret name must exactly match the target secret name."
                );
            }

            return lockManager.executeWithLock(vault.opaqueId(), secretName, () -> {
                SecretClient mutationClient = secretClientProvider.getMutationClient(vault);
                SyncPoller<DeletedSecret, Void> poller = mutationClient.beginDeleteSecret(secretName);
                VaultCacheKey cacheKey = paginationService.cacheKeyFor(vault);

                auditLogger.logSuccess(
                        principal.subject(),
                        vault.opaqueId(),
                        secretName,
                        null,
                        "SECRET_SOFT_DELETE_INITIATED",
                        correlationId
                );

                return operationTracker.trackPoller(
                        principal.subject(),
                        vault.opaqueId(),
                        secretName,
                        OperationType.SOFT_DELETE,
                        Permission.SECRET_DELETE_RECOVER,
                        correlationId,
                        poller,
                        () -> {
                            cache.applyMutationDelete(cacheKey, secretName);
                            paginationService.startOrCoalesceRefresh(vault);
                            auditLogger.logSuccess(
                                    principal.subject(),
                                    vault.opaqueId(),
                                    secretName,
                                    null,
                                    "SECRET_SOFT_DELETE_COMPLETE",
                                    correlationId
                            );
                        },
                        failure -> auditLogger.logFailure(
                                principal.subject(),
                                vault.opaqueId(),
                                secretName,
                                null,
                                "SECRET_SOFT_DELETE_COMPLETE",
                                failure.getErrorCode(),
                                correlationId
                        )
                );
            });
        } catch (Throwable ex) {
            AppException translated = exceptionTranslator.translate(ex, "Secret");
            auditLogger.logFailure(
                    principal.subject(),
                    vault.opaqueId(),
                    secretName,
                    null,
                    "SECRET_SOFT_DELETE",
                    translated.getErrorCode(),
                    correlationId
            );
            throw translated;
        }
    }

    public OperationStatusResponse recoverDeletedSecret(String vaultId, String secretName) {
        VaultDescriptor vault = vaultAuthorizationService.requireVaultPermission(vaultId, Permission.SECRET_DELETE_RECOVER);
        AppPrincipal principal = vaultAuthorizationService.requireCurrentPrincipal();
        String correlationId = CorrelationIdHolder.getOrGenerate();

        try {
            validator.validateSecretName(secretName);

            return lockManager.executeWithLock(vault.opaqueId(), secretName, () -> {
                SecretClient mutationClient = secretClientProvider.getMutationClient(vault);
                SyncPoller<KeyVaultSecret, Void> poller = mutationClient.beginRecoverDeletedSecret(secretName);
                VaultCacheKey cacheKey = paginationService.cacheKeyFor(vault);

                auditLogger.logSuccess(
                        principal.subject(),
                        vault.opaqueId(),
                        secretName,
                        null,
                        "SECRET_RECOVER_INITIATED",
                        correlationId
                );

                return operationTracker.trackPoller(
                        principal.subject(),
                        vault.opaqueId(),
                        secretName,
                        OperationType.RECOVER,
                        Permission.SECRET_DELETE_RECOVER,
                        correlationId,
                        poller,
                        () -> {
                            cache.invalidate(cacheKey);
                            paginationService.startOrCoalesceRefresh(vault);
                            auditLogger.logSuccess(
                                    principal.subject(),
                                    vault.opaqueId(),
                                    secretName,
                                    null,
                                    "SECRET_RECOVER_COMPLETE",
                                    correlationId
                            );
                        },
                        failure -> auditLogger.logFailure(
                                principal.subject(),
                                vault.opaqueId(),
                                secretName,
                                null,
                                "SECRET_RECOVER_COMPLETE",
                                failure.getErrorCode(),
                                correlationId
                        )
                );
            });
        } catch (Throwable ex) {
            AppException translated = exceptionTranslator.translate(ex, "Deleted secret");
            auditLogger.logFailure(
                    principal.subject(),
                    vault.opaqueId(),
                    secretName,
                    null,
                    "SECRET_RECOVER",
                    translated.getErrorCode(),
                    correlationId
            );
            throw translated;
        }
    }

    private void checkSoftDeletedConflict(
            SecretClient readClient,
            VaultDescriptor vault,
            String secretName,
            String correlationId
    ) {
        try {
            DeletedSecret deleted = readClient.getDeletedSecret(secretName);
            if (deleted != null) {
                throw AppException.conflict(
                        "SECRET_SOFT_DELETED_CONFLICT",
                        "A soft-deleted secret with this name exists. Recover it or wait until retention expires before creating a new secret with this name."
                );
            }
        } catch (AppException conflict) {
            throw conflict;
        } catch (Throwable ex) {
            AppException translated = exceptionTranslator.translate(ex, "Deleted secret");
            if (translated.getStatus() == HttpStatus.NOT_FOUND) {
                return;
            }
            if (translated.getStatus() == HttpStatus.FORBIDDEN) {
                log.debug("Skipped soft-deleted pre-check due to missing deleted-secret read permission [vaultId={}, correlationId={}]",
                        vault.opaqueId(), correlationId);
                return;
            }
            throw translated;
        }
    }

    private Optional<SecretProperties> resolveLatestProperties(SecretClient readClient, String secretName) {
        List<SecretProperties> versions = listAllVersionProperties(readClient, secretName);
        return versions.isEmpty() ? Optional.empty() : Optional.of(versions.get(0));
    }

    /**
     * Walks all continuation pages of {@code listPropertiesOfSecretVersions(secretName)} without ever calling
     * {@code getSecret}, deduplicates by version ID, and sorts descending so index 0 is the latest version.
     */
    private List<SecretProperties> listAllVersionProperties(SecretClient readClient, String secretName) {
        List<IndexedProperties> collected = new ArrayList<>();
        LinkedHashMap<String, IndexedProperties> byVersion = new LinkedHashMap<>();
        int index = 0;

        try {
            Iterable<PagedResponse<SecretProperties>> pages = readClient
                    .listPropertiesOfSecretVersions(secretName)
                    .iterableByPage();
            for (PagedResponse<SecretProperties> page : pages) {
                List<SecretProperties> values = page != null ? page.getValue() : null;
                if (values == null) {
                    continue;
                }
                for (SecretProperties props : values) {
                    if (props == null) {
                        continue;
                    }
                    IndexedProperties item = new IndexedProperties(props, index++);
                    String version = props.getVersion();
                    if (version != null && !version.isBlank()) {
                        byVersion.put(version, item);
                    } else {
                        collected.add(item);
                    }
                }
            }
        } catch (Throwable ex) {
            AppException translated = exceptionTranslator.translate(ex, "Secret");
            if (translated.getStatus() == HttpStatus.NOT_FOUND) {
                return List.of();
            }
            throw translated;
        }

        List<IndexedProperties> all = new ArrayList<>(byVersion.size() + collected.size());
        all.addAll(byVersion.values());
        all.addAll(collected);

        all.sort((a, b) -> {
            int createdCmp = compareNullableDescending(a.properties().getCreatedOn(), b.properties().getCreatedOn());
            if (createdCmp != 0) {
                return createdCmp;
            }
            int updatedCmp = compareNullableDescending(a.properties().getUpdatedOn(), b.properties().getUpdatedOn());
            if (updatedCmp != 0) {
                return updatedCmp;
            }
            // Prefer later encountered item on exact timestamp tie
            return Integer.compare(b.encounterIndex(), a.encounterIndex());
        });

        return all.stream().map(IndexedProperties::properties).toList();
    }

    private static int compareNullableDescending(OffsetDateTime left, OffsetDateTime right) {
        if (left == null && right == null) {
            return 0;
        }
        if (left == null) {
            return 1;
        }
        if (right == null) {
            return -1;
        }
        return right.toInstant().compareTo(left.toInstant());
    }

    private record IndexedProperties(SecretProperties properties, int encounterIndex) {
    }
}
