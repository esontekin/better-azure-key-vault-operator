package com.akvoperator.security;

import com.akvoperator.audit.AuditLogger;
import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.correlation.CorrelationIdHolder;
import com.akvoperator.common.dto.Permission;
import com.akvoperator.common.dto.Role;
import com.akvoperator.common.dto.SubscriptionDto;
import com.akvoperator.common.dto.VaultDto;
import com.akvoperator.common.exception.AppException;
import com.akvoperator.vault.VaultDescriptor;
import com.akvoperator.vault.VaultRegistry;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Deny-by-default RBAC and vault-scope authorization service.
 */
@Service
public class DefaultVaultAuthorizationService implements VaultAuthorizationService {

    private final AppProperties appProperties;
    private final VaultRegistry vaultRegistry;
    private final RoleMappingResolver roleMappingResolver;
    private final AuditLogger auditLogger;

    public DefaultVaultAuthorizationService(
            AppProperties appProperties,
            VaultRegistry vaultRegistry,
            RoleMappingResolver roleMappingResolver,
            AuditLogger auditLogger
    ) {
        this.appProperties = appProperties;
        this.vaultRegistry = vaultRegistry;
        this.roleMappingResolver = roleMappingResolver;
        this.auditLogger = auditLogger;
    }

    @Override
    public Optional<AppPrincipal> getCurrentPrincipal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null
                || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            return Optional.empty();
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof AppPrincipal appPrincipal) {
            return Optional.of(appPrincipal);
        }
        if (principal instanceof AppOidcUser oidcUser) {
            return Optional.of(oidcUser.toAppPrincipal());
        }
        return Optional.empty();
    }

    @Override
    public AppPrincipal requireCurrentPrincipal() {
        return getCurrentPrincipal()
                .orElseThrow(() -> AppException.authRequired("Authentication is required to access this resource."));
    }

    @Override
    public Set<Permission> getPermissionsForVault(AppPrincipal principal, VaultDescriptor vault) {
        if (principal == null || vault == null) {
            return Set.of();
        }
        if (appProperties.isLocalProfile()) {
            if (principal.localOperator()) {
                return Role.ADMIN.permissions();
            }
            return Set.of();
        }
        if (appProperties.isServerProfile()) {
            // Never allow localOperator flag in server profile
            if (principal.localOperator()) {
                return Set.of();
            }
            return roleMappingResolver.resolvePermissions(principal, vault.resourceId());
        }
        return Set.of();
    }

    @Override
    public VaultDescriptor requireVaultPermission(String opaqueVaultId, Permission permission) {
        AppPrincipal principal = requireCurrentPrincipal();
        String correlationId = CorrelationIdHolder.getOrGenerate();
        String action = "VAULT_ACCESS:" + (permission != null ? permission.name() : "UNKNOWN");

        if (opaqueVaultId == null || opaqueVaultId.isBlank() || permission == null) {
            auditLogger.logDenied(principal.subject(), opaqueVaultId, null, null, action, "VAULT_NOT_FOUND", correlationId);
            throw AppException.notFound("VAULT_NOT_FOUND", "The requested Key Vault was not found or is not accessible.");
        }

        Optional<VaultDescriptor> vaultOpt = vaultRegistry.findByOpaqueId(opaqueVaultId);
        if (vaultOpt.isEmpty()) {
            auditLogger.logDenied(principal.subject(), opaqueVaultId, null, null, action, "VAULT_NOT_FOUND", correlationId);
            throw AppException.notFound("VAULT_NOT_FOUND", "The requested Key Vault was not found or is not accessible.");
        }

        VaultDescriptor vault = vaultOpt.get();
        Set<Permission> permissions = getPermissionsForVault(principal, vault);
        if (!permissions.contains(permission)) {
            auditLogger.logDenied(
                    principal.subject(),
                    opaqueVaultId,
                    null,
                    null,
                    action,
                    "VAULT_PERMISSION_DENIED",
                    correlationId
            );
            throw AppException.forbidden(
                    "VAULT_PERMISSION_DENIED",
                    "You do not have permission to perform this action on the requested Key Vault."
            );
        }
        return vault;
    }

    @Override
    public List<VaultDto> filterAuthorizedVaults(List<VaultDescriptor> discoveredVaults) {
        AppPrincipal principal = requireCurrentPrincipal();
        if (discoveredVaults == null || discoveredVaults.isEmpty()) {
            return List.of();
        }
        List<VaultDto> authorized = new ArrayList<>();
        for (VaultDescriptor vault : discoveredVaults) {
            Set<Permission> permissions = getPermissionsForVault(principal, vault);
            if (permissions.contains(Permission.SECRET_LIST)) {
                authorized.add(new VaultDto(
                        vault.opaqueId(),
                        vault.name(),
                        vault.subscriptionId(),
                        vault.resourceGroup(),
                        vault.location(),
                        vault.vaultUri(),
                        vault.environment(),
                        vault.production(),
                        vault.source(),
                        permissions
                ));
            }
        }
        return List.copyOf(authorized);
    }

    @Override
    public List<SubscriptionDto> filterAuthorizedSubscriptions(
            List<SubscriptionDto> discoveredSubscriptions,
            List<VaultDto> authorizedVaults
    ) {
        if (discoveredSubscriptions == null || discoveredSubscriptions.isEmpty()
                || authorizedVaults == null || authorizedVaults.isEmpty()) {
            return List.of();
        }
        Set<String> allowedSubIds = authorizedVaults.stream()
                .map(VaultDto::subscriptionId)
                .filter(id -> id != null && !id.isBlank())
                .map(id -> id.trim().toLowerCase(Locale.ROOT))
                .collect(Collectors.toSet());

        return discoveredSubscriptions.stream()
                .filter(sub -> sub.subscriptionId() != null
                        && allowedSubIds.contains(sub.subscriptionId().trim().toLowerCase(Locale.ROOT)))
                .toList();
    }

    @Override
    public Map<String, Set<Permission>> getAllPermissionsByVault(AppPrincipal principal, List<VaultDescriptor> vaults) {
        if (principal == null || vaults == null || vaults.isEmpty()) {
            return Map.of();
        }
        Map<String, Set<Permission>> result = new LinkedHashMap<>();
        for (VaultDescriptor vault : vaults) {
            Set<Permission> permissions = getPermissionsForVault(principal, vault);
            if (!permissions.isEmpty()) {
                result.put(vault.opaqueId(), permissions);
            }
        }
        return Map.copyOf(result);
    }

    @Override
    public void requireOperationAccess(String ownerSubject, String opaqueVaultId, Permission requiredPermission) {
        AppPrincipal principal = requireCurrentPrincipal();
        requireVaultPermission(opaqueVaultId, requiredPermission);

        if (!principal.localOperator()) {
            if (ownerSubject == null || !ownerSubject.equals(principal.subject())) {
                auditLogger.logDenied(
                        principal.subject(),
                        opaqueVaultId,
                        null,
                        null,
                        "OPERATION_STATUS_READ",
                        "OPERATION_ACCESS_DENIED",
                        CorrelationIdHolder.getOrGenerate()
                );
                throw AppException.forbidden(
                        "OPERATION_ACCESS_DENIED",
                        "You do not have permission to access this asynchronous operation."
                );
            }
        }
    }
}
