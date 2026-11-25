package com.akvoperator.security;

import com.akvoperator.common.dto.Permission;
import com.akvoperator.common.dto.SubscriptionDto;
import com.akvoperator.common.dto.VaultDto;
import com.akvoperator.vault.VaultDescriptor;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public interface VaultAuthorizationService {

    Optional<AppPrincipal> getCurrentPrincipal();

    AppPrincipal requireCurrentPrincipal();

    Set<Permission> getPermissionsForVault(AppPrincipal principal, VaultDescriptor vault);

    VaultDescriptor requireVaultPermission(String opaqueVaultId, Permission permission);

    List<VaultDto> filterAuthorizedVaults(List<VaultDescriptor> discoveredVaults);

    List<SubscriptionDto> filterAuthorizedSubscriptions(
            List<SubscriptionDto> discoveredSubscriptions,
            List<VaultDto> authorizedVaults
    );

    Map<String, Set<Permission>> getAllPermissionsByVault(AppPrincipal principal, List<VaultDescriptor> vaults);

    void requireOperationAccess(String ownerSubject, String opaqueVaultId, Permission requiredPermission);
}
