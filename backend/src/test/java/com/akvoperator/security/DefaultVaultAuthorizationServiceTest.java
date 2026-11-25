package com.akvoperator.security;

import com.akvoperator.audit.AuditLogger;
import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.dto.Permission;
import com.akvoperator.common.dto.Role;
import com.akvoperator.common.dto.SubscriptionDto;
import com.akvoperator.common.dto.VaultDto;
import com.akvoperator.common.dto.VaultSource;
import com.akvoperator.common.exception.AppException;
import com.akvoperator.vault.VaultDescriptor;
import com.akvoperator.vault.VaultRegistry;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DefaultVaultAuthorizationServiceTest {

    private static final String VAULT_A_RES_ID =
            "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.KeyVault/vaults/kv-alpha";
    private static final String VAULT_B_RES_ID =
            "/subscriptions/sub-b/resourceGroups/rg-b/providers/Microsoft.KeyVault/vaults/kv-beta";

    private static final VaultDescriptor VAULT_A = new VaultDescriptor(
            "vault_alpha_1234", VAULT_A_RES_ID, "kv-alpha", "sub-a", "rg-a", "westeurope",
            "https://kv-alpha.vault.azure.net", "prod", true, VaultSource.ARM_DISCOVERY
    );
    private static final VaultDescriptor VAULT_B = new VaultDescriptor(
            "vault_beta_5678", VAULT_B_RES_ID, "kv-beta", "sub-b", "rg-b", "westeurope",
            "https://kv-beta.vault.azure.net", "dev", false, VaultSource.ARM_DISCOVERY
    );

    private final ObjectMapper objectMapper = new ObjectMapper();

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void enforcesFullRbacMatrixPerRole() {
        AppProperties props = serverPropsWithMappings(List.of(
                mapping("viewer-user", null, VAULT_A_RES_ID, Role.VIEWER),
                mapping("operator-user", null, VAULT_A_RES_ID, Role.OPERATOR),
                mapping("manager-user", null, VAULT_A_RES_ID, Role.MANAGER),
                mapping("admin-user", null, VAULT_A_RES_ID, Role.ADMIN)
        ));
        DefaultVaultAuthorizationService service = createService(props, mock(VaultRegistry.class), mock(AuditLogger.class));

        assertThat(service.getPermissionsForVault(serverPrincipal("viewer-user", Set.of()), VAULT_A))
                .containsExactlyInAnyOrder(Permission.SECRET_LIST);

        assertThat(service.getPermissionsForVault(serverPrincipal("operator-user", Set.of()), VAULT_A))
                .containsExactlyInAnyOrder(Permission.SECRET_LIST, Permission.SECRET_REVEAL);

        assertThat(service.getPermissionsForVault(serverPrincipal("manager-user", Set.of()), VAULT_A))
                .containsExactlyInAnyOrder(Permission.SECRET_LIST, Permission.SECRET_REVEAL, Permission.SECRET_WRITE);

        assertThat(service.getPermissionsForVault(serverPrincipal("admin-user", Set.of()), VAULT_A))
                .containsExactlyInAnyOrder(
                        Permission.SECRET_LIST, Permission.SECRET_REVEAL,
                        Permission.SECRET_WRITE, Permission.SECRET_DELETE_RECOVER
                );
    }

    @Test
    void deniesUnmappedUserAndLocalOperatorInServerProfile() {
        AppProperties props = serverPropsWithMappings(List.of(
                mapping("mapped-user", null, VAULT_A_RES_ID, Role.ADMIN)
        ));
        DefaultVaultAuthorizationService service = createService(props, mock(VaultRegistry.class), mock(AuditLogger.class));

        AppPrincipal unmapped = serverPrincipal("unmapped-user", Set.of("some-group"));
        assertThat(service.getPermissionsForVault(unmapped, VAULT_A)).isEmpty();

        AppPrincipal spoofedLocal = new AppPrincipal("local-operator", "Local", "local", Set.of("local-admin"), true);
        assertThat(service.getPermissionsForVault(spoofedLocal, VAULT_A)).isEmpty();
    }

    @Test
    void blocksCrossVaultIdorAndAuditsDeniedAttempt() {
        AppProperties props = serverPropsWithMappings(List.of(
                mapping("alice", null, VAULT_A_RES_ID, Role.ADMIN)
        ));
        VaultRegistry registry = mock(VaultRegistry.class);
        when(registry.findByOpaqueId(VAULT_A.opaqueId())).thenReturn(Optional.of(VAULT_A));
        when(registry.findByOpaqueId(VAULT_B.opaqueId())).thenReturn(Optional.of(VAULT_B));
        when(registry.findByOpaqueId("unknown_id_9999")).thenReturn(Optional.empty());

        AuditLogger auditLogger = mock(AuditLogger.class);
        DefaultVaultAuthorizationService service = createService(props, registry, auditLogger);

        authenticate(serverPrincipal("alice", Set.of()));

        // Authorized on Vault A
        assertThat(service.requireVaultPermission(VAULT_A.opaqueId(), Permission.SECRET_DELETE_RECOVER))
                .isEqualTo(VAULT_A);

        // Cross-vault IDOR attempt on Vault B -> 403
        assertThatThrownBy(() -> service.requireVaultPermission(VAULT_B.opaqueId(), Permission.SECRET_LIST))
                .isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getStatus()).isEqualTo(HttpStatus.FORBIDDEN);
                    assertThat(appEx.getErrorCode()).isEqualTo("VAULT_PERMISSION_DENIED");
                });
        verify(auditLogger).logDenied(
                eq("alice"), eq(VAULT_B.opaqueId()), eq(null), eq(null),
                eq("VAULT_ACCESS:SECRET_LIST"), eq("VAULT_PERMISSION_DENIED"), any()
        );

        // Unknown opaque ID -> 404
        assertThatThrownBy(() -> service.requireVaultPermission("unknown_id_9999", Permission.SECRET_LIST))
                .isInstanceOf(AppException.class)
                .satisfies(ex -> assertThat(((AppException) ex).getStatus()).isEqualTo(HttpStatus.NOT_FOUND));
    }

    @Test
    void filtersDiscoveryVaultsAndSubscriptionsByUserPermissions() {
        AppProperties props = serverPropsWithMappings(List.of(
                mapping(null, "team-alpha", VAULT_A_RES_ID.toUpperCase(), Role.VIEWER)
        ));
        DefaultVaultAuthorizationService service = createService(props, mock(VaultRegistry.class), mock(AuditLogger.class));

        authenticate(serverPrincipal("bob", Set.of("team-alpha")));

        List<VaultDto> vaults = service.filterAuthorizedVaults(List.of(VAULT_A, VAULT_B));
        assertThat(vaults).hasSize(1);
        assertThat(vaults.get(0).id()).isEqualTo(VAULT_A.opaqueId());
        assertThat(vaults.get(0).permissions()).containsExactly(Permission.SECRET_LIST);

        List<SubscriptionDto> subs = service.filterAuthorizedSubscriptions(
                List.of(
                        new SubscriptionDto("sub-a", "Alpha Sub", "Enabled"),
                        new SubscriptionDto("sub-b", "Beta Sub", "Enabled")
                ),
                vaults
        );
        assertThat(subs).extracting(SubscriptionDto::subscriptionId).containsExactly("sub-a");
    }

    @Test
    void enforcesOperationOwnerAndVaultScope() {
        AppProperties props = serverPropsWithMappings(List.of(
                mapping("admin-1", null, VAULT_A_RES_ID, Role.ADMIN),
                mapping("admin-2", null, VAULT_A_RES_ID, Role.ADMIN)
        ));
        VaultRegistry registry = mock(VaultRegistry.class);
        when(registry.findByOpaqueId(VAULT_A.opaqueId())).thenReturn(Optional.of(VAULT_A));
        AuditLogger auditLogger = mock(AuditLogger.class);
        DefaultVaultAuthorizationService service = createService(props, registry, auditLogger);

        // Owner allowed
        authenticate(serverPrincipal("admin-1", Set.of()));
        service.requireOperationAccess("admin-1", VAULT_A.opaqueId(), Permission.SECRET_DELETE_RECOVER);

        // Another user even with ADMIN on same vault cannot read admin-1's operation
        authenticate(serverPrincipal("admin-2", Set.of()));
        assertThatThrownBy(() ->
                service.requireOperationAccess("admin-1", VAULT_A.opaqueId(), Permission.SECRET_DELETE_RECOVER))
                .isInstanceOf(AppException.class)
                .satisfies(ex -> assertThat(((AppException) ex).getErrorCode()).isEqualTo("OPERATION_ACCESS_DENIED"));
    }

    @Test
    void localOperatorHasAdminOnDiscoveredVaultsInLocalProfile() {
        AppProperties props = new AppProperties();
        props.setProfile("local");
        DefaultVaultAuthorizationService service = createService(props, mock(VaultRegistry.class), mock(AuditLogger.class));

        AppPrincipal localOp = new AppPrincipal("local-operator", "Local Operator", "local", Set.of("local-admin"), true);
        assertThat(service.getPermissionsForVault(localOp, VAULT_A))
                .containsExactlyInAnyOrderElementsOf(Role.ADMIN.permissions());
    }

    private DefaultVaultAuthorizationService createService(
            AppProperties props,
            VaultRegistry registry,
            AuditLogger auditLogger
    ) {
        RoleMappingResolver resolver = new RoleMappingResolver(props, objectMapper);
        return new DefaultVaultAuthorizationService(props, registry, resolver, auditLogger);
    }

    private static AppProperties serverPropsWithMappings(List<AppProperties.RoleMappingConfig> mappings) {
        AppProperties props = new AppProperties();
        props.setProfile("server");
        props.getServer().setRoleMappings(mappings);
        return props;
    }

    private static AppProperties.RoleMappingConfig mapping(
            String subject,
            String group,
            String vaultResourceId,
            Role role
    ) {
        AppProperties.RoleMappingConfig cfg = new AppProperties.RoleMappingConfig();
        cfg.setSubject(subject);
        cfg.setGroup(group);
        cfg.setVaultResourceId(vaultResourceId);
        cfg.setRole(role);
        return cfg;
    }

    private static AppPrincipal serverPrincipal(String subject, Set<String> groups) {
        return new AppPrincipal(subject, subject, "https://hydra.example.com", groups, false);
    }

    private static void authenticate(AppPrincipal principal) {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(principal, null, List.of())
        );
    }
}
