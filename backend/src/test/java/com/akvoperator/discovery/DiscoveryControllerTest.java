package com.akvoperator.discovery;

import com.akvoperator.audit.AuditLogger;
import com.akvoperator.common.dto.Permission;
import com.akvoperator.common.dto.SubscriptionDto;
import com.akvoperator.common.dto.VaultDto;
import com.akvoperator.common.dto.VaultSource;
import com.akvoperator.security.AppPrincipal;
import com.akvoperator.security.VaultAuthorizationService;
import com.akvoperator.vault.VaultDescriptor;
import com.akvoperator.vault.VaultRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DiscoveryControllerTest {

    @Test
    void listVaultsFiltersByAuthorizationAndOptionalSubscriptionIdAndAudits() {
        VaultRegistry registry = mock(VaultRegistry.class);
        VaultAuthorizationService authService = mock(VaultAuthorizationService.class);
        AuditLogger auditLogger = mock(AuditLogger.class);

        AppPrincipal principal = new AppPrincipal("alice@example.com", "Alice", "https://idp.example.com", Set.of("ops"), false);
        when(authService.requireCurrentPrincipal()).thenReturn(principal);

        VaultDescriptor d1 = new VaultDescriptor("vlt_aaaaaaaaaaaaaaaaaaaaaaaa", "/sub/1/v1", "v1", "sub-1", "rg-1",
                "westeurope", "https://v1.vault.azure.net", "dev", false, VaultSource.ARM_DISCOVERY);
        VaultDescriptor d2 = new VaultDescriptor("vlt_bbbbbbbbbbbbbbbbbbbbbbbb", "/sub/2/v2", "v2", "sub-2", "rg-2",
                "westeurope", "https://v2.vault.azure.net", "prod", true, VaultSource.ARM_DISCOVERY);
        when(registry.listVaults()).thenReturn(List.of(d1, d2));

        VaultDto dto1 = new VaultDto(d1.opaqueId(), d1.name(), d1.subscriptionId(), d1.resourceGroup(),
                d1.location(), d1.vaultUri(), d1.environment(), d1.production(), d1.source(), Set.of(Permission.SECRET_LIST));
        VaultDto dto2 = new VaultDto(d2.opaqueId(), d2.name(), d2.subscriptionId(), d2.resourceGroup(),
                d2.location(), d2.vaultUri(), d2.environment(), d2.production(), d2.source(), Set.of(Permission.SECRET_LIST));
        when(authService.filterAuthorizedVaults(List.of(d1, d2))).thenReturn(List.of(dto1, dto2));

        DiscoveryController controller = new DiscoveryController(registry, authService, auditLogger);

        ResponseEntity<List<VaultDto>> response = controller.listVaults("sub-1");
        assertThat(response.getBody()).containsExactly(dto1);
        assertThat(response.getHeaders().getCacheControl()).contains("no-store");
        verify(auditLogger).logSuccess(eq("alice@example.com"), isNull(), isNull(), isNull(), eq("DISCOVERY_LIST_VAULTS"), any());
    }

    @Test
    void listSubscriptionsFiltersByAuthorizedVaultsAndAudits() {
        VaultRegistry registry = mock(VaultRegistry.class);
        VaultAuthorizationService authService = mock(VaultAuthorizationService.class);
        AuditLogger auditLogger = mock(AuditLogger.class);

        AppPrincipal principal = new AppPrincipal("alice@example.com", "Alice", "https://idp.example.com", Set.of("ops"), false);
        when(authService.requireCurrentPrincipal()).thenReturn(principal);

        SubscriptionDto sub1 = new SubscriptionDto("sub-1", "Sub One", "Enabled");
        SubscriptionDto sub2 = new SubscriptionDto("sub-2", "Sub Two", "Enabled");
        when(registry.listSubscriptions()).thenReturn(List.of(sub1, sub2));
        when(registry.listVaults()).thenReturn(List.of());
        when(authService.filterAuthorizedVaults(List.of())).thenReturn(List.of());
        when(authService.filterAuthorizedSubscriptions(List.of(sub1, sub2), List.of())).thenReturn(List.of(sub1));

        DiscoveryController controller = new DiscoveryController(registry, authService, auditLogger);

        ResponseEntity<List<SubscriptionDto>> response = controller.listSubscriptions();
        assertThat(response.getBody()).containsExactly(sub1);
        assertThat(response.getHeaders().getCacheControl()).contains("no-store");
        verify(auditLogger).logSuccess(eq("alice@example.com"), isNull(), isNull(), isNull(), eq("DISCOVERY_LIST_SUBSCRIPTIONS"), any());
    }

    @Test
    void refreshVaultsForcesRegistryRefreshFiltersByAuthorizationAndAudits() {
        VaultRegistry registry = mock(VaultRegistry.class);
        VaultAuthorizationService authService = mock(VaultAuthorizationService.class);
        AuditLogger auditLogger = mock(AuditLogger.class);

        AppPrincipal principal = new AppPrincipal("alice@example.com", "Alice", "https://idp.example.com", Set.of("ops"), false);
        when(authService.requireCurrentPrincipal()).thenReturn(principal);

        VaultDescriptor d1 = new VaultDescriptor("vlt_aaaaaaaaaaaaaaaaaaaaaaaa", "/sub/1/v1", "v1", "sub-1", "rg-1",
                "westeurope", "https://v1.vault.azure.net", "dev", false, VaultSource.ARM_DISCOVERY);
        when(registry.listVaults()).thenReturn(List.of(d1));

        VaultDto dto1 = new VaultDto(d1.opaqueId(), d1.name(), d1.subscriptionId(), d1.resourceGroup(),
                d1.location(), d1.vaultUri(), d1.environment(), d1.production(), d1.source(), Set.of(Permission.SECRET_LIST));
        when(authService.filterAuthorizedVaults(List.of(d1))).thenReturn(List.of(dto1));

        DiscoveryController controller = new DiscoveryController(registry, authService, auditLogger);

        ResponseEntity<List<VaultDto>> response = controller.refreshVaults(null);
        verify(registry).refreshDiscovery();
        assertThat(response.getBody()).containsExactly(dto1);
        assertThat(response.getHeaders().getCacheControl()).contains("no-store");
        verify(auditLogger).logSuccess(eq("alice@example.com"), isNull(), isNull(), isNull(), eq("DISCOVERY_REFRESH_VAULTS"), any());
    }
}
