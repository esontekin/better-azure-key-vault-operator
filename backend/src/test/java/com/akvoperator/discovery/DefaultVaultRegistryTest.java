package com.akvoperator.discovery;

import com.akvoperator.azure.AzureVaultUrlValidator;
import com.akvoperator.azure.OpaqueVaultIdGenerator;
import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.dto.SubscriptionDto;
import com.akvoperator.common.dto.VaultSource;
import com.akvoperator.common.exception.AppException;
import com.akvoperator.vault.DefaultVaultRegistry;
import com.akvoperator.vault.VaultDescriptor;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DefaultVaultRegistryTest {

    private static final String SUB_1 = "11111111-1111-1111-1111-111111111111";
    private static final String SUB_2 = "22222222-2222-2222-2222-222222222222";
    private static final String PROD_RES_ID = "/subscriptions/" + SUB_1 + "/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/kv-payments-prod";
    private static final String DEV_RES_ID = "/subscriptions/" + SUB_1 + "/resourceGroups/rg-dev/providers/Microsoft.KeyVault/vaults/kv-payments-dev";
    private static final String STATIC_RES_ID = "/subscriptions/" + SUB_2 + "/resourceGroups/rg-static/providers/Microsoft.KeyVault/vaults/kv-static-stg";

    private final AzureVaultUrlValidator validator = new AzureVaultUrlValidator(true);

    @Test
    void mergesArmDiscoveryAndStaticConfigWithDeterministicOpaqueIdsAndEnvironmentLabels() {
        ArmDiscoveryClient armClient = mock(ArmDiscoveryClient.class);
        when(armClient.discover()).thenReturn(new ArmDiscoveryResult(
                List.of(new SubscriptionDto(SUB_1, "Primary Sub", "Enabled")),
                List.of(
                        new DiscoveredVault(
                                PROD_RES_ID,
                                "kv-payments-prod",
                                SUB_1,
                                "rg-prod",
                                "westeurope",
                                "https://kv-payments-prod.vault.azure.net/",
                                Map.of("Environment", "Production")
                        ),
                        new DiscoveredVault(
                                DEV_RES_ID,
                                "kv-payments-dev",
                                SUB_1,
                                "rg-dev",
                                "westeurope",
                                "https://kv-payments-dev.vault.azure.net/",
                                Map.of()
                        )
                )
        ));

        AppProperties props = new AppProperties();
        props.setStaticVaults(List.of(staticVault(STATIC_RES_ID, "https://kv-static-stg.vault.azure.net/", "kv-static-stg", SUB_2, "staging")));

        DefaultVaultRegistry registry = new DefaultVaultRegistry(armClient, validator, props);
        List<VaultDescriptor> vaults = registry.listVaults();

        assertThat(vaults).hasSize(3);
        VaultDescriptor prod = vaults.stream().filter(v -> v.name().equals("kv-payments-prod")).findFirst().orElseThrow();
        assertThat(prod.production()).isTrue();
        assertThat(prod.environment()).isEqualTo("prod");
        assertThat(prod.source()).isEqualTo(VaultSource.ARM_DISCOVERY);
        assertThat(prod.vaultUri()).isEqualTo("https://kv-payments-prod.vault.azure.net");
        assertThat(prod.opaqueId()).isEqualTo(OpaqueVaultIdGenerator.generate(PROD_RES_ID));
        assertThat(prod.opaqueId()).matches("^vlt_[a-zA-Z0-9_-]{24}$");

        VaultDescriptor dev = vaults.stream().filter(v -> v.name().equals("kv-payments-dev")).findFirst().orElseThrow();
        assertThat(dev.production()).isFalse();
        assertThat(dev.environment()).isEqualTo("dev");

        VaultDescriptor staticVault = vaults.stream().filter(v -> v.name().equals("kv-static-stg")).findFirst().orElseThrow();
        assertThat(staticVault.source()).isEqualTo(VaultSource.STATIC_CONFIG);
        assertThat(staticVault.environment()).isEqualTo("staging");
        assertThat(staticVault.production()).isFalse();

        assertThat(registry.findByOpaqueId(prod.opaqueId())).contains(prod);
        assertThat(registry.listSubscriptions()).extracting(SubscriptionDto::subscriptionId)
                .containsExactlyInAnyOrder(SUB_1, SUB_2);

        // Cached within TTL: ARM discover called only once
        registry.listVaults();
        verify(armClient, times(1)).discover();

        // Explicit refresh reloads
        registry.refreshDiscovery();
        verify(armClient, times(2)).discover();
    }

    @Test
    void enforcesAllowedVaultIdsCaseInsensitively() {
        ArmDiscoveryClient armClient = mock(ArmDiscoveryClient.class);
        when(armClient.discover()).thenReturn(new ArmDiscoveryResult(
                List.of(new SubscriptionDto(SUB_1, "Primary Sub", "Enabled")),
                List.of(
                        new DiscoveredVault(PROD_RES_ID, "kv-payments-prod", SUB_1, "rg-prod", "westeurope",
                                "https://kv-payments-prod.vault.azure.net", Map.of()),
                        new DiscoveredVault(DEV_RES_ID, "kv-payments-dev", SUB_1, "rg-dev", "westeurope",
                                "https://kv-payments-dev.vault.azure.net", Map.of())
                )
        ));

        AppProperties props = new AppProperties();
        props.setAllowedVaultIds(List.of(DEV_RES_ID.toUpperCase()));

        DefaultVaultRegistry registry = new DefaultVaultRegistry(armClient, validator, props);
        List<VaultDescriptor> vaults = registry.listVaults();

        assertThat(vaults).hasSize(1);
        assertThat(vaults.getFirst().name()).isEqualTo("kv-payments-dev");
    }

    @Test
    void fallsBackToStaticVaultsWhenArmReturns403Forbidden() {
        ArmDiscoveryClient armClient = mock(ArmDiscoveryClient.class);
        when(armClient.discover()).thenThrow(AppException.azurePermissionDenied(null));

        AppProperties props = new AppProperties();
        props.setStaticVaults(List.of(staticVault(STATIC_RES_ID, "https://kv-static-stg.vault.azure.net", "kv-static-stg", SUB_2, "staging")));

        DefaultVaultRegistry registry = new DefaultVaultRegistry(armClient, validator, props);
        List<VaultDescriptor> vaults = registry.listVaults();

        assertThat(vaults).hasSize(1);
        assertThat(vaults.getFirst().source()).isEqualTo(VaultSource.STATIC_CONFIG);
        assertThat(vaults.getFirst().name()).isEqualTo("kv-static-stg");
    }

    @Test
    void propagatesArm403ErrorWhenNoStaticVaultsConfigured() {
        ArmDiscoveryClient armClient = mock(ArmDiscoveryClient.class);
        when(armClient.discover()).thenThrow(AppException.azurePermissionDenied(null));

        AppProperties props = new AppProperties();
        DefaultVaultRegistry registry = new DefaultVaultRegistry(armClient, validator, props);

        assertThatThrownBy(registry::listVaults)
                .isInstanceOf(AppException.class)
                .satisfies(ex -> assertThat(((AppException) ex).getErrorCode()).isEqualTo("AZURE_PERMISSION_DENIED"));
    }

    @Test
    void rejectsInvalidStaticVaultUriFailClosed() {
        ArmDiscoveryClient armClient = mock(ArmDiscoveryClient.class);

        AppProperties props = new AppProperties();
        props.setStaticVaults(List.of(staticVault(STATIC_RES_ID, "https://evil.example.com", "evil", SUB_2, "prod")));

        DefaultVaultRegistry registry = new DefaultVaultRegistry(armClient, validator, props);

        assertThatThrownBy(registry::validateStaticVaultConfiguration)
                .isInstanceOf(AppException.class)
                .satisfies(ex -> assertThat(((AppException) ex).getErrorCode()).isEqualTo("INVALID_CONFIGURATION"));
    }

    @Test
    void skipsUntrustedArmDiscoveredVaultUriAndRespectsCacheTtl() {
        ArmDiscoveryClient armClient = mock(ArmDiscoveryClient.class);
        when(armClient.discover()).thenReturn(new ArmDiscoveryResult(
                List.of(new SubscriptionDto(SUB_1, "Primary Sub", "Enabled")),
                List.of(
                        new DiscoveredVault(DEV_RES_ID, "kv-payments-dev", SUB_1, "rg-dev", "westeurope",
                                "https://kv-payments-dev.vault.azure.net", Map.of()),
                        new DiscoveredVault("/subscriptions/" + SUB_1 + "/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/bad",
                                "bad", SUB_1, "rg", "westeurope",
                                "https://bad.vault.evil.com", Map.of())
                )
        ));

        AppProperties props = new AppProperties();
        props.setMetadataTtl(Duration.ofSeconds(1));
        Clock fixedClock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);

        DefaultVaultRegistry registry = new DefaultVaultRegistry(armClient, validator, props, fixedClock);
        List<VaultDescriptor> vaults = registry.listVaults();

        assertThat(vaults).hasSize(1);
        assertThat(vaults.getFirst().name()).isEqualTo("kv-payments-dev");
    }

    private static AppProperties.StaticVaultConfig staticVault(
            String resourceId,
            String vaultUri,
            String name,
            String subId,
            String env
    ) {
        AppProperties.StaticVaultConfig cfg = new AppProperties.StaticVaultConfig();
        cfg.setResourceId(resourceId);
        cfg.setVaultUri(vaultUri);
        cfg.setName(name);
        cfg.setSubscriptionId(subId);
        cfg.setEnvironment(env);
        return cfg;
    }
}
