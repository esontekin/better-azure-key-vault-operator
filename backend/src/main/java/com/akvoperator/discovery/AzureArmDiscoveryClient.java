package com.akvoperator.discovery;

import com.akvoperator.azure.AzureCredentialFactory;
import com.akvoperator.azure.AzureExceptionTranslator;
import com.akvoperator.azure.AzureHttpClientFactory;
import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.dto.SubscriptionDto;
import com.akvoperator.common.exception.AppException;
import com.akvoperator.vault.VaultEnvironmentClassifier;
import com.azure.core.http.policy.ExponentialBackoffOptions;
import com.azure.core.http.policy.RetryOptions;
import com.azure.core.management.AzureEnvironment;
import com.azure.core.management.profile.AzureProfile;
import com.azure.resourcemanager.keyvault.KeyVaultManager;
import com.azure.resourcemanager.keyvault.fluent.models.VaultInner;
import com.azure.resourcemanager.resources.ResourceManager;
import com.azure.resourcemanager.resources.models.Subscription;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Azure Resource Manager (ARM) discovery client for Azure Public Cloud.
 * Reuses the application's shared
 * {@link com.azure.core.credential.TokenCredential} and hardened HTTP pipeline
 * with HTTP logging disabled and cross-host redirects blocked.
 */
@Component
public class AzureArmDiscoveryClient implements ArmDiscoveryClient {

    private static final Logger log = LoggerFactory.getLogger(AzureArmDiscoveryClient.class);

    private final AzureCredentialFactory credentialFactory;
    private final AzureHttpClientFactory httpClientFactory;
    private final AzureExceptionTranslator exceptionTranslator;
    private final AppProperties appProperties;

    public AzureArmDiscoveryClient(
            AzureCredentialFactory credentialFactory,
            AzureHttpClientFactory httpClientFactory,
            AzureExceptionTranslator exceptionTranslator,
            AppProperties appProperties) {
        this.credentialFactory = credentialFactory;
        this.httpClientFactory = httpClientFactory;
        this.exceptionTranslator = exceptionTranslator;
        this.appProperties = appProperties;
    }

    @Override
    public ArmDiscoveryResult discover() {
        String tenantId = credentialFactory.getTenantId();
        String configuredSubscriptionId = trimToNull(
                appProperties != null && appProperties.getAzure() != null
                        ? appProperties.getAzure().getSubscriptionId()
                        : null);
        RetryOptions retryOptions = buildReadRetryOptions();

        List<SubscriptionDto> discoveredSubscriptions = new ArrayList<>();
        AppException subscriptionListError = null;

        try {
            AzureProfile baseProfile = new AzureProfile(tenantId, configuredSubscriptionId, AzureEnvironment.AZURE);
            ResourceManager.Authenticated authenticated = ResourceManager.configure()
                    .withHttpClient(httpClientFactory.getHttpClient())
                    .withLogOptions(httpClientFactory.createNoLoggingOptions())
                    .withPolicy(httpClientFactory.getNoCrossHostRedirectPolicy())
                    .withRetryOptions(retryOptions)
                    .authenticate(credentialFactory.getCredential(), baseProfile);

            for (Subscription subscription : authenticated.subscriptions().list()) {
                String subId = subscription.subscriptionId();
                if (configuredSubscriptionId != null && !configuredSubscriptionId.equalsIgnoreCase(subId)) {
                    continue;
                }
                discoveredSubscriptions.add(new SubscriptionDto(
                        subId,
                        subscription.displayName() != null ? subscription.displayName() : subId,
                        subscription.state() != null ? subscription.state().toString() : null));
            }
        } catch (RuntimeException ex) {
            AppException translated = exceptionTranslator.translate(ex, "Azure subscriptions");
            if (configuredSubscriptionId != null && isPermissionDenied(translated)) {
                // SP may only have narrow Resource Group Reader inside the configured
                // subscription
                subscriptionListError = translated;
                log.warn(
                        "Unable to list subscriptions via ARM (403); attempting direct Key Vault discovery for configured subscription {}",
                        configuredSubscriptionId);
            } else {
                throw translated;
            }
        }

        if (discoveredSubscriptions.isEmpty() && configuredSubscriptionId != null) {
            discoveredSubscriptions.add(new SubscriptionDto(configuredSubscriptionId, configuredSubscriptionId, null));
        }

        List<DiscoveredVault> discoveredVaults = new ArrayList<>();
        List<SubscriptionDto> accessibleSubscriptions = new ArrayList<>();
        AppException lastVaultDiscoveryError = null;

        for (SubscriptionDto subscription : discoveredSubscriptions) {
            try {
                AzureProfile subProfile = new AzureProfile(tenantId, subscription.subscriptionId(),
                        AzureEnvironment.AZURE);
                KeyVaultManager kvManager = KeyVaultManager.configure()
                        .withHttpClient(httpClientFactory.getHttpClient())
                        .withLogOptions(httpClientFactory.createNoLoggingOptions())
                        .withPolicy(httpClientFactory.getNoCrossHostRedirectPolicy())
                        .withRetryOptions(retryOptions)
                        .authenticate(credentialFactory.getCredential(), subProfile);

                for (VaultInner vault : kvManager.serviceClient().getVaults().listBySubscription()) {
                    String resourceId = vault.id();
                    String vaultUri = vault.properties() != null ? vault.properties().vaultUri() : null;
                    String resourceGroup = VaultEnvironmentClassifier.extractResourceGroup(resourceId);
                    Map<String, String> tags = vault.tags() != null ? Map.copyOf(vault.tags()) : Map.of();

                    discoveredVaults.add(new DiscoveredVault(
                            resourceId,
                            vault.name(),
                            subscription.subscriptionId(),
                            resourceGroup,
                            vault.location(),
                            vaultUri,
                            tags));
                }
                accessibleSubscriptions.add(subscription);
            } catch (RuntimeException ex) {
                AppException translated = exceptionTranslator.translate(ex, "Azure Key Vaults");
                if (isPermissionDenied(translated)) {
                    log.warn("ARM Key Vault discovery denied (403) for subscription {}", subscription.subscriptionId());
                    lastVaultDiscoveryError = translated;
                } else {
                    throw translated;
                }
            }
        }

        if (accessibleSubscriptions.isEmpty()) {
            if (lastVaultDiscoveryError != null) {
                throw lastVaultDiscoveryError;
            }
            if (subscriptionListError != null) {
                throw subscriptionListError;
            }
        }

        return new ArmDiscoveryResult(accessibleSubscriptions, discoveredVaults);
    }

    private RetryOptions buildReadRetryOptions() {
        int maxRetries = appProperties != null && appProperties.getAzure() != null
                ? Math.max(0, appProperties.getAzure().getMaxReadRetries())
                : 3;
        return new RetryOptions(new ExponentialBackoffOptions()
                .setMaxRetries(maxRetries)
                .setBaseDelay(Duration.ofMillis(800))
                .setMaxDelay(Duration.ofSeconds(16)));
    }

    private static boolean isPermissionDenied(AppException ex) {
        return ex.getStatus() == HttpStatus.FORBIDDEN || "AZURE_PERMISSION_DENIED".equals(ex.getErrorCode());
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
