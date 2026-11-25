package com.akvoperator.azure;

import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.exception.AppException;
import com.akvoperator.vault.VaultDescriptor;
import com.azure.core.http.policy.ExponentialBackoffOptions;
import com.azure.core.http.policy.FixedDelayOptions;
import com.azure.core.http.policy.RetryOptions;
import com.azure.core.http.policy.RetryPolicy;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Provides cached, reusable {@link SecretClient} instances per vault opaque ID.
 * Separates read clients (bounded exponential backoff respecting Retry-After) from mutation clients
 * (zero automatic retries to avoid creating duplicate secret versions on ambiguous write outcomes).
 */
@Component
public class AzureSecretClientProvider implements SecretClientProvider {

    private final AzureCredentialFactory credentialFactory;
    private final AzureVaultUrlValidator vaultUrlValidator;
    private final AzureHttpClientFactory httpClientFactory;
    private final AppProperties appProperties;

    private final ConcurrentHashMap<String, SecretClient> readClients = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, SecretClient> mutationClients = new ConcurrentHashMap<>();

    public AzureSecretClientProvider(
            AzureCredentialFactory credentialFactory,
            AzureVaultUrlValidator vaultUrlValidator,
            AzureHttpClientFactory httpClientFactory,
            AppProperties appProperties
    ) {
        this.credentialFactory = credentialFactory;
        this.vaultUrlValidator = vaultUrlValidator;
        this.httpClientFactory = httpClientFactory;
        this.appProperties = appProperties;
    }

    @Override
    public SecretClient getReadClient(VaultDescriptor vault) {
        String normalizedUri = validateVault(vault);
        return readClients.computeIfAbsent(vault.opaqueId(), id -> buildClient(normalizedUri, true));
    }

    @Override
    public SecretClient getMutationClient(VaultDescriptor vault) {
        String normalizedUri = validateVault(vault);
        return mutationClients.computeIfAbsent(vault.opaqueId(), id -> buildClient(normalizedUri, false));
    }

    @Override
    public String getCredentialContextId() {
        return credentialFactory.getCredentialContextId();
    }

    @Override
    public String getTenantId() {
        return credentialFactory.getTenantId();
    }

    private String validateVault(VaultDescriptor vault) {
        if (vault == null || vault.opaqueId() == null || vault.opaqueId().isBlank()) {
            throw AppException.badRequest("INVALID_VAULT", "Vault descriptor is missing or invalid.");
        }
        return vaultUrlValidator.validateAndNormalize(vault.vaultUri());
    }

    private SecretClient buildClient(String normalizedVaultUri, boolean allowRetries) {
        int maxReadRetries = appProperties != null && appProperties.getAzure() != null
                ? Math.max(0, appProperties.getAzure().getMaxReadRetries())
                : 3;

        RetryOptions retryOptions = allowRetries
                ? new RetryOptions(new ExponentialBackoffOptions()
                        .setMaxRetries(maxReadRetries)
                        .setBaseDelay(Duration.ofMillis(800))
                        .setMaxDelay(Duration.ofSeconds(16)))
                : new RetryOptions(new FixedDelayOptions(0, Duration.ZERO));

        return new SecretClientBuilder()
                .vaultUrl(normalizedVaultUri)
                .credential(credentialFactory.getCredential())
                .httpClient(httpClientFactory.getHttpClient())
                .httpLogOptions(httpClientFactory.createNoLoggingOptions())
                .addPolicy(httpClientFactory.getNoCrossHostRedirectPolicy())
                .retryPolicy(new RetryPolicy(retryOptions))
                .buildClient();
    }
}
