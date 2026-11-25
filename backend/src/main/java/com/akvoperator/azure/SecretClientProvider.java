package com.akvoperator.azure;

import com.akvoperator.vault.VaultDescriptor;
import com.azure.security.keyvault.secrets.SecretClient;

public interface SecretClientProvider {

    /**
     * Returns a reusable SecretClient configured with bounded read retry policy (respecting Retry-After).
     */
    SecretClient getReadClient(VaultDescriptor vault);

    /**
     * Returns a reusable SecretClient configured without blind retries on ambiguous write/mutation outcomes.
     */
    SecretClient getMutationClient(VaultDescriptor vault);

    /**
     * Returns a non-secret identifier for the active Azure tenant + client credential context (used in cache keys).
     */
    String getCredentialContextId();

    /**
     * Returns the configured Azure tenant ID (used in cache keys).
     */
    String getTenantId();
}
