package com.akvoperator.azure;

import com.azure.core.credential.TokenCredential;

/**
 * Extensible factory for Azure Service Principal credentials.
 * MVP uses {@link ClientSecretCredentialFactory}; future implementations may add
 * Workload Identity or Managed Identity without introducing automatic fallback chains.
 */
public interface AzureCredentialFactory {

    /**
     * Returns the reusable {@link TokenCredential} instance (Azure SDK manages token caching and refresh).
     */
    TokenCredential getCredential();

    /**
     * Returns the configured Azure Entra tenant ID.
     */
    String getTenantId();

    /**
     * Returns the configured Azure Entra application (client) ID.
     */
    String getClientId();

    /**
     * Returns a non-secret deterministic fingerprint of tenant + client context for cache keying.
     */
    String getCredentialContextId();
}
