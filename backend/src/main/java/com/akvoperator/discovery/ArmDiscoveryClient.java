package com.akvoperator.discovery;

/**
 * Discovers Azure subscriptions and Key Vault resources via Azure Resource Manager (ARM).
 */
public interface ArmDiscoveryClient {

    /**
     * Executes ARM discovery for all accessible subscriptions (constrained by AZURE_SUBSCRIPTION_ID if set).
     */
    ArmDiscoveryResult discover();
}
