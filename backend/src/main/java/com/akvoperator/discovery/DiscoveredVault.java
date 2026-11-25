package com.akvoperator.discovery;

import java.util.Map;

/**
 * Raw Key Vault discovery record returned by {@link ArmDiscoveryClient} before URL validation,
 * allowlist filtering, and opaque ID generation.
 */
public record DiscoveredVault(
        String resourceId,
        String name,
        String subscriptionId,
        String resourceGroup,
        String location,
        String vaultUri,
        Map<String, String> tags
) {
    public DiscoveredVault {
        tags = tags == null ? Map.of() : Map.copyOf(tags);
    }
}
