package com.akvoperator.discovery;

import com.akvoperator.common.dto.SubscriptionDto;

import java.util.List;

/**
 * Result of an Azure Resource Manager (ARM) subscription and Key Vault discovery pass.
 */
public record ArmDiscoveryResult(
        List<SubscriptionDto> subscriptions,
        List<DiscoveredVault> vaults
) {
    public ArmDiscoveryResult {
        subscriptions = subscriptions == null ? List.of() : List.copyOf(subscriptions);
        vaults = vaults == null ? List.of() : List.copyOf(vaults);
    }

    public static ArmDiscoveryResult empty() {
        return new ArmDiscoveryResult(List.of(), List.of());
    }
}
