package com.akvoperator.vault;

import com.akvoperator.common.dto.VaultSource;

public record VaultDescriptor(
        String opaqueId,
        String resourceId,
        String name,
        String subscriptionId,
        String resourceGroup,
        String location,
        String vaultUri,
        String environment,
        boolean production,
        VaultSource source
) {
}
