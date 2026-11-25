package com.akvoperator.common.dto;

import java.util.Set;

public record VaultDto(
        String id,
        String name,
        String subscriptionId,
        String resourceGroup,
        String location,
        String vaultUri,
        String environment,
        boolean production,
        VaultSource source,
        Set<Permission> permissions
) {
}
