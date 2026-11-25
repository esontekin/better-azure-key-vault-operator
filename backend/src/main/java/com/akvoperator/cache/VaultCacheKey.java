package com.akvoperator.cache;

import java.util.Objects;

/**
 * Composite cache key isolating cached metadata snapshots by Azure tenant, opaque vault ID,
 * and active service principal credential context.
 */
public record VaultCacheKey(
        String tenantId,
        String vaultId,
        String credentialContextId
) {
    public VaultCacheKey {
        tenantId = tenantId == null ? "" : tenantId;
        vaultId = Objects.requireNonNull(vaultId, "vaultId must not be null");
        credentialContextId = credentialContextId == null ? "" : credentialContextId;
    }
}
