package com.akvoperator.common.dto;

import java.time.Instant;
import java.util.List;

public record SecretListSnapshotResponse(
        String vaultId,
        SyncStatus status,
        long generationId,
        int loadedCount,
        int pagesLoaded,
        boolean stale,
        Instant lastSuccessfulSyncAt,
        Instant lastAttemptAt,
        String errorCode,
        String errorMessage,
        List<SecretMetadataDto> items
) {
    public SecretListSnapshotResponse {
        items = items == null ? List.of() : List.copyOf(items);
    }
}
