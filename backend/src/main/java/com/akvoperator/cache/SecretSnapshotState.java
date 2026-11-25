package com.akvoperator.cache;

import com.akvoperator.common.dto.SecretMetadataDto;
import com.akvoperator.common.dto.SyncStatus;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Immutable metadata-only snapshot state for a single Key Vault.
 * Never holds secret values; retains lastSuccessfulItems so failed refreshes can serve stale data explicitly labeled.
 */
public record SecretSnapshotState(
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
        List<SecretMetadataDto> items,
        List<SecretMetadataDto> lastSuccessfulItems
) {
    public SecretSnapshotState {
        vaultId = Objects.requireNonNull(vaultId, "vaultId must not be null");
        status = Objects.requireNonNull(status, "status must not be null");
        items = items == null ? List.of() : List.copyOf(items);
        lastSuccessfulItems = lastSuccessfulItems == null ? List.of() : List.copyOf(lastSuccessfulItems);
    }

    public static SecretSnapshotState idle(String vaultId, long generationId) {
        return new SecretSnapshotState(
                vaultId,
                SyncStatus.IDLE,
                generationId,
                0,
                0,
                false,
                null,
                null,
                null,
                null,
                List.of(),
                List.of()
        );
    }

    @Override
    public String toString() {
        return "SecretSnapshotState[vaultId=" + vaultId
                + ", status=" + status
                + ", generationId=" + generationId
                + ", loadedCount=" + loadedCount
                + ", pagesLoaded=" + pagesLoaded
                + ", stale=" + stale
                + ", errorCode=" + errorCode + "]";
    }
}
