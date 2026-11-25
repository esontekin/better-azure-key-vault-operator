package com.akvoperator.common.dto;

import java.time.Instant;

public record OperationStatusResponse(
        String operationId,
        String vaultId,
        String secretName,
        OperationType operationType,
        OperationState state,
        Instant createdAt,
        Instant updatedAt,
        String errorCode,
        String errorMessage
) {
}
