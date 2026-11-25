package com.akvoperator.audit;

import java.time.Instant;

public record AuditEvent(
        Instant timestamp,
        String subject,
        String vaultId,
        String secretName,
        String secretVersion,
        String action,
        String outcome,
        String errorCode,
        String correlationId
) {
    public static AuditEvent of(
            String subject,
            String vaultId,
            String secretName,
            String secretVersion,
            String action,
            String outcome,
            String errorCode,
            String correlationId
    ) {
        return new AuditEvent(
                Instant.now(),
                subject != null ? subject : "anonymous",
                vaultId,
                secretName,
                secretVersion,
                action,
                outcome,
                errorCode,
                correlationId
        );
    }
}
