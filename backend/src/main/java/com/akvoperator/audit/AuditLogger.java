package com.akvoperator.audit;

public interface AuditLogger {

    void log(AuditEvent event);

    default void logSuccess(String subject, String vaultId, String secretName, String secretVersion, String action, String correlationId) {
        log(AuditEvent.of(subject, vaultId, secretName, secretVersion, action, "SUCCESS", null, correlationId));
    }

    default void logDenied(String subject, String vaultId, String secretName, String secretVersion, String action, String errorCode, String correlationId) {
        log(AuditEvent.of(subject, vaultId, secretName, secretVersion, action, "DENIED", errorCode, correlationId));
    }

    default void logFailure(String subject, String vaultId, String secretName, String secretVersion, String action, String errorCode, String correlationId) {
        log(AuditEvent.of(subject, vaultId, secretName, secretVersion, action, "FAILURE", errorCode, correlationId));
    }
}
