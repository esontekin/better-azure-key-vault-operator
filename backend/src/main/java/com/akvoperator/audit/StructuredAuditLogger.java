package com.akvoperator.audit;

import com.akvoperator.common.correlation.CorrelationIdHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.regex.Pattern;

import static net.logstash.logback.argument.StructuredArguments.kv;

/**
 * Elasticsearch-compatible structured JSON audit logger.
 * Never logs secret values, tokens, tags, or contentType.
 */
@Component
public class StructuredAuditLogger implements AuditLogger {

    public static final String AUDIT_LOGGER_NAME = "AUDIT";

    private static final Logger AUDIT_LOG = LoggerFactory.getLogger(AUDIT_LOGGER_NAME);
    private static final Pattern CONTROL_CHARS = Pattern.compile("[\\p{Cntrl}]");
    private static final int MAX_FIELD_LENGTH = 256;

    @Override
    public void log(AuditEvent event) {
        if (event == null) {
            return;
        }
        String timestamp = (event.timestamp() != null ? event.timestamp() : Instant.now()).toString();
        String subject = sanitize(event.subject() != null && !event.subject().isBlank() ? event.subject() : "anonymous");
        String vaultId = sanitize(event.vaultId());
        String secretName = sanitize(event.secretName());
        String secretVersion = sanitize(event.secretVersion());
        String action = sanitize(event.action());
        String outcome = sanitize(event.outcome());
        String errorCode = sanitize(event.errorCode());
        String correlationId = sanitize(
                event.correlationId() != null && !event.correlationId().isBlank()
                        ? event.correlationId()
                        : CorrelationIdHolder.getOrGenerate()
        );

        AUDIT_LOG.info(
                "audit_event",
                kv("timestamp", timestamp),
                kv("subject", subject),
                kv("vaultId", vaultId),
                kv("secretName", secretName),
                kv("secretVersion", secretVersion),
                kv("action", action),
                kv("outcome", outcome),
                kv("errorCode", errorCode),
                kv("correlationId", correlationId)
        );
    }

    static String sanitize(String value) {
        if (value == null) {
            return null;
        }
        String cleaned = CONTROL_CHARS.matcher(value).replaceAll(" ").trim();
        if (cleaned.length() > MAX_FIELD_LENGTH) {
            return cleaned.substring(0, MAX_FIELD_LENGTH);
        }
        return cleaned;
    }
}
