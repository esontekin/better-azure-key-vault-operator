package com.akvoperator.audit;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class StructuredAuditLoggerTest {

    private Logger auditLogbackLogger;
    private ListAppender<ILoggingEvent> listAppender;
    private StructuredAuditLogger auditLogger;

    @BeforeEach
    void setUp() {
        auditLogbackLogger = (Logger) LoggerFactory.getLogger(StructuredAuditLogger.AUDIT_LOGGER_NAME);
        listAppender = new ListAppender<>();
        listAppender.start();
        auditLogbackLogger.addAppender(listAppender);
        auditLogger = new StructuredAuditLogger();
    }

    @AfterEach
    void tearDown() {
        auditLogbackLogger.detachAppender(listAppender);
        listAppender.stop();
    }

    @Test
    void emitsStructuredAuditFieldsSanitizesNewlinesAndNeverContainsSecretCanary() {
        String canarySecretValue = "CANARY-SUPER-SECRET-VALUE-987654321";

        auditLogger.logSuccess(
                "alice@example.com\r\nFAKE_LOG",
                "vault_abc12345",
                "db-password",
                "v1234",
                "SECRET_REVEAL",
                "corr-12345"
        );

        assertThat(listAppender.list).hasSize(1);
        ILoggingEvent event = listAppender.list.get(0);
        assertThat(event.getMessage()).isEqualTo("audit_event");
        assertThat(event.getArgumentArray()).isNotNull();

        String serializedArgs = Arrays.stream(event.getArgumentArray())
                .map(Object::toString)
                .collect(Collectors.joining(" "));

        assertThat(serializedArgs).contains("subject=alice@example.com  FAKE_LOG");
        assertThat(serializedArgs).doesNotContain("\n").doesNotContain("\r");
        assertThat(serializedArgs).contains("vaultId=vault_abc12345");
        assertThat(serializedArgs).contains("secretName=db-password");
        assertThat(serializedArgs).contains("secretVersion=v1234");
        assertThat(serializedArgs).contains("action=SECRET_REVEAL");
        assertThat(serializedArgs).contains("outcome=SUCCESS");
        assertThat(serializedArgs).contains("correlationId=corr-12345");
        assertThat(serializedArgs).doesNotContain(canarySecretValue);
    }

    @Test
    void recordsDeniedOutcomeWithErrorCode() {
        auditLogger.logDenied(
                "bob",
                "vault_xyz98765",
                "api-key",
                null,
                "SECRET_DELETE",
                "VAULT_PERMISSION_DENIED",
                "corr-999"
        );

        assertThat(listAppender.list).hasSize(1);
        String serializedArgs = Arrays.stream(listAppender.list.get(0).getArgumentArray())
                .map(Object::toString)
                .collect(Collectors.joining(" "));

        assertThat(serializedArgs).contains("outcome=DENIED");
        assertThat(serializedArgs).contains("errorCode=VAULT_PERMISSION_DENIED");
        assertThat(serializedArgs).contains("action=SECRET_DELETE");
    }
}
