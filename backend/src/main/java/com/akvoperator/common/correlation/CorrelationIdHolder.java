package com.akvoperator.common.correlation;

import org.slf4j.MDC;

import java.util.UUID;

public final class CorrelationIdHolder {

    public static final String MDC_KEY = "correlationId";
    public static final String HEADER_NAME = "X-Correlation-Id";

    private CorrelationIdHolder() {
    }

    public static String getOrGenerate() {
        String existing = MDC.get(MDC_KEY);
        if (existing != null && !existing.isBlank()) {
            return existing;
        }
        String generated = UUID.randomUUID().toString();
        MDC.put(MDC_KEY, generated);
        return generated;
    }

    public static void set(String correlationId) {
        if (correlationId != null && !correlationId.isBlank()) {
            MDC.put(MDC_KEY, correlationId);
        }
    }

    public static void clear() {
        MDC.remove(MDC_KEY);
    }
}
