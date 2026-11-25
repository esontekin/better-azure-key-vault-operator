package com.akvoperator.security;

import com.akvoperator.common.correlation.CorrelationIdHolder;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Establishes and propagates a sanitized correlation ID via MDC and X-Correlation-Id header.
 */
public class CorrelationIdFilter extends OncePerRequestFilter {

    private static final Pattern SAFE_CORRELATION_ID = Pattern.compile("^[a-zA-Z0-9._-]{1,64}$");

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String incoming = request.getHeader(CorrelationIdHolder.HEADER_NAME);
        String correlationId = isValidCorrelationId(incoming)
                ? incoming.trim()
                : UUID.randomUUID().toString();

        CorrelationIdHolder.set(correlationId);
        response.setHeader(CorrelationIdHolder.HEADER_NAME, correlationId);
        try {
            filterChain.doFilter(request, response);
        } finally {
            CorrelationIdHolder.clear();
        }
    }

    private static boolean isValidCorrelationId(String candidate) {
        if (candidate == null) {
            return false;
        }
        String trimmed = candidate.trim();
        return !trimmed.isEmpty() && SAFE_CORRELATION_ID.matcher(trimmed).matches();
    }
}
