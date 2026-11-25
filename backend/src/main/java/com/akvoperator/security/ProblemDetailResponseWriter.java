package com.akvoperator.security;

import com.akvoperator.common.correlation.CorrelationIdHolder;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Writes RFC 9457 Problem Details JSON responses directly from security filters and handlers.
 */
@Component
public class ProblemDetailResponseWriter {

    private static final String PROBLEM_TYPE_PREFIX = "urn:akv-operator:error:";

    private final ObjectMapper objectMapper;

    public ProblemDetailResponseWriter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public void write(
            HttpServletRequest request,
            HttpServletResponse response,
            HttpStatus status,
            String errorCode,
            String detail
    ) throws IOException {
        write(request, response, status, errorCode, detail, null);
    }

    public void write(
            HttpServletRequest request,
            HttpServletResponse response,
            HttpStatus status,
            String errorCode,
            String detail,
            Integer retryAfterSeconds
    ) throws IOException {
        if (response.isCommitted()) {
            return;
        }
        String correlationId = CorrelationIdHolder.getOrGenerate();
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setType(URI.create(PROBLEM_TYPE_PREFIX + errorCode.toLowerCase(Locale.ROOT)));
        problem.setTitle(status.getReasonPhrase());
        if (request != null && request.getRequestURI() != null && !request.getRequestURI().isBlank()) {
            try {
                problem.setInstance(URI.create(request.getRequestURI()));
            } catch (IllegalArgumentException ignored) {
                // Ignore malformed request URI in problem instance
            }
        }
        problem.setProperty("errorCode", errorCode);
        problem.setProperty("correlationId", correlationId);
        if (retryAfterSeconds != null && retryAfterSeconds > 0) {
            problem.setProperty("retryAfterSeconds", retryAfterSeconds);
        }

        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store, no-cache, max-age=0, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Expires", "0");
        response.setHeader(CorrelationIdHolder.HEADER_NAME, correlationId);
        if (retryAfterSeconds != null && retryAfterSeconds > 0) {
            response.setHeader(HttpHeaders.RETRY_AFTER, String.valueOf(retryAfterSeconds));
        }

        byte[] body = objectMapper.writeValueAsBytes(problem);
        response.getOutputStream().write(body);
        response.getOutputStream().flush();
    }
}
