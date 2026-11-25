package com.akvoperator.common.exception;

import com.akvoperator.common.correlation.CorrelationIdHolder;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    private static final String PROBLEM_TYPE_PREFIX = "urn:akv-operator:error:";

    @ExceptionHandler(AppException.class)
    public ResponseEntity<ProblemDetail> handleAppException(AppException ex, HttpServletRequest request) {
        String correlationId = CorrelationIdHolder.getOrGenerate();
        if (ex.getStatus().is5xxServerError()) {
            log.error("Application error [code={}, status={}, correlationId={}]: {}",
                    ex.getErrorCode(), ex.getStatus().value(), correlationId, ex.getSafeMessage());
        } else {
            log.warn("Request rejected [code={}, status={}, correlationId={}]: {}",
                    ex.getErrorCode(), ex.getStatus().value(), correlationId, ex.getSafeMessage());
        }

        ProblemDetail problem = buildProblemDetail(
                ex.getStatus(),
                ex.getErrorCode(),
                ex.getSafeMessage(),
                request.getRequestURI(),
                correlationId,
                ex.getRetryAfterSeconds(),
                ex.getFieldErrors()
        );

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        headers.setCacheControl("no-store");
        headers.set(CorrelationIdHolder.HEADER_NAME, correlationId);
        if (ex.getRetryAfterSeconds() != null && ex.getRetryAfterSeconds() > 0) {
            headers.set(HttpHeaders.RETRY_AFTER, String.valueOf(ex.getRetryAfterSeconds()));
        }
        return new ResponseEntity<>(problem, headers, ex.getStatus());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ProblemDetail> handleValidation(MethodArgumentNotValidException ex, HttpServletRequest request) {
        String correlationId = CorrelationIdHolder.getOrGenerate();
        Map<String, String> fieldErrors = new LinkedHashMap<>();
        for (FieldError fieldError : ex.getBindingResult().getFieldErrors()) {
            fieldErrors.putIfAbsent(fieldError.getField(), fieldError.getDefaultMessage());
        }
        ProblemDetail problem = buildProblemDetail(
                HttpStatus.BAD_REQUEST,
                "VALIDATION_ERROR",
                "Request validation failed.",
                request.getRequestURI(),
                correlationId,
                null,
                fieldErrors
        );
        return response(problem, HttpStatus.BAD_REQUEST, correlationId);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ProblemDetail> handleConstraintViolation(ConstraintViolationException ex, HttpServletRequest request) {
        String correlationId = CorrelationIdHolder.getOrGenerate();
        ProblemDetail problem = buildProblemDetail(
                HttpStatus.BAD_REQUEST,
                "VALIDATION_ERROR",
                "Request parameters failed validation.",
                request.getRequestURI(),
                correlationId,
                null,
                Map.of()
        );
        return response(problem, HttpStatus.BAD_REQUEST, correlationId);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ProblemDetail> handleMalformedJson(HttpMessageNotReadableException ex, HttpServletRequest request) {
        String correlationId = CorrelationIdHolder.getOrGenerate();
        ProblemDetail problem = buildProblemDetail(
                HttpStatus.BAD_REQUEST,
                "MALFORMED_REQUEST",
                "Request body is invalid or unreadable JSON.",
                request.getRequestURI(),
                correlationId,
                null,
                Map.of()
        );
        return response(problem, HttpStatus.BAD_REQUEST, correlationId);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ProblemDetail> handleAuthentication(AuthenticationException ex, HttpServletRequest request) {
        String correlationId = CorrelationIdHolder.getOrGenerate();
        ProblemDetail problem = buildProblemDetail(
                HttpStatus.UNAUTHORIZED,
                "AUTH_REQUIRED",
                "Authentication is required to access this resource.",
                request.getRequestURI(),
                correlationId,
                null,
                Map.of()
        );
        return response(problem, HttpStatus.UNAUTHORIZED, correlationId);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ProblemDetail> handleAccessDenied(AccessDeniedException ex, HttpServletRequest request) {
        String correlationId = CorrelationIdHolder.getOrGenerate();
        ProblemDetail problem = buildProblemDetail(
                HttpStatus.FORBIDDEN,
                "ACCESS_DENIED",
                "You do not have permission to perform this action.",
                request.getRequestURI(),
                correlationId,
                null,
                Map.of()
        );
        return response(problem, HttpStatus.FORBIDDEN, correlationId);
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ProblemDetail> handleNotFound(NoResourceFoundException ex, HttpServletRequest request) {
        String correlationId = CorrelationIdHolder.getOrGenerate();
        ProblemDetail problem = buildProblemDetail(
                HttpStatus.NOT_FOUND,
                "ENDPOINT_NOT_FOUND",
                "The requested resource was not found.",
                request.getRequestURI(),
                correlationId,
                null,
                Map.of()
        );
        return response(problem, HttpStatus.NOT_FOUND, correlationId);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ProblemDetail> handleMethodNotSupported(HttpRequestMethodNotSupportedException ex, HttpServletRequest request) {
        String correlationId = CorrelationIdHolder.getOrGenerate();
        ProblemDetail problem = buildProblemDetail(
                HttpStatus.METHOD_NOT_ALLOWED,
                "METHOD_NOT_ALLOWED",
                "HTTP method is not supported for this endpoint.",
                request.getRequestURI(),
                correlationId,
                null,
                Map.of()
        );
        return response(problem, HttpStatus.METHOD_NOT_ALLOWED, correlationId);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleUnexpected(Exception ex, HttpServletRequest request) {
        String correlationId = CorrelationIdHolder.getOrGenerate();
        // Never log raw exception message if it could accidentally contain sensitive data; log class & correlation ID.
        log.error("Unhandled exception [type={}, correlationId={}]", ex.getClass().getName(), correlationId);
        ProblemDetail problem = buildProblemDetail(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "An unexpected internal error occurred. Reference correlationId when checking logs.",
                request.getRequestURI(),
                correlationId,
                null,
                Map.of()
        );
        return response(problem, HttpStatus.INTERNAL_SERVER_ERROR, correlationId);
    }

    private ResponseEntity<ProblemDetail> response(ProblemDetail problem, HttpStatus status, String correlationId) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        headers.setCacheControl("no-store");
        headers.set(CorrelationIdHolder.HEADER_NAME, correlationId);
        return new ResponseEntity<>(problem, headers, status);
    }

    private ProblemDetail buildProblemDetail(
            HttpStatus status,
            String errorCode,
            String detail,
            String instancePath,
            String correlationId,
            Integer retryAfterSeconds,
            Map<String, String> fieldErrors
    ) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setType(URI.create(PROBLEM_TYPE_PREFIX + errorCode.toLowerCase()));
        problem.setTitle(status.getReasonPhrase());
        if (instancePath != null && !instancePath.isBlank()) {
            problem.setInstance(URI.create(instancePath));
        }
        problem.setProperty("errorCode", errorCode);
        problem.setProperty("correlationId", correlationId);
        if (retryAfterSeconds != null) {
            problem.setProperty("retryAfterSeconds", retryAfterSeconds);
        }
        if (fieldErrors != null && !fieldErrors.isEmpty()) {
            problem.setProperty("fieldErrors", fieldErrors);
        }
        return problem;
    }
}
