package com.akvoperator.common.exception;

import org.springframework.http.HttpStatus;

import java.util.Map;

public class AppException extends RuntimeException {

    private final HttpStatus status;
    private final String errorCode;
    private final String safeMessage;
    private final Integer retryAfterSeconds;
    private final Map<String, String> fieldErrors;

    public AppException(HttpStatus status, String errorCode, String safeMessage) {
        this(status, errorCode, safeMessage, null, Map.of(), null);
    }

    public AppException(HttpStatus status, String errorCode, String safeMessage, Throwable cause) {
        this(status, errorCode, safeMessage, null, Map.of(), cause);
    }

    public AppException(
            HttpStatus status,
            String errorCode,
            String safeMessage,
            Integer retryAfterSeconds,
            Map<String, String> fieldErrors,
            Throwable cause
    ) {
        super(safeMessage, cause);
        this.status = status;
        this.errorCode = errorCode;
        this.safeMessage = safeMessage;
        this.retryAfterSeconds = retryAfterSeconds;
        this.fieldErrors = fieldErrors == null ? Map.of() : Map.copyOf(fieldErrors);
    }

    public HttpStatus getStatus() {
        return status;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public String getSafeMessage() {
        return safeMessage;
    }

    public Integer getRetryAfterSeconds() {
        return retryAfterSeconds;
    }

    public Map<String, String> getFieldErrors() {
        return fieldErrors;
    }

    public static AppException invalidConfiguration(String message) {
        return new AppException(HttpStatus.INTERNAL_SERVER_ERROR, "INVALID_CONFIGURATION", message);
    }

    public static AppException badRequest(String errorCode, String message) {
        return new AppException(HttpStatus.BAD_REQUEST, errorCode, message);
    }

    public static AppException badRequest(String errorCode, String message, Map<String, String> fieldErrors) {
        return new AppException(HttpStatus.BAD_REQUEST, errorCode, message, null, fieldErrors, null);
    }

    public static AppException authRequired(String message) {
        return new AppException(HttpStatus.UNAUTHORIZED, "AUTH_REQUIRED", message);
    }

    public static AppException bootstrapInvalid(String message) {
        return new AppException(HttpStatus.UNAUTHORIZED, "BOOTSTRAP_TOKEN_INVALID", message);
    }

    public static AppException forbidden(String errorCode, String message) {
        return new AppException(HttpStatus.FORBIDDEN, errorCode, message);
    }

    public static AppException featureDisabled(String message) {
        return new AppException(HttpStatus.FORBIDDEN, "FEATURE_DISABLED", message);
    }

    public static AppException notFound(String errorCode, String message) {
        return new AppException(HttpStatus.NOT_FOUND, errorCode, message);
    }

    public static AppException conflict(String errorCode, String message) {
        return new AppException(HttpStatus.CONFLICT, errorCode, message);
    }

    public static AppException azureAuthenticationError(Throwable cause) {
        return new AppException(
                HttpStatus.UNAUTHORIZED,
                "AZURE_CREDENTIAL_INVALID",
                "Azure Service Principal authentication failed. Check tenant ID, client ID, client secret value, or secret expiration.",
                cause
        );
    }

    public static AppException azurePermissionDenied(Throwable cause) {
        return new AppException(
                HttpStatus.FORBIDDEN,
                "AZURE_PERMISSION_DENIED",
                "Azure Service Principal does not have permission for this Key Vault operation or is blocked by firewall/network rules.",
                cause
        );
    }

    public static AppException azureNotFound(String resourceDescription, Throwable cause) {
        return new AppException(
                HttpStatus.NOT_FOUND,
                "AZURE_RESOURCE_NOT_FOUND",
                resourceDescription + " was not found in Azure Key Vault.",
                cause
        );
    }

    public static AppException azureConflict(String message, Throwable cause) {
        return new AppException(HttpStatus.CONFLICT, "AZURE_CONFLICT", message, cause);
    }

    public static AppException azureThrottled(Integer retryAfterSeconds, Throwable cause) {
        return new AppException(
                HttpStatus.TOO_MANY_REQUESTS,
                "AZURE_THROTTLED",
                "Azure Key Vault throttled the request. Retry after the indicated delay.",
                retryAfterSeconds,
                Map.of(),
                cause
        );
    }

    public static AppException azureUpstreamError(HttpStatus status, String message, Throwable cause) {
        return new AppException(status, "AZURE_UPSTREAM_ERROR", message, cause);
    }
}
