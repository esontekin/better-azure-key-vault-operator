package com.akvoperator.azure;

import com.akvoperator.common.exception.AppException;
import com.azure.core.exception.ClientAuthenticationException;
import com.azure.core.exception.HttpResponseException;
import com.azure.core.exception.ResourceModifiedException;
import com.azure.core.exception.ResourceNotFoundException;
import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.HttpResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.concurrent.TimeoutException;

/**
 * Translates Azure SDK and transport exceptions into safe {@link AppException} instances.
 * Never copies raw Azure HTTP response bodies, headers, or stack traces into client-facing messages.
 */
@Component
public class AzureExceptionTranslator {

    private static final int MIN_RETRY_AFTER_SECONDS = 1;
    private static final int MAX_RETRY_AFTER_SECONDS = 300;

    public AppException translate(Throwable throwable, String resourceDescription) {
        if (throwable instanceof AppException appException) {
            return appException;
        }

        String safeResource = (resourceDescription == null || resourceDescription.isBlank())
                ? "Azure resource"
                : resourceDescription;

        ClientAuthenticationException authEx = findCause(throwable, ClientAuthenticationException.class);
        if (authEx != null) {
            if (authEx.getResponse() != null && authEx.getResponse().getStatusCode() == 403) {
                return AppException.azurePermissionDenied(authEx);
            }
            return AppException.azureAuthenticationError(authEx);
        }

        // Check actual HTTP status code before exception subclass because Azure Key Vault SDK
        // throws ResourceModifiedException for HTTP 403 Forbidden as well as 409 Conflict.
        HttpResponseException httpEx = findCause(throwable, HttpResponseException.class);
        if (httpEx != null && httpEx.getResponse() != null && httpEx.getResponse().getStatusCode() > 0) {
            return translateHttpResponseException(httpEx, safeResource);
        }

        ResourceNotFoundException notFoundEx = findCause(throwable, ResourceNotFoundException.class);
        if (notFoundEx != null) {
            return AppException.azureNotFound(safeResource, notFoundEx);
        }

        ResourceModifiedException modifiedEx = findCause(throwable, ResourceModifiedException.class);
        if (modifiedEx != null) {
            return AppException.azureConflict(
                    "Azure Key Vault reported a resource conflict or concurrent modification.",
                    modifiedEx
            );
        }

        if (httpEx != null) {
            return translateHttpResponseException(httpEx, safeResource);
        }

        if (findCause(throwable, TimeoutException.class) != null
                || findCause(throwable, SocketTimeoutException.class) != null) {
            return AppException.azureUpstreamError(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "Connection to Azure timed out. Verify network connectivity or firewall rules.",
                    throwable
            );
        }

        if (findCause(throwable, UnknownHostException.class) != null
                || findCause(throwable, ConnectException.class) != null
                || findCause(throwable, SSLException.class) != null
                || findCause(throwable, IOException.class) != null) {
            return AppException.azureUpstreamError(
                    HttpStatus.BAD_GATEWAY,
                    "Unable to reach the Azure endpoint. Verify network connectivity, private endpoint DNS, and TLS certificates.",
                    throwable
            );
        }

        return AppException.azureUpstreamError(
                HttpStatus.BAD_GATEWAY,
                "An unexpected upstream Azure error occurred.",
                throwable
        );
    }

    private AppException translateHttpResponseException(HttpResponseException httpEx, String safeResource) {
        HttpResponse response = httpEx.getResponse();
        int statusCode = response != null ? response.getStatusCode() : 0;

        return switch (statusCode) {
            case 401 -> AppException.azureAuthenticationError(httpEx);
            case 403 -> AppException.azurePermissionDenied(httpEx);
            case 404 -> AppException.azureNotFound(safeResource, httpEx);
            case 409 -> AppException.azureConflict(
                    "Azure Key Vault reported a resource conflict.",
                    httpEx
            );
            case 429 -> AppException.azureThrottled(parseRetryAfterSeconds(response), httpEx);
            case 400 -> AppException.badRequest(
                    "AZURE_BAD_REQUEST",
                    "Azure Key Vault rejected the request parameters."
            );
            case 503 -> AppException.azureUpstreamError(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "Azure Key Vault service is temporarily unavailable.",
                    httpEx
            );
            case 504 -> AppException.azureUpstreamError(
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "Azure Key Vault upstream request timed out.",
                    httpEx
            );
            default -> {
                if (statusCode >= 500 && statusCode < 600) {
                    yield AppException.azureUpstreamError(
                            HttpStatus.BAD_GATEWAY,
                            "Azure Key Vault returned an upstream service error.",
                            httpEx
                    );
                }
                yield AppException.azureUpstreamError(
                        HttpStatus.BAD_GATEWAY,
                        "Unexpected upstream response received from Azure.",
                        httpEx
                );
            }
        };
    }

    static Integer parseRetryAfterSeconds(HttpResponse response) {
        if (response == null) {
            return null;
        }
        String raw = response.getHeaderValue(HttpHeaderName.RETRY_AFTER);
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String trimmed = raw.trim();
        try {
            long seconds = Long.parseLong(trimmed);
            return clampRetryAfter(seconds);
        } catch (NumberFormatException ignored) {
            // Try RFC 1123 HTTP-date format
        }
        try {
            ZonedDateTime retryAt = ZonedDateTime.parse(trimmed, DateTimeFormatter.RFC_1123_DATE_TIME);
            long seconds = Duration.between(ZonedDateTime.now(retryAt.getZone()), retryAt).getSeconds();
            return clampRetryAfter(seconds);
        } catch (DateTimeParseException ignored) {
            return null;
        }
    }

    private static int clampRetryAfter(long seconds) {
        if (seconds < MIN_RETRY_AFTER_SECONDS) {
            return MIN_RETRY_AFTER_SECONDS;
        }
        if (seconds > MAX_RETRY_AFTER_SECONDS) {
            return MAX_RETRY_AFTER_SECONDS;
        }
        return (int) seconds;
    }

    private static <T extends Throwable> T findCause(Throwable root, Class<T> targetType) {
        Throwable current = root;
        int depth = 0;
        while (current != null && depth < 16) {
            if (targetType.isInstance(current)) {
                return targetType.cast(current);
            }
            current = current.getCause();
            depth++;
        }
        return null;
    }
}
