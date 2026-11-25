package com.akvoperator.azure;

import com.akvoperator.common.exception.AppException;
import com.azure.core.exception.ClientAuthenticationException;
import com.azure.core.exception.HttpResponseException;
import com.azure.core.exception.ResourceModifiedException;
import com.azure.core.exception.ResourceNotFoundException;
import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpMethod;
import com.azure.core.http.HttpRequest;
import com.azure.core.http.HttpResponse;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class AzureExceptionTranslatorTest {

    private static final String CANARY_BODY = "RAW_AZURE_CANARY_INTERNAL_TOKEN_XYZ_999";

    private final AzureExceptionTranslator translator = new AzureExceptionTranslator();

    @Test
    void mapsClientAuthenticationExceptionTo401WithoutLeakingRawBody() {
        HttpResponse response = stubResponse(401, new HttpHeaders(), CANARY_BODY);
        ClientAuthenticationException ex = new ClientAuthenticationException("AADSTS7000215 " + CANARY_BODY, response);

        AppException translated = translator.translate(ex, "Secret");

        assertThat(translated.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(translated.getErrorCode()).isEqualTo("AZURE_CREDENTIAL_INVALID");
        assertThat(translated.getSafeMessage()).doesNotContain(CANARY_BODY);
    }

    @Test
    void maps403ToAzurePermissionDeniedWithoutLeakingRawBody() {
        HttpResponse response = stubResponse(403, new HttpHeaders(), CANARY_BODY);
        HttpResponseException ex = new HttpResponseException("Forbidden: " + CANARY_BODY, response);

        AppException translated = translator.translate(ex, "Secret");

        assertThat(translated.getStatus()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(translated.getErrorCode()).isEqualTo("AZURE_PERMISSION_DENIED");
        assertThat(translated.getSafeMessage()).doesNotContain(CANARY_BODY);
    }

    @Test
    void maps404AndResourceNotFoundExceptionWithoutLeakingRawBody() {
        HttpResponse response = stubResponse(404, new HttpHeaders(), CANARY_BODY);
        ResourceNotFoundException ex = new ResourceNotFoundException("Not found: " + CANARY_BODY, response);

        AppException translated = translator.translate(ex, "Secret");

        assertThat(translated.getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(translated.getErrorCode()).isEqualTo("AZURE_RESOURCE_NOT_FOUND");
        assertThat(translated.getSafeMessage()).contains("Secret").doesNotContain(CANARY_BODY);
    }

    @Test
    void maps409AndResourceModifiedExceptionToConflictWithoutLeakingRawBody() {
        HttpResponse response = stubResponse(409, new HttpHeaders(), CANARY_BODY);
        ResourceModifiedException ex = new ResourceModifiedException("Conflict: " + CANARY_BODY, response);

        AppException translated = translator.translate(ex, "Secret");

        assertThat(translated.getStatus()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(translated.getErrorCode()).isEqualTo("AZURE_CONFLICT");
        assertThat(translated.getSafeMessage()).doesNotContain(CANARY_BODY);
    }

    @Test
    void maps429WithBoundedRetryAfterHeader() {
        HttpHeaders headers = new HttpHeaders().set(HttpHeaderName.RETRY_AFTER, "42");
        HttpResponse response = stubResponse(429, headers, CANARY_BODY);
        HttpResponseException ex = new HttpResponseException("Throttled: " + CANARY_BODY, response);

        AppException translated = translator.translate(ex, "Secret");

        assertThat(translated.getStatus()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(translated.getErrorCode()).isEqualTo("AZURE_THROTTLED");
        assertThat(translated.getRetryAfterSeconds()).isEqualTo(42);
        assertThat(translated.getSafeMessage()).doesNotContain(CANARY_BODY);

        // Verify upper bound clamp (300s)
        HttpHeaders hugeHeaders = new HttpHeaders().set(HttpHeaderName.RETRY_AFTER, "99999");
        AppException clamped = translator.translate(
                new HttpResponseException("Throttled", stubResponse(429, hugeHeaders, CANARY_BODY)),
                "Secret"
        );
        assertThat(clamped.getRetryAfterSeconds()).isEqualTo(300);
    }

    @Test
    void maps5xxAndNetworkErrorsTo502Or503WithoutLeakingRawMessage() {
        HttpResponse resp500 = stubResponse(500, new HttpHeaders(), CANARY_BODY);
        AppException translated500 = translator.translate(
                new HttpResponseException("Internal error: " + CANARY_BODY, resp500), "Secret");
        assertThat(translated500.getStatus()).isEqualTo(HttpStatus.BAD_GATEWAY);
        assertThat(translated500.getErrorCode()).isEqualTo("AZURE_UPSTREAM_ERROR");
        assertThat(translated500.getSafeMessage()).doesNotContain(CANARY_BODY);

        HttpResponse resp503 = stubResponse(503, new HttpHeaders(), CANARY_BODY);
        AppException translated503 = translator.translate(
                new HttpResponseException("Unavailable: " + CANARY_BODY, resp503), "Secret");
        assertThat(translated503.getStatus()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(translated503.getSafeMessage()).doesNotContain(CANARY_BODY);

        AppException timeout = translator.translate(
                new RuntimeException(new SocketTimeoutException(CANARY_BODY)), "Secret");
        assertThat(timeout.getStatus()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(timeout.getSafeMessage()).doesNotContain(CANARY_BODY);

        AppException dnsError = translator.translate(
                new RuntimeException(new UnknownHostException(CANARY_BODY)), "Secret");
        assertThat(dnsError.getStatus()).isEqualTo(HttpStatus.BAD_GATEWAY);
        assertThat(dnsError.getSafeMessage()).doesNotContain(CANARY_BODY);
    }

    private static HttpResponse stubResponse(int statusCode, HttpHeaders headers, String body) {
        HttpRequest req = new HttpRequest(HttpMethod.GET, "https://test-vault.vault.azure.net/secrets");
        return new HttpResponse(req) {
            @Override
            public int getStatusCode() {
                return statusCode;
            }

            @Override
            public String getHeaderValue(String name) {
                return headers.getValue(name);
            }

            @Override
            public HttpHeaders getHeaders() {
                return headers;
            }

            @Override
            public Flux<ByteBuffer> getBody() {
                return Flux.just(ByteBuffer.wrap(body.getBytes(StandardCharsets.UTF_8)));
            }

            @Override
            public Mono<byte[]> getBodyAsByteArray() {
                return Mono.just(body.getBytes(StandardCharsets.UTF_8));
            }

            @Override
            public Mono<String> getBodyAsString() {
                return Mono.just(body);
            }

            @Override
            public Mono<String> getBodyAsString(Charset charset) {
                return Mono.just(body);
            }
        };
    }
}
