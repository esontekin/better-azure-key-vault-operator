package com.akvoperator.azure;

import com.akvoperator.common.exception.AppException;
import com.azure.core.http.HttpClient;
import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpMethod;
import com.azure.core.http.HttpPipeline;
import com.azure.core.http.HttpPipelineBuilder;
import com.azure.core.http.HttpRequest;
import com.azure.core.http.HttpResponse;
import com.azure.core.util.Context;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class NoCrossHostRedirectPolicyTest {

    @ParameterizedTest
    @ValueSource(ints = {301, 302, 303, 307, 308})
    void blocksRedirectResponsesInBothSyncAndAsyncPipelines(int redirectStatus) {
        AtomicInteger callCount = new AtomicInteger();
        HttpClient fakeClient = new HttpClient() {
            @Override
            public Mono<HttpResponse> send(HttpRequest request) {
                callCount.incrementAndGet();
                HttpHeaders headers = new HttpHeaders()
                        .set(HttpHeaderName.LOCATION, "https://attacker.example.com/steal-token");
                return Mono.just(stubResponse(request, redirectStatus, headers));
            }

            @Override
            public HttpResponse sendSync(HttpRequest request, Context context) {
                callCount.incrementAndGet();
                HttpHeaders headers = new HttpHeaders()
                        .set(HttpHeaderName.LOCATION, "https://attacker.example.com/steal-token");
                return stubResponse(request, redirectStatus, headers);
            }
        };

        HttpPipeline pipeline = new HttpPipelineBuilder()
                .httpClient(fakeClient)
                .policies(new NoCrossHostRedirectPolicy())
                .build();

        HttpRequest syncRequest = new HttpRequest(HttpMethod.GET, "https://my-vault.vault.azure.net/secrets")
                .setHeader(HttpHeaderName.AUTHORIZATION, "Bearer secret-token");
        assertThatThrownBy(() -> pipeline.sendSync(syncRequest, Context.NONE))
                .isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getStatus()).isEqualTo(HttpStatus.BAD_GATEWAY);
                    assertThat(appEx.getErrorCode()).isEqualTo("AZURE_UPSTREAM_ERROR");
                });

        HttpRequest asyncRequest = new HttpRequest(HttpMethod.GET, "https://my-vault.vault.azure.net/secrets")
                .setHeader(HttpHeaderName.AUTHORIZATION, "Bearer secret-token");
        assertThatThrownBy(() -> pipeline.send(asyncRequest).block())
                .isInstanceOf(AppException.class)
                .satisfies(ex -> assertThat(((AppException) ex).getStatus()).isEqualTo(HttpStatus.BAD_GATEWAY));

        // Verify neither sync nor async followed the redirect to a second request
        assertThat(callCount.get()).isEqualTo(2);
    }

    @Test
    void allowsNormalResponsesToPassThrough() {
        HttpClient fakeClient = new HttpClient() {
            @Override
            public Mono<HttpResponse> send(HttpRequest request) {
                return Mono.just(stubResponse(request, 200, new HttpHeaders()));
            }

            @Override
            public HttpResponse sendSync(HttpRequest request, Context context) {
                return stubResponse(request, 200, new HttpHeaders());
            }
        };

        HttpPipeline pipeline = new HttpPipelineBuilder()
                .httpClient(fakeClient)
                .policies(new NoCrossHostRedirectPolicy())
                .build();

        HttpResponse syncResp = pipeline.sendSync(
                new HttpRequest(HttpMethod.GET, "https://my-vault.vault.azure.net/secrets"), Context.NONE);
        assertThat(syncResp.getStatusCode()).isEqualTo(200);

        HttpResponse asyncResp = pipeline.send(
                new HttpRequest(HttpMethod.GET, "https://my-vault.vault.azure.net/secrets")).block();
        assertThat(asyncResp).isNotNull();
        assertThat(asyncResp.getStatusCode()).isEqualTo(200);
    }

    private static HttpResponse stubResponse(HttpRequest request, int statusCode, HttpHeaders headers) {
        return new HttpResponse(request) {
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
                return Flux.empty();
            }

            @Override
            public Mono<byte[]> getBodyAsByteArray() {
                return Mono.just(new byte[0]);
            }

            @Override
            public Mono<String> getBodyAsString() {
                return Mono.just("");
            }

            @Override
            public Mono<String> getBodyAsString(Charset charset) {
                return Mono.just("");
            }
        };
    }
}
