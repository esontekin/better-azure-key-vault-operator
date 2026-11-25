package com.akvoperator.integration;

import com.akvoperator.azure.AzureExceptionTranslator;
import com.akvoperator.azure.AzureHttpClientFactory;
import com.akvoperator.azure.NoCrossHostRedirectPolicy;
import com.akvoperator.azure.SecretClientProvider;
import com.akvoperator.cache.SecretMetadataCache;
import com.akvoperator.cache.SecretSnapshotState;
import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.dto.SecretListSnapshotResponse;
import com.akvoperator.common.dto.SyncStatus;
import com.akvoperator.common.dto.VaultSource;
import com.akvoperator.common.exception.AppException;
import com.akvoperator.secret.SecretPaginationService;
import com.akvoperator.vault.VaultDescriptor;
import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.http.HttpClient;
import com.azure.core.http.HttpRequest;
import com.azure.core.http.HttpResponse;
import com.azure.core.http.policy.FixedDelayOptions;
import com.azure.core.http.policy.HttpLogDetailLevel;
import com.azure.core.http.policy.HttpLogOptions;
import com.azure.core.http.policy.RetryOptions;
import com.azure.core.http.policy.RetryPolicy;
import com.azure.core.util.Context;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.time.Duration;
import java.time.OffsetDateTime;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Verifies real Azure Key Vault SDK HTTP wire protocol (multi-page nextLink, 401/403/429/503 error mapping,
 * and cross-host redirect blocking) against an in-process WireMock HTTP server.
 */
class AzureWireMockProtocolIntegrationTest {

    private static WireMockServer wireMock;
    private static String httpsWireMockUrl;
    private static VaultDescriptor vault;

    private AppProperties appProperties;
    private AzureExceptionTranslator translator;
    private SecretMetadataCache cache;
    private SecretClient secretClient;
    private SecretPaginationService paginationService;

    @BeforeAll
    static void startWireMock() {
        wireMock = new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
        wireMock.start();
        httpsWireMockUrl = "https://localhost:" + wireMock.port();
        vault = new VaultDescriptor(
                "vlt_wiremock_0001",
                "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-wiremock",
                "kv-wiremock",
                "sub-1",
                "rg",
                "westeurope",
                httpsWireMockUrl,
                "test",
                false,
                VaultSource.STATIC_CONFIG
        );
    }

    @AfterAll
    static void stopWireMock() {
        if (wireMock != null) {
            wireMock.stop();
        }
    }

    @BeforeEach
    void setUp() {
        wireMock.resetAll();
        appProperties = new AppProperties();
        translator = new AzureExceptionTranslator();
        AzureHttpClientFactory httpClientFactory = new AzureHttpClientFactory(appProperties);
        TokenCredential mockCredential = request -> Mono.just(
                new AccessToken("wiremock-synthetic-token", OffsetDateTime.now().plusHours(1)));

        HttpClient delegate = httpClientFactory.getHttpClient();
        HttpClient loopbackTestClient = new HttpClient() {
            @Override
            public Mono<HttpResponse> send(HttpRequest request) {
                return delegate.send(rewriteToLocalWireMock(request));
            }

            @Override
            public HttpResponse sendSync(HttpRequest request, Context context) {
                return delegate.sendSync(rewriteToLocalWireMock(request), context);
            }

            private HttpRequest rewriteToLocalWireMock(HttpRequest request) {
                URL original = request.getUrl();
                if ("https".equalsIgnoreCase(original.getProtocol())
                        && "localhost".equalsIgnoreCase(original.getHost())
                        && original.getPort() == wireMock.port()) {
                    try {
                        String httpUrl = original.toString().replaceFirst("^https://", "http://");
                        request.setUrl(URI.create(httpUrl).toURL());
                    } catch (MalformedURLException e) {
                        throw new IllegalStateException(e);
                    }
                }
                return request;
            }
        };

        secretClient = new SecretClientBuilder()
                .vaultUrl(httpsWireMockUrl)
                .credential(mockCredential)
                .httpClient(loopbackTestClient)
                .addPolicy(new NoCrossHostRedirectPolicy())
                .retryPolicy(new RetryPolicy(new RetryOptions(new FixedDelayOptions(0, Duration.ZERO))))
                .httpLogOptions(new HttpLogOptions().setLogLevel(HttpLogDetailLevel.NONE))
                .disableChallengeResourceVerification()
                .buildClient();

        SecretClientProvider provider = new SecretClientProvider() {
            @Override
            public SecretClient getReadClient(VaultDescriptor v) {
                return secretClient;
            }

            @Override
            public SecretClient getMutationClient(VaultDescriptor v) {
                return secretClient;
            }

            @Override
            public String getCredentialContextId() {
                return "wiremock-ctx";
            }

            @Override
            public String getTenantId() {
                return "wiremock-tenant";
            }
        };

        cache = new SecretMetadataCache(appProperties);
        paginationService = new SecretPaginationService(provider, cache, translator);
    }

    @Test
    void walksThreeWireMockContinuationPagesWithoutEverCallingGetSecretValue() throws Exception {
        String base = httpsWireMockUrl;
        wireMock.stubFor(get(urlPathEqualTo("/secrets"))
                .atPriority(2)
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                  "value": [
                                    {"id": "%s/secrets/secret-page1-a", "attributes": {"enabled": true, "created": 1700000001, "updated": 1700000001}},
                                    {"id": "%s/secrets/secret-page1-b", "attributes": {"enabled": true, "created": 1700000002, "updated": 1700000002}}
                                  ],
                                  "nextLink": "%s/secrets?api-version=7.5&skiptoken=p2"
                                }
                                """.formatted(base, base, base))));

        wireMock.stubFor(get(urlPathEqualTo("/secrets"))
                .withQueryParam("skiptoken", equalTo("p2"))
                .atPriority(1)
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                  "value": [
                                    {"id": "%s/secrets/secret-page2-a", "attributes": {"enabled": false, "created": 1700000003, "updated": 1700000003}}
                                  ],
                                  "nextLink": "%s/secrets?api-version=7.5&skiptoken=p3"
                                }
                                """.formatted(base, base))));

        wireMock.stubFor(get(urlPathEqualTo("/secrets"))
                .withQueryParam("skiptoken", equalTo("p3"))
                .atPriority(1)
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                  "value": [
                                    {"id": "%s/secrets/secret-page3-final", "attributes": {"enabled": true, "created": 1700000004, "updated": 1700000004}}
                                  ],
                                  "nextLink": null
                                }
                                """.formatted(base))));

        paginationService.startOrCoalesceRefresh(vault);

        SecretListSnapshotResponse snapshot = waitForTerminalSnapshot(vault);
        assertThat(snapshot.status()).isEqualTo(SyncStatus.COMPLETE);
        assertThat(snapshot.pagesLoaded()).isEqualTo(3);
        assertThat(snapshot.loadedCount()).isEqualTo(4);
        assertThat(snapshot.items()).extracting(i -> i.name())
                .containsExactly("secret-page1-a", "secret-page1-b", "secret-page2-a", "secret-page3-final");

        // Verify zero calls to /secrets/{name} (value fetch)
        wireMock.verify(0, getRequestedFor(urlPathEqualTo("/secrets/secret-page1-a")));
        wireMock.verify(0, getRequestedFor(urlPathEqualTo("/secrets/secret-page3-final")));
    }

    @Test
    void translatesAzure401403429And503SafelyWithoutLeakingRawAzureBody() {
        // 401
        wireMock.stubFor(get(urlPathMatching("/secrets/sec-401/?"))
                .willReturn(aResponse().withStatus(401)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"error\":{\"code\":\"Unauthorized\",\"message\":\"RAW_AZURE_401_CANARY\"}}")));
        assertThatThrownBy(() -> {
            try {
                secretClient.getSecret("sec-401");
            } catch (RuntimeException ex) {
                throw translator.translate(ex, "Secret");
            }
        }).isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getErrorCode()).isEqualTo("AZURE_CREDENTIAL_INVALID");
                    assertThat(appEx.getSafeMessage()).doesNotContain("RAW_AZURE_401_CANARY");
                });

        // 403
        wireMock.stubFor(get(urlPathMatching("/secrets/sec-403/?"))
                .willReturn(aResponse().withStatus(403)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"error\":{\"code\":\"Forbidden\",\"message\":\"RAW_AZURE_403_CANARY\"}}")));
        assertThatThrownBy(() -> {
            try {
                secretClient.getSecret("sec-403");
            } catch (RuntimeException ex) {
                throw translator.translate(ex, "Secret");
            }
        }).isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getErrorCode()).isEqualTo("AZURE_PERMISSION_DENIED");
                    assertThat(appEx.getSafeMessage()).doesNotContain("RAW_AZURE_403_CANARY");
                });

        // 429 with Retry-After
        wireMock.stubFor(get(urlPathMatching("/secrets/sec-429/?"))
                .willReturn(aResponse().withStatus(429)
                        .withHeader("Retry-After", "7")
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"error\":{\"code\":\"Throttled\",\"message\":\"RAW_429_CANARY\"}}")));
        assertThatThrownBy(() -> {
            try {
                secretClient.getSecret("sec-429");
            } catch (RuntimeException ex) {
                throw translator.translate(ex, "Secret");
            }
        }).isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getErrorCode()).isEqualTo("AZURE_THROTTLED");
                    assertThat(appEx.getRetryAfterSeconds()).isEqualTo(7);
                    assertThat(appEx.getSafeMessage()).doesNotContain("RAW_429_CANARY");
                });

        // 503
        wireMock.stubFor(get(urlPathMatching("/secrets/sec-503/?"))
                .willReturn(aResponse().withStatus(503)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"error\":{\"code\":\"ServiceUnavailable\",\"message\":\"RAW_503_CANARY\"}}")));
        assertThatThrownBy(() -> {
            try {
                secretClient.getSecret("sec-503");
            } catch (RuntimeException ex) {
                throw translator.translate(ex, "Secret");
            }
        }).isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getErrorCode()).isEqualTo("AZURE_UPSTREAM_ERROR");
                    assertThat(appEx.getSafeMessage()).doesNotContain("RAW_503_CANARY");
                });
    }

    @Test
    void blocks302RedirectToExternalHostSoBearerTokenIsNeverForwarded() {
        wireMock.stubFor(get(urlPathMatching("/secrets/sec-redir/?"))
                .willReturn(aResponse()
                        .withStatus(302)
                        .withHeader("Location", "https://evil.attacker.example/steal-token")));

        assertThatThrownBy(() -> secretClient.getSecret("sec-redir"))
                .isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getErrorCode()).isEqualTo("AZURE_UPSTREAM_ERROR");
                    assertThat(appEx.getSafeMessage()).containsIgnoringCase("redirect");
                });
    }

    private SecretListSnapshotResponse waitForTerminalSnapshot(VaultDescriptor v) throws InterruptedException {
        for (int i = 0; i < 60; i++) {
            SecretSnapshotState state = paginationService.getOrStartRefresh(v);
            if (state.status() == SyncStatus.COMPLETE
                    || state.status() == SyncStatus.PARTIAL_ERROR
                    || state.status() == SyncStatus.ERROR) {
                return cache.toResponse(state);
            }
            Thread.sleep(50);
        }
        return cache.toResponse(paginationService.getOrStartRefresh(v));
    }
}
