package com.akvoperator.qa;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.akvoperator.auth.BootstrapTokenService;
import com.akvoperator.azure.AzureCredentialFactory;
import com.akvoperator.azure.SecretClientProvider;
import com.akvoperator.common.dto.SubscriptionDto;
import com.akvoperator.common.dto.VaultSource;
import com.akvoperator.vault.VaultDescriptor;
import com.akvoperator.vault.VaultRegistry;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.rest.PagedIterable;
import com.azure.core.http.rest.PagedResponse;
import com.azure.core.http.rest.PagedResponseBase;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.azure.security.keyvault.secrets.models.SecretProperties;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * QA verification tests covering canary secret non-leakage across logs and non-reveal endpoints,
 * 15-minute idle session timeout enforcement, XSS/path-traversal secret name rejection,
 * and absence of any permanent purge endpoint.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "app.profile=local",
        "server.address=127.0.0.1",
        "app.delete-enabled=true",
        "app.local.bootstrap-token-auto-print=false",
        "app.security.rate-limit-per-minute=1000",
        "app.security.bootstrap-rate-limit-per-minute=100"
})
class SecurityQaVerificationTest {

    private static final String CANARY_VALUE = "CANARY_QA_BACKEND_LEAK_551234";
    private static final String VAULT_ID = "vlt_qa_sec_vault_0001";
    private static final VaultDescriptor VAULT = new VaultDescriptor(
            VAULT_ID,
            "/subscriptions/sub-qa/resourceGroups/rg-qa/providers/Microsoft.KeyVault/vaults/kv-qa-sec",
            "kv-qa-sec",
            "sub-qa",
            "rg-qa",
            "westeurope",
            "https://kv-qa-sec.vault.azure.net",
            "test",
            false,
            VaultSource.ARM_DISCOVERY
    );

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private BootstrapTokenService bootstrapTokenService;

    @MockitoBean
    private AzureCredentialFactory azureCredentialFactory;

    @MockitoBean
    private VaultRegistry vaultRegistry;

    @MockitoBean
    private SecretClientProvider secretClientProvider;

    private SecretClient readClient;
    private SecretClient mutationClient;
    private ListAppender<ILoggingEvent> logAppender;
    private Logger rootLogger;

    @BeforeEach
    void setUp() {
        readClient = mock(SecretClient.class);
        mutationClient = mock(SecretClient.class);

        when(vaultRegistry.listSubscriptions()).thenReturn(List.of(new SubscriptionDto("sub-qa", "QA Sub", "Enabled")));
        when(vaultRegistry.listVaults()).thenReturn(List.of(VAULT));
        when(vaultRegistry.findByOpaqueId(VAULT_ID)).thenReturn(Optional.of(VAULT));

        when(secretClientProvider.getTenantId()).thenReturn("tenant-qa");
        when(secretClientProvider.getCredentialContextId()).thenReturn("ctx-qa-1");
        when(secretClientProvider.getReadClient(VAULT)).thenReturn(readClient);
        when(secretClientProvider.getMutationClient(VAULT)).thenReturn(mutationClient);

        rootLogger = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        logAppender = new ListAppender<>();
        logAppender.start();
        rootLogger.addAppender(logAppender);
    }

    @AfterEach
    void tearDown() {
        if (rootLogger != null && logAppender != null) {
            rootLogger.detachAppender(logAppender);
            logAppender.stop();
        }
    }

    @Test
    void canarySecretNeverLeaksIntoLogsOrNonRevealResponsesAndIdleTimeoutIs15Minutes() throws Exception {
        AuthContext ctx = loginLocalOperator();

        // 15-minute (900s) idle timeout must be enforced on authenticated session
        assertThat(ctx.session().getMaxInactiveInterval()).isEqualTo(900);

        // Stub secret create & reveal & list with canary value
        SecretProperties props = mock(SecretProperties.class);
        when(props.getName()).thenReturn("qa-canary-secret");
        when(props.getVersion()).thenReturn("v1");
        when(props.isEnabled()).thenReturn(true);
        when(props.getCreatedOn()).thenReturn(OffsetDateTime.of(2026, 6, 1, 10, 0, 0, 0, ZoneOffset.UTC));
        when(props.getUpdatedOn()).thenReturn(OffsetDateTime.of(2026, 6, 1, 10, 0, 0, 0, ZoneOffset.UTC));
        when(props.getTags()).thenReturn(Map.of("env", "qa"));

        KeyVaultSecret created = new KeyVaultSecret("qa-canary-secret", CANARY_VALUE);
        created.getProperties().setEnabled(true);
        when(mutationClient.setSecret(any(KeyVaultSecret.class))).thenReturn(created);
        when(readClient.getSecret("qa-canary-secret")).thenReturn(created);

        @SuppressWarnings("unchecked")
        PagedIterable<SecretProperties> emptyIterable = mock(PagedIterable.class);
        when(emptyIterable.iterableByPage()).thenReturn(List.of(
                new PagedResponseBase<Void, SecretProperties>(null, 200, new HttpHeaders(), List.of(), null, null)));
        when(readClient.listPropertiesOfSecrets()).thenReturn(emptyIterable);
        when(readClient.listPropertiesOfSecretVersions("qa-canary-secret")).thenReturn(emptyIterable);
        when(readClient.listDeletedSecrets()).thenReturn(mock(PagedIterable.class));

        // Create secret -> response must NOT echo canary value
        MvcResult createRes = mockMvc.perform(post("/api/v1/vaults/{id}/secrets", VAULT_ID)
                        .session(ctx.session())
                        .cookie(ctx.xsrfCookie())
                        .header("X-XSRF-TOKEN", ctx.xsrfCookie().getValue())
                        .header("Host", "127.0.0.1:8765")
                        .header("Origin", "http://127.0.0.1:8765")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"qa-canary-secret\",\"value\":\"" + CANARY_VALUE + "\"}"))
                .andExpect(status().isCreated())
                .andExpect(header().string("Cache-Control", org.hamcrest.Matchers.containsString("no-store")))
                .andReturn();
        assertThat(createRes.getResponse().getContentAsString()).doesNotContain(CANARY_VALUE);

        // Reveal secret -> returns canary with Cache-Control: no-store
        mockMvc.perform(post("/api/v1/vaults/{id}/secrets/qa-canary-secret/reveal", VAULT_ID)
                        .session(ctx.session())
                        .cookie(ctx.xsrfCookie())
                        .header("X-XSRF-TOKEN", ctx.xsrfCookie().getValue())
                        .header("Host", "127.0.0.1:8765")
                        .header("Origin", "http://127.0.0.1:8765")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", org.hamcrest.Matchers.containsString("no-store")))
                .andExpect(jsonPath("$.value").value(CANARY_VALUE));

        // Verify ZERO logback events contain the canary secret value or bootstrap token
        for (ILoggingEvent event : logAppender.list) {
            assertThat(event.getFormattedMessage()).doesNotContain(CANARY_VALUE);
            assertThat(event.getFormattedMessage()).doesNotContain(ctx.bootstrapToken());
        }
    }

    @Test
    void rejectsXssAndTraversalSecretNamesAndHasNoPermanentPurgeEndpoint() throws Exception {
        AuthContext ctx = loginLocalOperator();

        // XSS / invalid secret names rejected with 400 RFC 9457 Problem Details (and never reflect payload)
        for (String invalidName : List.of("<script>alert(1)</script>", "bad_underscore", "space name", "../etc")) {
            MvcResult badRes = mockMvc.perform(post("/api/v1/vaults/{id}/secrets", VAULT_ID)
                            .session(ctx.session())
                            .cookie(ctx.xsrfCookie())
                            .header("X-XSRF-TOKEN", ctx.xsrfCookie().getValue())
                            .header("Host", "127.0.0.1:8765")
                            .header("Origin", "http://127.0.0.1:8765")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"name\":\"" + invalidName + "\",\"value\":\"test\"}"))
                    .andExpect(status().isBadRequest())
                    .andExpect(header().string("Content-Type", org.hamcrest.Matchers.containsString("application/problem+json")))
                    .andExpect(header().exists("X-Correlation-Id"))
                    .andExpect(jsonPath("$.status").value(400))
                    .andExpect(jsonPath("$.errorCode").value("VALIDATION_ERROR"))
                    .andExpect(jsonPath("$.correlationId").isNotEmpty())
                    .andExpect(jsonPath("$.fieldErrors.name").isNotEmpty())
                    .andReturn();
            // Ensure raw XSS/traversal payload is never reflected unsafely in the error response
            assertThat(badRes.getResponse().getContentAsString()).doesNotContain("<script>");
        }

        // Permanent purge routes must NOT exist (never 2xx)
        int deletePurgeStatus = mockMvc.perform(delete("/api/v1/vaults/{id}/deleted-secrets/qa-canary-secret", VAULT_ID)
                        .session(ctx.session())
                        .cookie(ctx.xsrfCookie())
                        .header("X-XSRF-TOKEN", ctx.xsrfCookie().getValue())
                        .header("Host", "127.0.0.1:8765")
                        .header("Origin", "http://127.0.0.1:8765"))
                .andReturn().getResponse().getStatus();
        assertThat(deletePurgeStatus).isIn(404, 405, 403);

        int postPurgeStatus = mockMvc.perform(post("/api/v1/vaults/{id}/deleted-secrets/qa-canary-secret/purge", VAULT_ID)
                        .session(ctx.session())
                        .cookie(ctx.xsrfCookie())
                        .header("X-XSRF-TOKEN", ctx.xsrfCookie().getValue())
                        .header("Host", "127.0.0.1:8765")
                        .header("Origin", "http://127.0.0.1:8765"))
                .andReturn().getResponse().getStatus();
        assertThat(postPurgeStatus).isIn(404, 405, 403);
    }

    private AuthContext loginLocalOperator() throws Exception {
        MvcResult statusResult = mockMvc.perform(get("/api/v1/auth/status")
                        .header("Host", "127.0.0.1:8765"))
                .andExpect(status().isOk())
                .andReturn();
        Cookie xsrfCookie = statusResult.getResponse().getCookie("XSRF-TOKEN");
        assertThat(xsrfCookie).isNotNull();

        String token = bootstrapTokenService.regenerateToken();
        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/bootstrap")
                        .cookie(xsrfCookie)
                        .header("X-XSRF-TOKEN", xsrfCookie.getValue())
                        .header("Host", "127.0.0.1:8765")
                        .header("Origin", "http://127.0.0.1:8765")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + token + "\"}"))
                .andExpect(status().isOk())
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession(false);
        assertThat(session).isNotNull();
        return new AuthContext(session, xsrfCookie, token);
    }

    private record AuthContext(MockHttpSession session, Cookie xsrfCookie, String bootstrapToken) {
    }
}
