package com.akvoperator.integration;

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
import com.azure.core.util.polling.LongRunningOperationStatus;
import com.azure.core.util.polling.PollResponse;
import com.azure.core.util.polling.SyncPoller;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.DeletedSecret;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.azure.security.keyvault.secrets.models.SecretProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
class LocalProfileIntegrationTest {

    private static final String CANARY_SECRET = "CANARY_LOCAL_INT_VAL_998123";
    private static final String VAULT_ID = "vlt_local_int_vault_0001";
    private static final VaultDescriptor VAULT = new VaultDescriptor(
            VAULT_ID,
            "/subscriptions/sub-1/resourceGroups/rg-app/providers/Microsoft.KeyVault/vaults/kv-app-dev",
            "kv-app-dev",
            "sub-1",
            "rg-app",
            "westeurope",
            "https://kv-app-dev.vault.azure.net",
            "dev",
            false,
            VaultSource.ARM_DISCOVERY
    );

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private BootstrapTokenService bootstrapTokenService;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AzureCredentialFactory azureCredentialFactory;

    @MockitoBean
    private VaultRegistry vaultRegistry;

    @MockitoBean
    private SecretClientProvider secretClientProvider;

    private SecretClient readClient;
    private SecretClient mutationClient;

    @BeforeEach
    void setUp() {
        readClient = mock(SecretClient.class);
        mutationClient = mock(SecretClient.class);

        when(vaultRegistry.listSubscriptions()).thenReturn(List.of(new SubscriptionDto("sub-1", "Dev Sub", "Enabled")));
        when(vaultRegistry.listVaults()).thenReturn(List.of(VAULT));
        when(vaultRegistry.findByOpaqueId(VAULT_ID)).thenReturn(Optional.of(VAULT));

        when(secretClientProvider.getTenantId()).thenReturn("tenant-int");
        when(secretClientProvider.getCredentialContextId()).thenReturn("ctx-int-1");
        when(secretClientProvider.getReadClient(VAULT)).thenReturn(readClient);
        when(secretClientProvider.getMutationClient(VAULT)).thenReturn(mutationClient);
    }

    @Test
    void fullLocalBootstrapSessionSecurityHeadersAndCrudFlow() throws Exception {
        // 1. Unauthenticated status sets XSRF cookie, no-store, and strict security headers
        MvcResult statusResult = mockMvc.perform(get("/api/v1/auth/status")
                        .header("Host", "127.0.0.1:8765"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", org.hamcrest.Matchers.containsString("no-store")))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andExpect(header().string("Content-Security-Policy", org.hamcrest.Matchers.containsString("frame-ancestors 'none'")))
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"))
                .andExpect(jsonPath("$.authenticated").value(false))
                .andExpect(jsonPath("$.profile").value("local"))
                .andReturn();

        Cookie xsrfCookie = statusResult.getResponse().getCookie("XSRF-TOKEN");
        assertThat(xsrfCookie).isNotNull();
        String xsrfToken = xsrfCookie.getValue();

        // 2. Unauthenticated API call returns 401 RFC 9457 JSON (never HTML redirect)
        mockMvc.perform(get("/api/v1/vaults")
                        .header("Host", "127.0.0.1:8765"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("AUTH_REQUIRED"))
                .andExpect(jsonPath("$.correlationId").isNotEmpty());

        // 3. Bootstrap without CSRF token is rejected 403
        String bootstrapToken = bootstrapTokenService.regenerateToken();
        mockMvc.perform(post("/api/v1/auth/bootstrap")
                        .header("Host", "127.0.0.1:8765")
                        .header("Origin", "http://127.0.0.1:8765")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + bootstrapToken + "\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("CSRF_TOKEN_INVALID"));

        // 4. Bootstrap with valid CSRF + one-time token authenticates and rotates session
        MockHttpSession preLoginSession = new MockHttpSession();
        String preLoginId = preLoginSession.getId();
        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/bootstrap")
                        .session(preLoginSession)
                        .cookie(xsrfCookie)
                        .header("X-XSRF-TOKEN", xsrfToken)
                        .header("Host", "127.0.0.1:8765")
                        .header("Origin", "http://127.0.0.1:8765")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + bootstrapToken + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticated").value(true))
                .andExpect(jsonPath("$.subject").value("local-operator"))
                .andReturn();

        MockHttpSession authSession = (MockHttpSession) loginResult.getRequest().getSession(false);
        assertThat(authSession).isNotNull();
        assertThat(authSession.getId()).isNotEqualTo(preLoginId);

        // 5. Replaying consumed bootstrap token fails with 401
        mockMvc.perform(post("/api/v1/auth/bootstrap")
                        .cookie(xsrfCookie)
                        .header("X-XSRF-TOKEN", xsrfToken)
                        .header("Host", "127.0.0.1:8765")
                        .header("Origin", "http://127.0.0.1:8765")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + bootstrapToken + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("BOOTSTRAP_TOKEN_INVALID"));

        // 6. Discovery returns authorized subscription and vault
        mockMvc.perform(get("/api/v1/subscriptions")
                        .session(authSession)
                        .header("Host", "127.0.0.1:8765"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].subscriptionId").value("sub-1"));

        mockMvc.perform(get("/api/v1/vaults")
                        .session(authSession)
                        .header("Host", "127.0.0.1:8765"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(VAULT_ID));

        // 7. Secrets multi-page list never calls getSecret and never contains canary value
        SecretProperties p1 = secretProps("app-db-url", "v1", true);
        SecretProperties p2 = secretProps("app-api-key", "v1", true);
        SecretProperties p3 = secretProps("app-jwt-key", "v2", false);
        mockPagedSecrets(List.of(List.of(p1), List.of(p2), List.of(p3)));

        MvcResult snapResult = null;
        for (int i = 0; i < 30; i++) {
            snapResult = mockMvc.perform(get("/api/v1/vaults/{id}/secrets", VAULT_ID)
                            .session(authSession)
                            .header("Host", "127.0.0.1:8765"))
                    .andExpect(status().isOk())
                    .andReturn();
            JsonNode node = objectMapper.readTree(snapResult.getResponse().getContentAsString());
            if ("COMPLETE".equals(node.get("status").asText())) {
                break;
            }
            Thread.sleep(50);
        }
        assertThat(snapResult).isNotNull();
        String snapJson = snapResult.getResponse().getContentAsString();
        assertThat(snapJson).contains("app-db-url", "app-api-key", "app-jwt-key");
        assertThat(snapJson).doesNotContain(CANARY_SECRET);
        verify(readClient, never()).getSecret(any());

        // 8. Reveal returns value on demand with Cache-Control: no-store
        KeyVaultSecret revealed = new KeyVaultSecret("app-db-url", CANARY_SECRET);
        revealed.getProperties().setEnabled(true);
        when(readClient.getSecret("app-db-url")).thenReturn(revealed);

        mockMvc.perform(post("/api/v1/vaults/{id}/secrets/{name}/reveal", VAULT_ID, "app-db-url")
                        .session(authSession)
                        .cookie(xsrfCookie)
                        .header("X-XSRF-TOKEN", xsrfToken)
                        .header("Host", "127.0.0.1:8765")
                        .header("Origin", "http://127.0.0.1:8765")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", org.hamcrest.Matchers.containsString("no-store")))
                .andExpect(jsonPath("$.value").value(CANARY_SECRET));

        // 9. Update properties + async soft-delete & operation status
        mockPagedVersions("app-db-url", List.of(p1));
        when(mutationClient.updateSecretProperties(any())).thenReturn(p1);
        mockMvc.perform(patch("/api/v1/vaults/{id}/secrets/{name}/properties", VAULT_ID, "app-db-url")
                        .session(authSession)
                        .cookie(xsrfCookie)
                        .header("X-XSRF-TOKEN", xsrfToken)
                        .header("Host", "127.0.0.1:8765")
                        .header("Origin", "http://127.0.0.1:8765")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":false}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("app-db-url"));

        @SuppressWarnings("unchecked")
        SyncPoller<DeletedSecret, Void> deletePoller = mock(SyncPoller.class);
        when(deletePoller.waitForCompletion(any()))
                .thenReturn(new PollResponse<>(LongRunningOperationStatus.SUCCESSFULLY_COMPLETED, new DeletedSecret()));
        when(mutationClient.beginDeleteSecret("app-db-url")).thenReturn(deletePoller);

        MvcResult delResult = mockMvc.perform(delete("/api/v1/vaults/{id}/secrets/{name}", VAULT_ID, "app-db-url")
                        .session(authSession)
                        .cookie(xsrfCookie)
                        .header("X-XSRF-TOKEN", xsrfToken)
                        .header("Host", "127.0.0.1:8765")
                        .header("Origin", "http://127.0.0.1:8765")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"confirmSecretName\":\"app-db-url\"}"))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.operationId").isNotEmpty())
                .andReturn();

        String operationId = objectMapper.readTree(delResult.getResponse().getContentAsString()).get("operationId").asText();
        String finalState = null;
        for (int i = 0; i < 30; i++) {
            MvcResult opRes = mockMvc.perform(get("/api/v1/operations/{id}", operationId)
                            .session(authSession)
                            .header("Host", "127.0.0.1:8765"))
                    .andExpect(status().isOk())
                    .andReturn();
            finalState = objectMapper.readTree(opRes.getResponse().getContentAsString()).get("state").asText();
            if ("SUCCEEDED".equals(finalState) || "FAILED".equals(finalState)) {
                break;
            }
            Thread.sleep(50);
        }
        assertThat(finalState).isEqualTo("SUCCEEDED");

        // 10. Logout invalidates session
        mockMvc.perform(post("/api/v1/auth/logout")
                        .session(authSession)
                        .cookie(xsrfCookie)
                        .header("X-XSRF-TOKEN", xsrfToken)
                        .header("Host", "127.0.0.1:8765")
                        .header("Origin", "http://127.0.0.1:8765"))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/v1/vaults")
                        .session(authSession)
                        .header("Host", "127.0.0.1:8765"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void enforcesDnsRebindingCrossOriginActuatorLockdownAndApi404NotSwallowedBySpa() throws Exception {
        // DNS rebinding Host rejected
        mockMvc.perform(get("/api/v1/auth/status")
                        .header("Host", "evil.attacker.com"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("HOST_HEADER_INVALID"));

        // Cross-origin POST rejected
        mockMvc.perform(post("/api/v1/auth/bootstrap")
                        .header("Host", "127.0.0.1:8765")
                        .header("Origin", "https://evil.attacker.com")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"aaaaaaaaaaaaaaaa\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("ORIGIN_NOT_ALLOWED"));

        // Actuator health returns minimal status only
        mockMvc.perform(get("/actuator/health")
                        .header("Host", "127.0.0.1:8765"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.components").doesNotExist());

        // Sensitive actuator endpoints are closed
        for (String endpoint : List.of("/actuator/env", "/actuator/heapdump", "/actuator/configprops", "/actuator/beans")) {
            int code = mockMvc.perform(get(endpoint).header("Host", "127.0.0.1:8765"))
                    .andReturn()
                    .getResponse()
                    .getStatus();
            assertThat(code).isIn(401, 403, 404);
        }

        // Unknown /api path returns JSON error, never SPA HTML
        MvcResult statusResult = mockMvc.perform(get("/api/v1/auth/status").header("Host", "127.0.0.1:8765"))
                .andReturn();
        Cookie xsrf = statusResult.getResponse().getCookie("XSRF-TOKEN");
        String token = bootstrapTokenService.regenerateToken();
        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/bootstrap")
                        .cookie(xsrf)
                        .header("X-XSRF-TOKEN", xsrf.getValue())
                        .header("Host", "127.0.0.1:8765")
                        .header("Origin", "http://127.0.0.1:8765")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + token + "\"}"))
                .andExpect(status().isOk())
                .andReturn();

        MvcResult api404 = mockMvc.perform(get("/api/v1/non-existent-endpoint")
                        .session((MockHttpSession) loginResult.getRequest().getSession(false))
                        .header("Host", "127.0.0.1:8765"))
                .andExpect(status().isNotFound())
                .andReturn();
        assertThat(api404.getResponse().getContentType()).contains("problem+json");
        assertThat(api404.getResponse().getContentAsString()).doesNotContain("<html");
    }

    private SecretProperties secretProps(String name, String version, boolean enabled) {
        SecretProperties props = mock(SecretProperties.class);
        when(props.getName()).thenReturn(name);
        when(props.getVersion()).thenReturn(version);
        when(props.isEnabled()).thenReturn(enabled);
        when(props.getCreatedOn()).thenReturn(OffsetDateTime.of(2026, 1, 10, 12, 0, 0, 0, ZoneOffset.UTC));
        when(props.getUpdatedOn()).thenReturn(OffsetDateTime.of(2026, 1, 11, 12, 0, 0, 0, ZoneOffset.UTC));
        when(props.getTags()).thenReturn(Map.of("env", "dev"));
        return props;
    }

    @SuppressWarnings("unchecked")
    private void mockPagedSecrets(List<List<SecretProperties>> pages) {
        PagedIterable<SecretProperties> iterable = mock(PagedIterable.class);
        List<PagedResponse<SecretProperties>> responses = pages.stream()
                .map(items -> (PagedResponse<SecretProperties>) new PagedResponseBase<Void, SecretProperties>(
                        null, 200, new HttpHeaders(), items, null, null))
                .toList();
        when(iterable.iterableByPage()).thenReturn(responses);
        when(readClient.listPropertiesOfSecrets()).thenReturn(iterable);
    }

    @SuppressWarnings("unchecked")
    private void mockPagedVersions(String name, List<SecretProperties> versions) {
        PagedIterable<SecretProperties> iterable = mock(PagedIterable.class);
        PagedResponse<SecretProperties> page = new PagedResponseBase<Void, SecretProperties>(
                null, 200, new HttpHeaders(), versions, null, null);
        when(iterable.iterableByPage()).thenReturn(List.of(page));
        when(readClient.listPropertiesOfSecretVersions(name)).thenReturn(iterable);
    }
}
