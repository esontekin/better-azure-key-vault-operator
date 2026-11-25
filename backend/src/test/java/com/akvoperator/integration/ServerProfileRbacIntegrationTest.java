package com.akvoperator.integration;

import com.akvoperator.azure.AzureCredentialFactory;
import com.akvoperator.azure.SecretClientProvider;
import com.akvoperator.common.dto.SubscriptionDto;
import com.akvoperator.common.dto.VaultSource;
import com.akvoperator.security.AppPrincipal;
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
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "app.profile=server",
        "app.delete-enabled=true",
        "app.allowed-vault-ids=/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.KeyVault/vaults/kv-a,/subscriptions/sub-1/resourceGroups/rg-b/providers/Microsoft.KeyVault/vaults/kv-b",
        "app.server.public-base-url=https://akv.example.internal",
        "app.server.oidc-issuer-uri=https://hydra.example.internal",
        "app.server.oidc-client-id=akv-client",
        "app.server.oidc-client-secret=test-oidc-secret-placeholder",
        "app.server.trusted-proxies=10.0.0.0/8",
        "app.server.role-mappings-json=["
                + "{\"subject\":\"viewer-1\",\"vaultResourceId\":\"/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.KeyVault/vaults/kv-a\",\"role\":\"VIEWER\"},"
                + "{\"subject\":\"operator-1\",\"vaultResourceId\":\"/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.KeyVault/vaults/kv-a\",\"role\":\"OPERATOR\"},"
                + "{\"subject\":\"manager-1\",\"vaultResourceId\":\"/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.KeyVault/vaults/kv-a\",\"role\":\"MANAGER\"},"
                + "{\"subject\":\"admin-a\",\"vaultResourceId\":\"/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.KeyVault/vaults/kv-a\",\"role\":\"ADMIN\"},"
                + "{\"subject\":\"admin-b\",\"vaultResourceId\":\"/subscriptions/sub-1/resourceGroups/rg-b/providers/Microsoft.KeyVault/vaults/kv-b\",\"role\":\"ADMIN\"}"
                + "]",
        "app.security.rate-limit-per-minute=1000"
})
class ServerProfileRbacIntegrationTest {

    private static final String VAULT_A_ID = "vlt_server_vault_a_0001";
    private static final String VAULT_B_ID = "vlt_server_vault_b_0002";

    private static final VaultDescriptor VAULT_A = new VaultDescriptor(
            VAULT_A_ID,
            "/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.KeyVault/vaults/kv-a",
            "kv-a",
            "sub-1",
            "rg-a",
            "westeurope",
            "https://kv-a.vault.azure.net",
            "prod",
            true,
            VaultSource.ARM_DISCOVERY
    );

    private static final VaultDescriptor VAULT_B = new VaultDescriptor(
            VAULT_B_ID,
            "/subscriptions/sub-1/resourceGroups/rg-b/providers/Microsoft.KeyVault/vaults/kv-b",
            "kv-b",
            "sub-1",
            "rg-b",
            "westeurope",
            "https://kv-b.vault.azure.net",
            "prod",
            true,
            VaultSource.ARM_DISCOVERY
    );

    @Autowired
    private MockMvc mockMvc;

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

        when(vaultRegistry.listSubscriptions()).thenReturn(List.of(new SubscriptionDto("sub-1", "Prod Sub", "Enabled")));
        when(vaultRegistry.listVaults()).thenReturn(List.of(VAULT_A, VAULT_B));
        when(vaultRegistry.findByOpaqueId(VAULT_A_ID)).thenReturn(Optional.of(VAULT_A));
        when(vaultRegistry.findByOpaqueId(VAULT_B_ID)).thenReturn(Optional.of(VAULT_B));

        when(secretClientProvider.getTenantId()).thenReturn("tenant-srv");
        when(secretClientProvider.getCredentialContextId()).thenReturn("ctx-srv-1");
        when(secretClientProvider.getReadClient(any())).thenReturn(readClient);
        when(secretClientProvider.getMutationClient(any())).thenReturn(mutationClient);

        @SuppressWarnings("unchecked")
        PagedIterable<SecretProperties> emptySecrets = mock(PagedIterable.class);
        when(emptySecrets.iterableByPage()).thenReturn(List.of(
                new PagedResponseBase<Void, SecretProperties>(null, 200, new HttpHeaders(), List.of(), null, null)));
        when(readClient.listPropertiesOfSecrets()).thenReturn(emptySecrets);
        when(readClient.listPropertiesOfSecretVersions(any())).thenReturn(emptySecrets);

        KeyVaultSecret secret = new KeyVaultSecret("db-pass", "super-secret-value");
        secret.getProperties().setEnabled(true);
        when(readClient.getSecret("db-pass")).thenReturn(secret);
        when(mutationClient.setSecret(any(KeyVaultSecret.class))).thenReturn(secret);
    }

    @Test
    void enforcesFullRbacMatrixCrossVaultIdorDiscoveryFilteringAndOperationScope() throws Exception {
        // Local bootstrap is strictly blocked in server profile
        mockMvc.perform(post("/api/v1/auth/bootstrap")
                        .with(csrf())
                        .header("Host", "akv.example.internal")
                        .header("Origin", "https://akv.example.internal")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"aaaaaaaaaaaaaaaa\"}"))
                .andExpect(status().isForbidden());

        // UNMAPPED user sees 0 vaults and is denied on Vault A (default deny)
        mockMvc.perform(get("/api/v1/vaults")
                        .with(user("stranger"))
                        .header("Host", "akv.example.internal"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));

        mockMvc.perform(get("/api/v1/vaults/{id}/secrets", VAULT_A_ID)
                        .with(user("stranger"))
                        .header("Host", "akv.example.internal"))
                .andExpect(status().isForbidden());

        // VIEWER: list OK, reveal DENIED, create DENIED, delete DENIED
        mockMvc.perform(get("/api/v1/vaults/{id}/secrets", VAULT_A_ID)
                        .with(user("viewer-1"))
                        .header("Host", "akv.example.internal"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/v1/vaults/{id}/secrets/db-pass/reveal", VAULT_A_ID)
                        .with(user("viewer-1"))
                        .with(csrf())
                        .header("Host", "akv.example.internal")
                        .header("Origin", "https://akv.example.internal")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isForbidden());

        // OPERATOR: reveal OK, create DENIED
        mockMvc.perform(post("/api/v1/vaults/{id}/secrets/db-pass/reveal", VAULT_A_ID)
                        .with(user("operator-1"))
                        .with(csrf())
                        .header("Host", "akv.example.internal")
                        .header("Origin", "https://akv.example.internal")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.value").value("super-secret-value"));

        mockMvc.perform(post("/api/v1/vaults/{id}/secrets", VAULT_A_ID)
                        .with(user("operator-1"))
                        .with(csrf())
                        .header("Host", "akv.example.internal")
                        .header("Origin", "https://akv.example.internal")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"new-sec\",\"value\":\"val\"}"))
                .andExpect(status().isForbidden());

        // MANAGER: create OK, delete DENIED
        mockMvc.perform(post("/api/v1/vaults/{id}/secrets", VAULT_A_ID)
                        .with(user("manager-1"))
                        .with(csrf())
                        .header("Host", "akv.example.internal")
                        .header("Origin", "https://akv.example.internal")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"new-sec\",\"value\":\"val\"}"))
                .andExpect(status().isCreated());

        mockMvc.perform(delete("/api/v1/vaults/{id}/secrets/db-pass", VAULT_A_ID)
                        .with(user("manager-1"))
                        .with(csrf())
                        .header("Host", "akv.example.internal")
                        .header("Origin", "https://akv.example.internal")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"confirmSecretName\":\"db-pass\"}"))
                .andExpect(status().isForbidden());

        // ADMIN on Vault A: discovery only shows Vault A; accessing Vault B (cross-vault IDOR) is DENIED
        mockMvc.perform(get("/api/v1/vaults")
                        .with(user("admin-a"))
                        .header("Host", "akv.example.internal"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(VAULT_A_ID));

        mockMvc.perform(get("/api/v1/vaults/{id}/secrets", VAULT_B_ID)
                        .with(user("admin-a"))
                        .header("Host", "akv.example.internal"))
                .andExpect(status().isForbidden());

        // ADMIN on Vault A initiates delete -> ADMIN on Vault B CANNOT read Vault A's operation status!
        @SuppressWarnings("unchecked")
        SyncPoller<DeletedSecret, Void> poller = mock(SyncPoller.class);
        when(poller.waitForCompletion(any()))
                .thenReturn(new PollResponse<>(LongRunningOperationStatus.SUCCESSFULLY_COMPLETED, new DeletedSecret()));
        when(mutationClient.beginDeleteSecret("db-pass")).thenReturn(poller);

        MvcResult delRes = mockMvc.perform(delete("/api/v1/vaults/{id}/secrets/db-pass", VAULT_A_ID)
                        .with(user("admin-a"))
                        .with(csrf())
                        .header("Host", "akv.example.internal")
                        .header("Origin", "https://akv.example.internal")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"confirmSecretName\":\"db-pass\"}"))
                .andExpect(status().isAccepted())
                .andReturn();
        String opId = objectMapper.readTree(delRes.getResponse().getContentAsString()).get("operationId").asText();

        mockMvc.perform(get("/api/v1/operations/{id}", opId)
                        .with(user("admin-a"))
                        .header("Host", "akv.example.internal"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/operations/{id}", opId)
                        .with(user("admin-b"))
                        .header("Host", "akv.example.internal"))
                .andExpect(status().isForbidden());
    }

    @Test
    void enforcesHstsWhenBehindTrustedProxyAndRejectsUntrustedHost() throws Exception {
        mockMvc.perform(get("/api/v1/auth/status")
                        .with(req -> {
                            req.setRemoteAddr("10.1.2.3");
                            return req;
                        })
                        .header("Host", "akv.example.internal")
                        .header("X-Forwarded-Proto", "https"))
                .andExpect(status().isOk())
                .andExpect(header().string("Strict-Transport-Security",
                        org.hamcrest.Matchers.containsString("max-age=31536000")));

        mockMvc.perform(get("/api/v1/auth/status")
                        .header("Host", "spoofed.attacker.org"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errorCode").value("HOST_HEADER_INVALID"));
    }

    private RequestPostProcessor user(String subject) {
        AppPrincipal principal = new AppPrincipal(subject, subject, "https://hydra.example.internal", Set.of(), false);
        return authentication(new UsernamePasswordAuthenticationToken(
                principal, null, List.of(new SimpleGrantedAuthority("ROLE_USER"))
        ));
    }
}
