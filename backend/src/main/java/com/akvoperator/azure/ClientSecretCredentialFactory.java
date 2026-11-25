package com.akvoperator.azure;

import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.exception.AppException;
import com.azure.core.credential.TokenCredential;
import com.azure.identity.AzureAuthorityHosts;
import com.azure.identity.ClientSecretCredentialBuilder;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Service Principal credential factory backed exclusively by {@link ClientSecretCredentialBuilder}.
 * Never uses {@code AzureCliCredential}, {@code DefaultAzureCredential}, or any automatic fallback chain.
 * Validates configuration eagerly on startup and never logs or includes secret values in error messages.
 */
@Component
public class ClientSecretCredentialFactory implements AzureCredentialFactory {

    private final AppProperties appProperties;
    private final AzureHttpClientFactory httpClientFactory;

    private volatile TokenCredential credential;
    private volatile String tenantId;
    private volatile String clientId;
    private volatile String credentialContextId;

    @Autowired
    public ClientSecretCredentialFactory(AppProperties appProperties, AzureHttpClientFactory httpClientFactory) {
        this.appProperties = appProperties;
        this.httpClientFactory = httpClientFactory;
    }

    public ClientSecretCredentialFactory(AppProperties appProperties) {
        this(appProperties, new AzureHttpClientFactory(appProperties));
    }

    @PostConstruct
    public void initialize() {
        AppProperties.AzureProperties azure = appProperties != null ? appProperties.getAzure() : null;
        if (azure == null) {
            throw AppException.invalidConfiguration("Azure configuration section is missing.");
        }

        String resolvedTenantId = trimToNull(azure.getTenantId());
        if (resolvedTenantId == null) {
            throw AppException.invalidConfiguration(
                    "AZURE_TENANT_ID is required and must not be blank.");
        }

        String resolvedClientId = trimToNull(azure.getClientId());
        if (resolvedClientId == null) {
            throw AppException.invalidConfiguration(
                    "AZURE_CLIENT_ID is required and must not be blank.");
        }

        boolean hasInlineSecret = azure.getClientSecret() != null && !azure.getClientSecret().isBlank();
        boolean hasSecretFile = azure.getClientSecretFile() != null && !azure.getClientSecretFile().isBlank();

        if (hasInlineSecret && hasSecretFile) {
            throw AppException.invalidConfiguration(
                    "Both AZURE_CLIENT_SECRET and AZURE_CLIENT_SECRET_FILE are configured. Configure exactly one secret source.");
        }
        if (!hasInlineSecret && !hasSecretFile) {
            throw AppException.invalidConfiguration(
                    "Azure client secret is required. Configure either AZURE_CLIENT_SECRET or AZURE_CLIENT_SECRET_FILE (provide the secret value, not the secret ID).");
        }

        String resolvedSecret = hasSecretFile
                ? readSecretFile(azure.getClientSecretFile().trim())
                : azure.getClientSecret();

        ClientSecretCredentialBuilder builder = new ClientSecretCredentialBuilder()
                .tenantId(resolvedTenantId)
                .clientId(resolvedClientId)
                .clientSecret(resolvedSecret)
                .httpClient(httpClientFactory.getHttpClient())
                .httpLogOptions(httpClientFactory.createNoLoggingOptions());

        if (azure.isPublicCloudOnly()) {
            builder.authorityHost(AzureAuthorityHosts.AZURE_PUBLIC_CLOUD);
        }

        this.tenantId = resolvedTenantId;
        this.clientId = resolvedClientId;
        this.credentialContextId = computeContextId(resolvedTenantId, resolvedClientId);
        this.credential = builder.build();
    }

    @Override
    public TokenCredential getCredential() {
        if (credential == null) {
            initialize();
        }
        return credential;
    }

    @Override
    public String getTenantId() {
        if (tenantId == null) {
            initialize();
        }
        return tenantId;
    }

    @Override
    public String getClientId() {
        if (clientId == null) {
            initialize();
        }
        return clientId;
    }

    @Override
    public String getCredentialContextId() {
        if (credentialContextId == null) {
            initialize();
        }
        return credentialContextId;
    }

    @Override
    public String toString() {
        return "ClientSecretCredentialFactory{tenantId='" + tenantId
                + "', clientId='" + clientId
                + "', credentialContextId='" + credentialContextId
                + "', clientSecret='[REDACTED]'}";
    }

    private static String readSecretFile(String filePath) {
        Path path = Path.of(filePath);
        if (!Files.exists(path) || !Files.isRegularFile(path) || !Files.isReadable(path)) {
            throw AppException.invalidConfiguration(
                    "AZURE_CLIENT_SECRET_FILE does not exist or is not a readable regular file.");
        }
        final String content;
        try {
            content = Files.readString(path, StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw AppException.invalidConfiguration(
                    "Failed to read AZURE_CLIENT_SECRET_FILE. Verify file permissions and encoding.");
        }
        String stripped = stripTrailingLineEndings(content);
        if (stripped.isBlank()) {
            throw AppException.invalidConfiguration(
                    "AZURE_CLIENT_SECRET_FILE is empty. Provide a valid Azure client secret value.");
        }
        return stripped;
    }

    private static String stripTrailingLineEndings(String value) {
        int end = value.length();
        while (end > 0) {
            char c = value.charAt(end - 1);
            if (c == '\n' || c == '\r') {
                end--;
            } else {
                break;
            }
        }
        return value.substring(0, end);
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static String computeContextId(String tenantId, String clientId) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest((tenantId + "|" + clientId).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 algorithm is unavailable", ex);
        }
    }
}
