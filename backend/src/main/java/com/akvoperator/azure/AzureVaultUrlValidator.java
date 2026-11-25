package com.akvoperator.azure;

import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.exception.AppException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Strict SSRF guard and canonicalizer for Azure Key Vault endpoints.
 * Enforces HTTPS, Azure Public Cloud DNS suffix ({@code .vault.azure.net}), valid single-label
 * Key Vault name, standard HTTPS port (443 or omitted), and absence of userinfo, path, query, or fragment.
 */
@Component
public class AzureVaultUrlValidator {

    private static final String PUBLIC_CLOUD_SUFFIX = ".vault.azure.net";
    private static final Pattern VAULT_NAME_PATTERN = Pattern.compile("^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$");

    private final boolean publicCloudOnly;

    @Autowired
    public AzureVaultUrlValidator(AppProperties appProperties) {
        this(appProperties == null || appProperties.getAzure() == null || appProperties.getAzure().isPublicCloudOnly());
    }

    public AzureVaultUrlValidator(boolean publicCloudOnly) {
        this.publicCloudOnly = publicCloudOnly;
    }

    /**
     * Validates that {@code rawVaultUri} is a trusted Azure Key Vault HTTPS endpoint and returns its
     * canonical normalized form {@code https://<lowercase-vault-name>.vault.azure.net}.
     */
    public String validateAndNormalize(String rawVaultUri) {
        if (rawVaultUri == null || rawVaultUri.isBlank()) {
            throw invalidUri("Vault URI must not be blank.");
        }
        String trimmed = rawVaultUri.trim();
        if (trimmed.contains("\\") || trimmed.contains("@") || containsWhitespace(trimmed)) {
            throw invalidUri("Vault URI contains disallowed characters.");
        }

        final URI uri;
        try {
            uri = URI.create(trimmed);
        } catch (IllegalArgumentException ex) {
            throw invalidUri("Vault URI is not a valid URI.");
        }

        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw invalidUri("Vault URI must use the https scheme.");
        }

        if (uri.getRawUserInfo() != null || uri.getUserInfo() != null) {
            throw invalidUri("Vault URI must not include userinfo.");
        }

        int port = uri.getPort();
        if (port != -1 && port != 443) {
            throw invalidUri("Vault URI must use default HTTPS port 443.");
        }

        if (uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw invalidUri("Vault URI must not include query parameters or fragments.");
        }

        String rawPath = uri.getRawPath();
        if (rawPath != null && !rawPath.isEmpty() && !"/".equals(rawPath)) {
            throw invalidUri("Vault URI must not include a non-root path.");
        }

        String rawHost = uri.getHost();
        if (rawHost == null || rawHost.isBlank()) {
            throw invalidUri("Vault URI must include a valid host.");
        }

        String host = rawHost.toLowerCase(Locale.ROOT);
        if (!publicCloudOnly) {
            // MVP does not silently assume sovereign cloud support; fail closed until explicitly implemented.
            throw invalidUri("Only Azure Public Cloud Key Vault endpoints (*.vault.azure.net) are supported.");
        }

        if (!host.endsWith(PUBLIC_CLOUD_SUFFIX)) {
            throw invalidUri("Vault URI host must end with .vault.azure.net (Azure Public Cloud).");
        }

        String vaultName = host.substring(0, host.length() - PUBLIC_CLOUD_SUFFIX.length());
        if (vaultName.isEmpty() || vaultName.contains(".")) {
            throw invalidUri("Vault URI must contain a single Key Vault subdomain label.");
        }

        if (!VAULT_NAME_PATTERN.matcher(vaultName).matches()) {
            throw invalidUri("Vault URI subdomain is not a valid Azure Key Vault name.");
        }

        return "https://" + vaultName + PUBLIC_CLOUD_SUFFIX;
    }

    /**
     * Extracts the lowercase vault name from a validated and normalized vault URI.
     */
    public String extractVaultName(String normalizedVaultUri) {
        String normalized = validateAndNormalize(normalizedVaultUri);
        String host = URI.create(normalized).getHost();
        return host.substring(0, host.length() - PUBLIC_CLOUD_SUFFIX.length());
    }

    private static boolean containsWhitespace(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (Character.isWhitespace(value.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    private static AppException invalidUri(String detail) {
        return AppException.badRequest("INVALID_VAULT_URI", detail);
    }
}
