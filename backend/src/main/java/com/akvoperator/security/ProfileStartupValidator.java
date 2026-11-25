package com.akvoperator.security;

import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.exception.AppException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.List;

/**
 * Fail-closed startup validator for profile, network binding, OIDC, allowlist, and role mapping configuration.
 */
@Component
public class ProfileStartupValidator implements InitializingBean {

    private final AppProperties appProperties;
    private final ObjectMapper objectMapper;
    private final String serverAddress;

    public ProfileStartupValidator(
            AppProperties appProperties,
            ObjectMapper objectMapper,
            @Value("${server.address:127.0.0.1}") String serverAddress
    ) {
        this.appProperties = appProperties;
        this.objectMapper = objectMapper;
        this.serverAddress = serverAddress;
    }

    @Override
    public void afterPropertiesSet() {
        validate();
    }

    public void validate() {
        String profile = appProperties.getProfile();
        if (profile == null || (!"local".equalsIgnoreCase(profile.trim()) && !"server".equalsIgnoreCase(profile.trim()))) {
            throw AppException.invalidConfiguration(
                    "Invalid APP_PROFILE configuration. Allowed values are strictly 'local' or 'server'."
            );
        }

        if (appProperties.isLocalProfile()) {
            validateLocalProfile();
        } else {
            validateServerProfile();
        }
    }

    private void validateLocalProfile() {
        String addr = serverAddress != null ? serverAddress.trim() : "";
        boolean isLoopback = "localhost".equalsIgnoreCase(addr) || CidrMatcher.isLoopbackIpLiteral(addr);
        if (!isLoopback && !appProperties.getLocal().isAllowContainerBind()) {
            throw AppException.invalidConfiguration(
                    "Local profile requires loopback SERVER_ADDRESS (127.0.0.1 or ::1). "
                            + "For container local mode published to host 127.0.0.1, set APP_LOCAL_ALLOW_CONTAINER_BIND=true explicitly."
            );
        }
        if (appProperties.getLocal().getBootstrapTokenTtl() == null
                || appProperties.getLocal().getBootstrapTokenTtl().isNegative()
                || appProperties.getLocal().getBootstrapTokenTtl().isZero()) {
            throw AppException.invalidConfiguration("app.local.bootstrap-token-ttl must be a positive duration.");
        }
        if (appProperties.getLocal().getIdleTimeout() == null
                || appProperties.getLocal().getIdleTimeout().isNegative()
                || appProperties.getLocal().getIdleTimeout().isZero()) {
            throw AppException.invalidConfiguration("app.local.idle-timeout must be a positive duration.");
        }
        if (appProperties.getLocal().getAllowedHosts().stream().noneMatch(h -> h != null && !h.isBlank())) {
            throw AppException.invalidConfiguration("app.local.allowed-hosts must contain at least one host.");
        }
    }

    private void validateServerProfile() {
        List<String> allowedVaultIds = appProperties.getAllowedVaultIds();
        boolean hasAllowedVault = allowedVaultIds != null
                && allowedVaultIds.stream().anyMatch(id -> id != null && !id.isBlank());
        if (!hasAllowedVault) {
            throw AppException.invalidConfiguration(
                    "Server profile requires an explicit non-empty APP_ALLOWED_VAULT_IDS allowlist."
            );
        }

        AppProperties.ServerProperties server = appProperties.getServer();
        validateHttpsUri(server.getOidcIssuerUri(), "OIDC_ISSUER_URI (app.server.oidc-issuer-uri)");
        if (server.getOidcClientId() == null || server.getOidcClientId().isBlank()) {
            throw AppException.invalidConfiguration("Server profile requires non-blank OIDC_CLIENT_ID.");
        }
        if (server.getOidcClientSecret() == null || server.getOidcClientSecret().isBlank()) {
            throw AppException.invalidConfiguration("Server profile requires non-blank OIDC_CLIENT_SECRET.");
        }
        validateHttpsUri(server.getPublicBaseUrl(), "APP_SERVER_PUBLIC_BASE_URL (app.server.public-base-url)");

        if (server.getTrustedProxies() != null) {
            for (String proxy : server.getTrustedProxies()) {
                if (proxy == null || proxy.isBlank()) {
                    continue;
                }
                try {
                    CidrMatcher.parse(proxy);
                } catch (IllegalArgumentException ex) {
                    throw AppException.invalidConfiguration(
                            "Invalid CIDR/IP entry in APP_SERVER_TRUSTED_PROXIES: " + proxy
                    );
                }
            }
        }

        validateRoleMappings(server);
    }

    private void validateRoleMappings(AppProperties.ServerProperties server) {
        if (server.getRoleMappings() != null) {
            for (AppProperties.RoleMappingConfig mapping : server.getRoleMappings()) {
                validateRoleMappingEntry(mapping);
            }
        }
        if (server.getRoleMappingsJson() != null && !server.getRoleMappingsJson().isBlank()) {
            List<AppProperties.RoleMappingConfig> parsed;
            try {
                parsed = objectMapper.readValue(
                        server.getRoleMappingsJson(),
                        new TypeReference<List<AppProperties.RoleMappingConfig>>() {
                        }
                );
            } catch (Exception ex) {
                throw AppException.invalidConfiguration(
                        "Invalid JSON in APP_SERVER_ROLE_MAPPINGS_JSON (app.server.role-mappings-json)."
                );
            }
            if (parsed != null) {
                for (AppProperties.RoleMappingConfig mapping : parsed) {
                    validateRoleMappingEntry(mapping);
                }
            }
        }
    }

    private void validateRoleMappingEntry(AppProperties.RoleMappingConfig mapping) {
        if (mapping == null) {
            throw AppException.invalidConfiguration("Role mapping entry must not be null.");
        }
        boolean hasSubject = mapping.getSubject() != null && !mapping.getSubject().isBlank();
        boolean hasGroup = mapping.getGroup() != null && !mapping.getGroup().isBlank();
        if (!hasSubject && !hasGroup) {
            throw AppException.invalidConfiguration(
                    "Each role mapping must specify at least a non-blank 'subject' or 'group'."
            );
        }
        if (mapping.getVaultResourceId() == null || mapping.getVaultResourceId().isBlank()) {
            throw AppException.invalidConfiguration(
                    "Each role mapping must specify a non-blank 'vaultResourceId'."
            );
        }
        if (mapping.getRole() == null) {
            throw AppException.invalidConfiguration(
                    "Each role mapping must specify a valid 'role' (VIEWER, OPERATOR, MANAGER, ADMIN)."
            );
        }
    }

    private void validateHttpsUri(String value, String propertyName) {
        if (value == null || value.isBlank()) {
            throw AppException.invalidConfiguration("Server profile requires non-blank " + propertyName + ".");
        }
        URI uri;
        try {
            uri = URI.create(value.trim());
        } catch (IllegalArgumentException ex) {
            throw AppException.invalidConfiguration("Invalid URI syntax for " + propertyName + ".");
        }
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getHost().isBlank()) {
            throw AppException.invalidConfiguration(
                    "Server profile requires a valid https:// URI with host for " + propertyName + "."
            );
        }
    }
}
