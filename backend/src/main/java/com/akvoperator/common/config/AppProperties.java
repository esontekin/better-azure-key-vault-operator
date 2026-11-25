package com.akvoperator.common.config;

import com.akvoperator.common.dto.Role;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "app")
public class AppProperties {

    private String profile = "local";
    private boolean deleteEnabled = false;
    private Duration metadataTtl = Duration.ofMinutes(5);
    private List<String> allowedVaultIds = new ArrayList<>();
    private List<StaticVaultConfig> staticVaults = new ArrayList<>();
    private AzureProperties azure = new AzureProperties();
    private LocalProperties local = new LocalProperties();
    private ServerProperties server = new ServerProperties();
    private CacheProperties cache = new CacheProperties();
    private SecurityProperties security = new SecurityProperties();

    public boolean isLocalProfile() {
        return "local".equalsIgnoreCase(profile);
    }

    public boolean isServerProfile() {
        return "server".equalsIgnoreCase(profile);
    }

    public String getProfile() {
        return profile;
    }

    public void setProfile(String profile) {
        this.profile = profile;
    }

    public boolean isDeleteEnabled() {
        return deleteEnabled;
    }

    public void setDeleteEnabled(boolean deleteEnabled) {
        this.deleteEnabled = deleteEnabled;
    }

    public Duration getMetadataTtl() {
        return metadataTtl;
    }

    public void setMetadataTtl(Duration metadataTtl) {
        this.metadataTtl = metadataTtl;
    }

    public List<String> getAllowedVaultIds() {
        return allowedVaultIds;
    }

    public void setAllowedVaultIds(List<String> allowedVaultIds) {
        this.allowedVaultIds = allowedVaultIds != null ? allowedVaultIds : new ArrayList<>();
    }

    public List<StaticVaultConfig> getStaticVaults() {
        return staticVaults;
    }

    public void setStaticVaults(List<StaticVaultConfig> staticVaults) {
        this.staticVaults = staticVaults != null ? staticVaults : new ArrayList<>();
    }

    public AzureProperties getAzure() {
        return azure;
    }

    public void setAzure(AzureProperties azure) {
        this.azure = azure;
    }

    public LocalProperties getLocal() {
        return local;
    }

    public void setLocal(LocalProperties local) {
        this.local = local;
    }

    public ServerProperties getServer() {
        return server;
    }

    public void setServer(ServerProperties server) {
        this.server = server;
    }

    public CacheProperties getCache() {
        return cache;
    }

    public void setCache(CacheProperties cache) {
        this.cache = cache;
    }

    public SecurityProperties getSecurity() {
        return security;
    }

    public void setSecurity(SecurityProperties security) {
        this.security = security;
    }

    public static class AzureProperties {
        private String tenantId = "";
        private String clientId = "";
        private String clientSecret = "";
        private String clientSecretFile = "";
        private String subscriptionId = "";
        private boolean publicCloudOnly = true;
        private Duration connectTimeout = Duration.ofSeconds(10);
        private Duration responseTimeout = Duration.ofSeconds(30);
        private int maxReadRetries = 3;

        public String getTenantId() {
            return tenantId;
        }

        public void setTenantId(String tenantId) {
            this.tenantId = tenantId;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getClientSecretFile() {
            return clientSecretFile;
        }

        public void setClientSecretFile(String clientSecretFile) {
            this.clientSecretFile = clientSecretFile;
        }

        public String getSubscriptionId() {
            return subscriptionId;
        }

        public void setSubscriptionId(String subscriptionId) {
            this.subscriptionId = subscriptionId;
        }

        public boolean isPublicCloudOnly() {
            return publicCloudOnly;
        }

        public void setPublicCloudOnly(boolean publicCloudOnly) {
            this.publicCloudOnly = publicCloudOnly;
        }

        public Duration getConnectTimeout() {
            return connectTimeout;
        }

        public void setConnectTimeout(Duration connectTimeout) {
            this.connectTimeout = connectTimeout;
        }

        public Duration getResponseTimeout() {
            return responseTimeout;
        }

        public void setResponseTimeout(Duration responseTimeout) {
            this.responseTimeout = responseTimeout;
        }

        public int getMaxReadRetries() {
            return maxReadRetries;
        }

        public void setMaxReadRetries(int maxReadRetries) {
            this.maxReadRetries = maxReadRetries;
        }

        @Override
        public String toString() {
            return "AzureProperties{tenantId='" + tenantId + "', clientId='" + clientId
                    + "', clientSecret='[REDACTED]', clientSecretFile='" + clientSecretFile
                    + "', subscriptionId='" + subscriptionId + "'}";
        }
    }

    public static class StaticVaultConfig {
        private String resourceId;
        private String vaultUri;
        private String name;
        private String subscriptionId;
        private String resourceGroup;
        private String location;
        private String environment = "unknown";

        public String getResourceId() {
            return resourceId;
        }

        public void setResourceId(String resourceId) {
            this.resourceId = resourceId;
        }

        public String getVaultUri() {
            return vaultUri;
        }

        public void setVaultUri(String vaultUri) {
            this.vaultUri = vaultUri;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getSubscriptionId() {
            return subscriptionId;
        }

        public void setSubscriptionId(String subscriptionId) {
            this.subscriptionId = subscriptionId;
        }

        public String getResourceGroup() {
            return resourceGroup;
        }

        public void setResourceGroup(String resourceGroup) {
            this.resourceGroup = resourceGroup;
        }

        public String getLocation() {
            return location;
        }

        public void setLocation(String location) {
            this.location = location;
        }

        public String getEnvironment() {
            return environment;
        }

        public void setEnvironment(String environment) {
            this.environment = environment;
        }
    }

    public static class LocalProperties {
        private Duration bootstrapTokenTtl = Duration.ofMinutes(10);
        private Duration idleTimeout = Duration.ofMinutes(15);
        private boolean allowContainerBind = false;
        private boolean bootstrapTokenAutoPrint = true;
        private List<String> allowedHosts = new ArrayList<>(List.of("localhost", "127.0.0.1", "[::1]"));

        public Duration getBootstrapTokenTtl() {
            return bootstrapTokenTtl;
        }

        public void setBootstrapTokenTtl(Duration bootstrapTokenTtl) {
            this.bootstrapTokenTtl = bootstrapTokenTtl;
        }

        public Duration getIdleTimeout() {
            return idleTimeout;
        }

        public void setIdleTimeout(Duration idleTimeout) {
            this.idleTimeout = idleTimeout;
        }

        public boolean isAllowContainerBind() {
            return allowContainerBind;
        }

        public void setAllowContainerBind(boolean allowContainerBind) {
            this.allowContainerBind = allowContainerBind;
        }

        public boolean isBootstrapTokenAutoPrint() {
            return bootstrapTokenAutoPrint;
        }

        public void setBootstrapTokenAutoPrint(boolean bootstrapTokenAutoPrint) {
            this.bootstrapTokenAutoPrint = bootstrapTokenAutoPrint;
        }

        public List<String> getAllowedHosts() {
            return allowedHosts;
        }

        public void setAllowedHosts(List<String> allowedHosts) {
            this.allowedHosts = allowedHosts != null ? allowedHosts : new ArrayList<>();
        }
    }

    public static class ServerProperties {
        private String publicBaseUrl = "";
        private List<String> trustedProxies = new ArrayList<>();
        private String oidcIssuerUri = "";
        private String oidcClientId = "";
        private String oidcClientSecret = "";
        private String roleMappingsJson = "";
        private List<RoleMappingConfig> roleMappings = new ArrayList<>();
        private String groupsClaim = "groups";
        private String subjectClaim = "sub";

        public String getPublicBaseUrl() {
            return publicBaseUrl;
        }

        public void setPublicBaseUrl(String publicBaseUrl) {
            this.publicBaseUrl = publicBaseUrl;
        }

        public List<String> getTrustedProxies() {
            return trustedProxies;
        }

        public void setTrustedProxies(List<String> trustedProxies) {
            this.trustedProxies = trustedProxies != null ? trustedProxies : new ArrayList<>();
        }

        public String getOidcIssuerUri() {
            return oidcIssuerUri;
        }

        public void setOidcIssuerUri(String oidcIssuerUri) {
            this.oidcIssuerUri = oidcIssuerUri;
        }

        public String getOidcClientId() {
            return oidcClientId;
        }

        public void setOidcClientId(String oidcClientId) {
            this.oidcClientId = oidcClientId;
        }

        public String getOidcClientSecret() {
            return oidcClientSecret;
        }

        public void setOidcClientSecret(String oidcClientSecret) {
            this.oidcClientSecret = oidcClientSecret;
        }

        public String getRoleMappingsJson() {
            return roleMappingsJson;
        }

        public void setRoleMappingsJson(String roleMappingsJson) {
            this.roleMappingsJson = roleMappingsJson;
        }

        public List<RoleMappingConfig> getRoleMappings() {
            return roleMappings;
        }

        public void setRoleMappings(List<RoleMappingConfig> roleMappings) {
            this.roleMappings = roleMappings != null ? roleMappings : new ArrayList<>();
        }

        public String getGroupsClaim() {
            return groupsClaim;
        }

        public void setGroupsClaim(String groupsClaim) {
            this.groupsClaim = groupsClaim;
        }

        public String getSubjectClaim() {
            return subjectClaim;
        }

        public void setSubjectClaim(String subjectClaim) {
            this.subjectClaim = subjectClaim;
        }

        @Override
        public String toString() {
            return "ServerProperties{publicBaseUrl='" + publicBaseUrl + "', oidcIssuerUri='" + oidcIssuerUri
                    + "', oidcClientId='" + oidcClientId + "', oidcClientSecret='[REDACTED]'}";
        }
    }

    public static class RoleMappingConfig {
        private String subject;
        private String group;
        private String vaultResourceId;
        private Role role;

        public String getSubject() {
            return subject;
        }

        public void setSubject(String subject) {
            this.subject = subject;
        }

        public String getGroup() {
            return group;
        }

        public void setGroup(String group) {
            this.group = group;
        }

        public String getVaultResourceId() {
            return vaultResourceId;
        }

        public void setVaultResourceId(String vaultResourceId) {
            this.vaultResourceId = vaultResourceId;
        }

        public Role getRole() {
            return role;
        }

        public void setRole(Role role) {
            this.role = role;
        }
    }

    public static class CacheProperties {
        private int maxVaultEntries = 200;

        public int getMaxVaultEntries() {
            return maxVaultEntries;
        }

        public void setMaxVaultEntries(int maxVaultEntries) {
            this.maxVaultEntries = maxVaultEntries;
        }
    }

    public static class SecurityProperties {
        private int rateLimitPerMinute = 240;
        private int bootstrapRateLimitPerMinute = 10;
        private int maxRequestBodyBytes = 131072;

        public int getRateLimitPerMinute() {
            return rateLimitPerMinute;
        }

        public void setRateLimitPerMinute(int rateLimitPerMinute) {
            this.rateLimitPerMinute = rateLimitPerMinute;
        }

        public int getBootstrapRateLimitPerMinute() {
            return bootstrapRateLimitPerMinute;
        }

        public void setBootstrapRateLimitPerMinute(int bootstrapRateLimitPerMinute) {
            this.bootstrapRateLimitPerMinute = bootstrapRateLimitPerMinute;
        }

        public int getMaxRequestBodyBytes() {
            return maxRequestBodyBytes;
        }

        public void setMaxRequestBodyBytes(int maxRequestBodyBytes) {
            this.maxRequestBodyBytes = maxRequestBodyBytes;
        }
    }
}
