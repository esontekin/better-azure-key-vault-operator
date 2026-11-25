package com.akvoperator.vault;

import com.akvoperator.azure.AzureVaultUrlValidator;
import com.akvoperator.azure.OpaqueVaultIdGenerator;
import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.dto.SubscriptionDto;
import com.akvoperator.common.dto.VaultSource;
import com.akvoperator.common.exception.AppException;
import com.akvoperator.discovery.ArmDiscoveryClient;
import com.akvoperator.discovery.ArmDiscoveryResult;
import com.akvoperator.discovery.DiscoveredVault;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Combines ARM-discovered Key Vaults with administrator-configured static data-plane-only vaults,
 * validates every vault URI against {@link AzureVaultUrlValidator}, enforces {@code APP_ALLOWED_VAULT_IDS},
 * generates deterministic opaque vault IDs, and caches discovery results with {@code app.metadataTtl}.
 */
@Service
public class DefaultVaultRegistry implements VaultRegistry {

    private static final Logger log = LoggerFactory.getLogger(DefaultVaultRegistry.class);

    private final ArmDiscoveryClient armDiscoveryClient;
    private final AzureVaultUrlValidator vaultUrlValidator;
    private final AppProperties appProperties;
    private final Clock clock;

    private final Object refreshLock = new Object();
    private volatile DiscoverySnapshot cachedSnapshot;

    @Autowired
    public DefaultVaultRegistry(
            ArmDiscoveryClient armDiscoveryClient,
            AzureVaultUrlValidator vaultUrlValidator,
            AppProperties appProperties
    ) {
        this(armDiscoveryClient, vaultUrlValidator, appProperties, Clock.systemUTC());
    }

    public DefaultVaultRegistry(
            ArmDiscoveryClient armDiscoveryClient,
            AzureVaultUrlValidator vaultUrlValidator,
            AppProperties appProperties,
            Clock clock
    ) {
        this.armDiscoveryClient = armDiscoveryClient;
        this.vaultUrlValidator = vaultUrlValidator;
        this.appProperties = appProperties;
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    @PostConstruct
    public void validateStaticVaultConfiguration() {
        // Fail closed at startup if administrator-configured static vaults contain invalid URIs.
        buildStaticVaultDescriptors();
    }

    @Override
    public List<SubscriptionDto> listSubscriptions() {
        return getOrLoadSnapshot().subscriptions();
    }

    @Override
    public List<VaultDescriptor> listVaults() {
        return getOrLoadSnapshot().vaults();
    }

    @Override
    public Optional<VaultDescriptor> findByOpaqueId(String opaqueVaultId) {
        if (opaqueVaultId == null || opaqueVaultId.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(getOrLoadSnapshot().vaultsByOpaqueId().get(opaqueVaultId));
    }

    @Override
    public void refreshDiscovery() {
        synchronized (refreshLock) {
            this.cachedSnapshot = loadSnapshot();
        }
    }

    private DiscoverySnapshot getOrLoadSnapshot() {
        DiscoverySnapshot current = this.cachedSnapshot;
        if (current != null && !isExpired(current)) {
            return current;
        }
        synchronized (refreshLock) {
            current = this.cachedSnapshot;
            if (current != null && !isExpired(current)) {
                return current;
            }
            DiscoverySnapshot refreshed = loadSnapshot();
            this.cachedSnapshot = refreshed;
            return refreshed;
        }
    }

    private boolean isExpired(DiscoverySnapshot snapshot) {
        Duration ttl = appProperties != null && appProperties.getMetadataTtl() != null
                ? appProperties.getMetadataTtl()
                : Duration.ofMinutes(5);
        if (ttl.isNegative() || ttl.isZero()) {
            return true;
        }
        return Duration.between(snapshot.loadedAt(), clock.instant()).compareTo(ttl) >= 0;
    }

    private DiscoverySnapshot loadSnapshot() {
        List<VaultDescriptor> staticVaults = buildStaticVaultDescriptors();
        ArmDiscoveryResult armResult = discoverFromArm(staticVaults);

        List<VaultDescriptor> mergedVaults = new ArrayList<>();
        Set<String> seenResourceIds = new HashSet<>();
        Set<String> seenVaultUris = new HashSet<>();

        for (DiscoveredVault raw : armResult.vaults()) {
            VaultDescriptor validated = toArmVaultDescriptor(raw);
            if (validated == null) {
                continue;
            }
            String resKey = normalizeKey(validated.resourceId());
            String uriKey = normalizeKey(validated.vaultUri());
            if ((resKey != null && !seenResourceIds.add(resKey)) || !seenVaultUris.add(uriKey)) {
                continue;
            }
            mergedVaults.add(validated);
        }

        for (VaultDescriptor staticVault : staticVaults) {
            String resKey = normalizeKey(staticVault.resourceId());
            String uriKey = normalizeKey(staticVault.vaultUri());
            if ((resKey != null && seenResourceIds.contains(resKey)) || seenVaultUris.contains(uriKey)) {
                continue;
            }
            if (resKey != null) {
                seenResourceIds.add(resKey);
            }
            seenVaultUris.add(uriKey);
            mergedVaults.add(staticVault);
        }

        List<VaultDescriptor> filteredVaults = applyFilters(mergedVaults);
        filteredVaults.sort(Comparator.comparing(VaultDescriptor::name, String.CASE_INSENSITIVE_ORDER));

        Map<String, VaultDescriptor> byOpaqueId = new LinkedHashMap<>();
        for (VaultDescriptor vault : filteredVaults) {
            byOpaqueId.put(vault.opaqueId(), vault);
        }

        List<SubscriptionDto> subscriptions = buildSubscriptionList(armResult.subscriptions(), filteredVaults);
        return new DiscoverySnapshot(
                clock.instant(),
                List.copyOf(subscriptions),
                List.copyOf(filteredVaults),
                Map.copyOf(byOpaqueId)
        );
    }

    private ArmDiscoveryResult discoverFromArm(List<VaultDescriptor> staticVaults) {
        try {
            ArmDiscoveryResult result = armDiscoveryClient.discover();
            return result != null ? result : ArmDiscoveryResult.empty();
        } catch (AppException ex) {
            boolean isArmForbidden = ex.getStatus() == HttpStatus.FORBIDDEN
                    || "AZURE_PERMISSION_DENIED".equals(ex.getErrorCode());
            if (isArmForbidden && !staticVaults.isEmpty()) {
                log.warn("ARM discovery returned 403 Forbidden (ARM Reader permission may be absent); "
                        + "falling back to {} configured static vault(s) in data-plane-only mode.", staticVaults.size());
                return ArmDiscoveryResult.empty();
            }
            throw ex;
        }
    }

    private VaultDescriptor toArmVaultDescriptor(DiscoveredVault raw) {
        if (raw == null || raw.vaultUri() == null || raw.vaultUri().isBlank()) {
            return null;
        }
        final String normalizedUri;
        try {
            normalizedUri = vaultUrlValidator.validateAndNormalize(raw.vaultUri());
        } catch (AppException ex) {
            log.warn("Skipping ARM-discovered Key Vault '{}' because its vault URI failed endpoint validation ({}).",
                    raw.name(), ex.getErrorCode());
            return null;
        }

        String name = (raw.name() != null && !raw.name().isBlank())
                ? raw.name().trim()
                : vaultUrlValidator.extractVaultName(normalizedUri);
        String resourceId = (raw.resourceId() != null && !raw.resourceId().isBlank())
                ? raw.resourceId().trim()
                : normalizedUri;
        String subscriptionId = (raw.subscriptionId() != null && !raw.subscriptionId().isBlank())
                ? raw.subscriptionId().trim()
                : VaultEnvironmentClassifier.extractSubscriptionId(resourceId);
        String resourceGroup = (raw.resourceGroup() != null && !raw.resourceGroup().isBlank())
                ? raw.resourceGroup().trim()
                : VaultEnvironmentClassifier.extractResourceGroup(resourceId);
        String environment = VaultEnvironmentClassifier.inferEnvironment(raw.tags(), name);
        boolean production = VaultEnvironmentClassifier.isProduction(environment);
        String opaqueId = OpaqueVaultIdGenerator.generate(resourceId);

        return new VaultDescriptor(
                opaqueId,
                resourceId,
                name,
                subscriptionId,
                resourceGroup,
                raw.location(),
                normalizedUri,
                environment,
                production,
                VaultSource.ARM_DISCOVERY
        );
    }

    private List<VaultDescriptor> buildStaticVaultDescriptors() {
        List<AppProperties.StaticVaultConfig> configs = appProperties != null && appProperties.getStaticVaults() != null
                ? appProperties.getStaticVaults()
                : List.of();
        List<VaultDescriptor> descriptors = new ArrayList<>();

        for (AppProperties.StaticVaultConfig cfg : configs) {
            if (cfg == null) {
                continue;
            }
            final String normalizedUri;
            try {
                normalizedUri = vaultUrlValidator.validateAndNormalize(cfg.getVaultUri());
            } catch (AppException ex) {
                throw AppException.invalidConfiguration(
                        "Invalid static vault URI in application configuration: " + ex.getSafeMessage());
            }

            String name = (cfg.getName() != null && !cfg.getName().isBlank())
                    ? cfg.getName().trim()
                    : vaultUrlValidator.extractVaultName(normalizedUri);
            String resourceId = (cfg.getResourceId() != null && !cfg.getResourceId().isBlank())
                    ? cfg.getResourceId().trim()
                    : normalizedUri;
            String subscriptionId = (cfg.getSubscriptionId() != null && !cfg.getSubscriptionId().isBlank())
                    ? cfg.getSubscriptionId().trim()
                    : VaultEnvironmentClassifier.extractSubscriptionId(resourceId);
            String resourceGroup = (cfg.getResourceGroup() != null && !cfg.getResourceGroup().isBlank())
                    ? cfg.getResourceGroup().trim()
                    : VaultEnvironmentClassifier.extractResourceGroup(resourceId);

            String configuredEnv = cfg.getEnvironment();
            String environment = (configuredEnv != null && !configuredEnv.isBlank()
                    && !"unknown".equalsIgnoreCase(configuredEnv.trim()))
                    ? VaultEnvironmentClassifier.normalizeEnvironmentLabel(configuredEnv)
                    : VaultEnvironmentClassifier.inferEnvironment(Map.of(), name);
            boolean production = VaultEnvironmentClassifier.isProduction(environment);
            String opaqueId = OpaqueVaultIdGenerator.generate(resourceId);

            descriptors.add(new VaultDescriptor(
                    opaqueId,
                    resourceId,
                    name,
                    subscriptionId,
                    resourceGroup,
                    cfg.getLocation(),
                    normalizedUri,
                    environment,
                    production,
                    VaultSource.STATIC_CONFIG
            ));
        }

        return descriptors;
    }

    private List<VaultDescriptor> applyFilters(List<VaultDescriptor> vaults) {
        String configuredSubId = appProperties != null && appProperties.getAzure() != null
                ? trimToNull(appProperties.getAzure().getSubscriptionId())
                : null;
        Set<String> allowlist = buildAllowlist();

        // Fail closed in server profile if allowlist is empty
        if (appProperties != null && appProperties.isServerProfile() && allowlist.isEmpty()) {
            return new ArrayList<>();
        }

        List<VaultDescriptor> result = new ArrayList<>();
        for (VaultDescriptor vault : vaults) {
            if (configuredSubId != null
                    && vault.subscriptionId() != null
                    && !vault.subscriptionId().isBlank()
                    && !configuredSubId.equalsIgnoreCase(vault.subscriptionId())) {
                continue;
            }
            if (!allowlist.isEmpty()) {
                String resKey = normalizeKey(vault.resourceId());
                String uriKey = normalizeKey(vault.vaultUri());
                boolean allowed = (resKey != null && allowlist.contains(resKey))
                        || (uriKey != null && allowlist.contains(uriKey));
                if (!allowed) {
                    continue;
                }
            }
            result.add(vault);
        }
        return result;
    }

    private Set<String> buildAllowlist() {
        List<String> rawIds = appProperties != null && appProperties.getAllowedVaultIds() != null
                ? appProperties.getAllowedVaultIds()
                : List.of();
        Set<String> allowlist = new HashSet<>();
        for (String entry : rawIds) {
            if (entry == null || entry.isBlank()) {
                continue;
            }
            for (String part : entry.split(",")) {
                String normalized = normalizeKey(part);
                if (normalized != null) {
                    allowlist.add(normalized);
                }
            }
        }
        return allowlist;
    }

    private List<SubscriptionDto> buildSubscriptionList(
            List<SubscriptionDto> armSubscriptions,
            List<VaultDescriptor> filteredVaults
    ) {
        Set<String> activeSubIds = new HashSet<>();
        for (VaultDescriptor vault : filteredVaults) {
            if (vault.subscriptionId() != null && !vault.subscriptionId().isBlank()) {
                activeSubIds.add(vault.subscriptionId().toLowerCase(Locale.ROOT));
            }
        }

        Map<String, SubscriptionDto> byId = new LinkedHashMap<>();
        for (SubscriptionDto sub : armSubscriptions) {
            if (sub == null || sub.subscriptionId() == null || sub.subscriptionId().isBlank()) {
                continue;
            }
            String key = sub.subscriptionId().toLowerCase(Locale.ROOT);
            if (activeSubIds.contains(key)) {
                byId.putIfAbsent(key, sub);
            }
        }

        for (VaultDescriptor vault : filteredVaults) {
            if (vault.subscriptionId() != null && !vault.subscriptionId().isBlank()) {
                String key = vault.subscriptionId().toLowerCase(Locale.ROOT);
                byId.putIfAbsent(key, new SubscriptionDto(vault.subscriptionId(), vault.subscriptionId(), null));
            }
        }

        List<SubscriptionDto> sorted = new ArrayList<>(byId.values());
        sorted.sort(Comparator.comparing(
                s -> s.displayName() != null ? s.displayName() : s.subscriptionId(),
                String.CASE_INSENSITIVE_ORDER
        ));
        return sorted;
    }

    private static String normalizeKey(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim().toLowerCase(Locale.ROOT);
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private record DiscoverySnapshot(
            Instant loadedAt,
            List<SubscriptionDto> subscriptions,
            List<VaultDescriptor> vaults,
            Map<String, VaultDescriptor> vaultsByOpaqueId
    ) {
    }
}
