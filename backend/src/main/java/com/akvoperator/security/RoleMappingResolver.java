package com.akvoperator.security;

import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.dto.Permission;
import com.akvoperator.common.dto.Role;
import com.akvoperator.common.exception.AppException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Resolves explicit user/group -> vaultResourceId -> Role mappings for server profile.
 * Deny-by-default: unmapped users or vaults receive an empty permission set.
 */
@Component
public class RoleMappingResolver {

    private final List<NormalizedMapping> mappings;

    public RoleMappingResolver(AppProperties appProperties, ObjectMapper objectMapper) {
        this.mappings = parseMappings(appProperties.getServer(), objectMapper);
    }

    public Set<Permission> resolvePermissions(AppPrincipal principal, String vaultResourceId) {
        if (principal == null || vaultResourceId == null || vaultResourceId.isBlank() || mappings.isEmpty()) {
            return Set.of();
        }
        String normalizedVaultId = normalizeResourceId(vaultResourceId);
        EnumSet<Permission> permissions = EnumSet.noneOf(Permission.class);

        for (NormalizedMapping mapping : mappings) {
            if (!mapping.vaultResourceId().equals(normalizedVaultId)) {
                continue;
            }
            if (matchesPrincipal(mapping, principal)) {
                permissions.addAll(mapping.role().permissions());
            }
        }
        return permissions.isEmpty() ? Set.of() : Set.copyOf(permissions);
    }

    private boolean matchesPrincipal(NormalizedMapping mapping, AppPrincipal principal) {
        boolean hasSubject = mapping.subject() != null;
        boolean hasGroup = mapping.group() != null;
        if (!hasSubject && !hasGroup) {
            return false;
        }
        if (hasSubject && !mapping.subject().equals(principal.subject())) {
            return false;
        }
        if (hasGroup && !principal.groups().contains(mapping.group())) {
            return false;
        }
        return true;
    }

    private static List<NormalizedMapping> parseMappings(
            AppProperties.ServerProperties serverProperties,
            ObjectMapper objectMapper
    ) {
        List<AppProperties.RoleMappingConfig> combined = new ArrayList<>();
        if (serverProperties.getRoleMappings() != null) {
            combined.addAll(serverProperties.getRoleMappings());
        }
        String json = serverProperties.getRoleMappingsJson();
        if (json != null && !json.isBlank()) {
            try {
                List<AppProperties.RoleMappingConfig> fromJson = objectMapper.readValue(
                        json,
                        new TypeReference<List<AppProperties.RoleMappingConfig>>() {
                        }
                );
                if (fromJson != null) {
                    combined.addAll(fromJson);
                }
            } catch (Exception ex) {
                throw AppException.invalidConfiguration("Failed to parse APP_SERVER_ROLE_MAPPINGS_JSON.");
            }
        }

        List<NormalizedMapping> normalized = new ArrayList<>();
        for (AppProperties.RoleMappingConfig config : combined) {
            if (config == null || config.getRole() == null
                    || config.getVaultResourceId() == null || config.getVaultResourceId().isBlank()) {
                continue;
            }
            String subject = config.getSubject() != null && !config.getSubject().isBlank()
                    ? config.getSubject().trim()
                    : null;
            String group = config.getGroup() != null && !config.getGroup().isBlank()
                    ? config.getGroup().trim()
                    : null;
            if (subject == null && group == null) {
                continue;
            }
            normalized.add(new NormalizedMapping(
                    subject,
                    group,
                    normalizeResourceId(config.getVaultResourceId()),
                    config.getRole()
            ));
        }
        return List.copyOf(normalized);
    }

    static String normalizeResourceId(String resourceId) {
        return resourceId.trim().toLowerCase(Locale.ROOT);
    }

    private record NormalizedMapping(
            String subject,
            String group,
            String vaultResourceId,
            Role role
    ) {
    }
}
