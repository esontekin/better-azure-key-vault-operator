package com.akvoperator.common.dto;

import java.util.Map;
import java.util.Set;

public record AuthStatusResponse(
        boolean authenticated,
        String subject,
        String displayName,
        String profile,
        String authMode,
        String oidcLoginUrl,
        boolean deleteEnabled,
        long idleTimeoutSeconds,
        Map<String, Set<Permission>> permissionsByVault
) {
}
