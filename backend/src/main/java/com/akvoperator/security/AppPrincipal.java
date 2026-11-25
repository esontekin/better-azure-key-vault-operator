package com.akvoperator.security;

import java.io.Serializable;
import java.util.Set;

public record AppPrincipal(
        String subject,
        String displayName,
        String issuer,
        Set<String> groups,
        boolean localOperator
) implements Serializable {
    public AppPrincipal {
        groups = groups == null ? Set.of() : Set.copyOf(groups);
    }
}
