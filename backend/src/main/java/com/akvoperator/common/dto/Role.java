package com.akvoperator.common.dto;

import java.util.EnumSet;
import java.util.Set;

public enum Role {
    VIEWER(EnumSet.of(Permission.SECRET_LIST)),
    OPERATOR(EnumSet.of(Permission.SECRET_LIST, Permission.SECRET_REVEAL)),
    MANAGER(EnumSet.of(Permission.SECRET_LIST, Permission.SECRET_REVEAL, Permission.SECRET_WRITE)),
    ADMIN(EnumSet.of(
            Permission.SECRET_LIST,
            Permission.SECRET_REVEAL,
            Permission.SECRET_WRITE,
            Permission.SECRET_DELETE_RECOVER
    ));

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        this.permissions = Set.copyOf(permissions);
    }

    public Set<Permission> permissions() {
        return permissions;
    }
}
