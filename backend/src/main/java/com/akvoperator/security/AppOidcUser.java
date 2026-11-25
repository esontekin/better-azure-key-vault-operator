package com.akvoperator.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

import java.io.Serial;
import java.util.Collection;

/**
 * OIDC user principal wrapper carrying the verified application {@link AppPrincipal}.
 */
public class AppOidcUser extends DefaultOidcUser {

    @Serial
    private static final long serialVersionUID = 1L;

    private final AppPrincipal appPrincipal;

    public AppOidcUser(
            Collection<? extends GrantedAuthority> authorities,
            OidcIdToken idToken,
            OidcUserInfo userInfo,
            AppPrincipal appPrincipal
    ) {
        super(authorities, idToken, userInfo);
        this.appPrincipal = appPrincipal;
    }

    public AppPrincipal toAppPrincipal() {
        return appPrincipal;
    }

    @Override
    public String getName() {
        return appPrincipal.subject();
    }
}
