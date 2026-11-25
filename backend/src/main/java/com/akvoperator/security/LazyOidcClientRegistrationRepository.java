package com.akvoperator.security;

import com.akvoperator.common.config.AppProperties;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;

/**
 * Lazily resolves OIDC discovery metadata from the configured issuer URI (Ory Hydra / standard OIDC)
 * on first authentication attempt while configuration presence/validity is still strictly validated at startup.
 */
public class LazyOidcClientRegistrationRepository implements ClientRegistrationRepository {

    public static final String REGISTRATION_ID = "oidc";

    private final AppProperties appProperties;
    private volatile ClientRegistration cachedRegistration;

    public LazyOidcClientRegistrationRepository(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        if (!REGISTRATION_ID.equals(registrationId)) {
            return null;
        }
        ClientRegistration existing = cachedRegistration;
        if (existing != null) {
            return existing;
        }
        synchronized (this) {
            if (cachedRegistration == null) {
                AppProperties.ServerProperties server = appProperties.getServer();
                cachedRegistration = ClientRegistrations.fromOidcIssuerLocation(server.getOidcIssuerUri().trim())
                        .registrationId(REGISTRATION_ID)
                        .clientId(server.getOidcClientId().trim())
                        .clientSecret(server.getOidcClientSecret())
                        .scope("openid", "profile", "email")
                        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                        .build();
            }
            return cachedRegistration;
        }
    }
}
