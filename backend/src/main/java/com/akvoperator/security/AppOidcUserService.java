package com.akvoperator.security;

import com.akvoperator.audit.AuditLogger;
import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.correlation.CorrelationIdHolder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.net.URL;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Custom OIDC user service that verifies issuer and subject claims and extracts groups into {@link AppPrincipal}.
 */
public class AppOidcUserService extends OidcUserService {

    private final AppProperties appProperties;
    private final AuditLogger auditLogger;

    public AppOidcUserService(AppProperties appProperties, AuditLogger auditLogger) {
        this.appProperties = appProperties;
        this.auditLogger = auditLogger;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser delegateUser = super.loadUser(userRequest);
        return buildAppOidcUser(delegateUser);
    }

    AppOidcUser buildAppOidcUser(OidcUser delegateUser) {
        String correlationId = CorrelationIdHolder.getOrGenerate();
        String configuredIssuer = normalizeIssuer(appProperties.getServer().getOidcIssuerUri());
        URL tokenIssuerUrl = delegateUser.getIdToken() != null ? delegateUser.getIdToken().getIssuer() : null;
        String tokenIssuer = tokenIssuerUrl != null ? normalizeIssuer(tokenIssuerUrl.toString()) : "";

        if (configuredIssuer.isEmpty() || !configuredIssuer.equals(tokenIssuer)) {
            auditLogger.logFailure("anonymous", null, null, null, "OIDC_LOGIN", "OIDC_ISSUER_MISMATCH", correlationId);
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_issuer", "OIDC token issuer does not match configured issuer.", null)
            );
        }

        String subjectClaim = appProperties.getServer().getSubjectClaim();
        if (subjectClaim == null || subjectClaim.isBlank()) {
            subjectClaim = "sub";
        }
        String subject = extractStringClaim(delegateUser, subjectClaim);
        if (subject == null || subject.isBlank()) {
            auditLogger.logFailure("anonymous", null, null, null, "OIDC_LOGIN", "OIDC_SUBJECT_MISSING", correlationId);
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_subject", "OIDC token does not contain a valid subject claim.", null)
            );
        }

        String displayName = firstNonBlank(
                extractStringClaim(delegateUser, "name"),
                extractStringClaim(delegateUser, "preferred_username"),
                extractStringClaim(delegateUser, "email"),
                subject
        );

        String groupsClaim = appProperties.getServer().getGroupsClaim();
        if (groupsClaim == null || groupsClaim.isBlank()) {
            groupsClaim = "groups";
        }
        Set<String> groups = extractGroups(delegateUser, groupsClaim);

        AppPrincipal appPrincipal = new AppPrincipal(
                subject.trim(),
                displayName.trim(),
                tokenIssuer,
                groups,
                false
        );
        auditLogger.logSuccess(appPrincipal.subject(), null, null, null, "OIDC_LOGIN", correlationId);
        return new AppOidcUser(
                delegateUser.getAuthorities(),
                delegateUser.getIdToken(),
                delegateUser.getUserInfo(),
                appPrincipal
        );
    }

    private static String extractStringClaim(OidcUser user, String claimName) {
        Object value = null;
        if (user.getIdToken() != null && user.getIdToken().getClaims() != null) {
            value = user.getIdToken().getClaims().get(claimName);
        }
        if (value == null && user.getUserInfo() != null && user.getUserInfo().getClaims() != null) {
            value = user.getUserInfo().getClaims().get(claimName);
        }
        if (value instanceof String str && !str.isBlank()) {
            return str;
        }
        return null;
    }

    private static Set<String> extractGroups(OidcUser user, String claimName) {
        Set<String> groups = new LinkedHashSet<>();
        if (user.getIdToken() != null && user.getIdToken().getClaims() != null) {
            addClaimValues(groups, user.getIdToken().getClaims().get(claimName));
        }
        if (user.getUserInfo() != null && user.getUserInfo().getClaims() != null) {
            addClaimValues(groups, user.getUserInfo().getClaims().get(claimName));
        }
        return Set.copyOf(groups);
    }

    private static void addClaimValues(Set<String> target, Object claimValue) {
        if (claimValue instanceof Collection<?> collection) {
            for (Object item : collection) {
                if (item != null) {
                    String s = item.toString().trim();
                    if (!s.isEmpty()) {
                        target.add(s);
                    }
                }
            }
        } else if (claimValue instanceof String str && !str.isBlank()) {
            target.add(str.trim());
        }
    }

    private static String normalizeIssuer(String issuer) {
        if (issuer == null) {
            return "";
        }
        String trimmed = issuer.trim();
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    private static String firstNonBlank(String... values) {
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return "";
    }
}
