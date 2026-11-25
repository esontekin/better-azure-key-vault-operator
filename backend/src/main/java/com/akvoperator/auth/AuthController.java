package com.akvoperator.auth;

import com.akvoperator.audit.AuditLogger;
import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.correlation.CorrelationIdHolder;
import com.akvoperator.common.dto.AuthStatusResponse;
import com.akvoperator.common.dto.BootstrapLoginRequest;
import com.akvoperator.common.dto.Permission;
import com.akvoperator.common.exception.AppException;
import com.akvoperator.security.AppPrincipal;
import com.akvoperator.security.LazyOidcClientRegistrationRepository;
import com.akvoperator.security.VaultAuthorizationService;
import com.akvoperator.vault.VaultDescriptor;
import com.akvoperator.vault.VaultRegistry;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Authentication status, local bootstrap login, and logout REST endpoints.
 * Never returns Azure credentials, client secrets, or session/bootstrap tokens.
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private static final String SESSION_COOKIE_NAME = "AKV_SESSION";

    private final AppProperties appProperties;
    private final BootstrapTokenService bootstrapTokenService;
    private final VaultAuthorizationService authorizationService;
    private final VaultRegistry vaultRegistry;
    private final AuditLogger auditLogger;
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    public AuthController(
            AppProperties appProperties,
            BootstrapTokenService bootstrapTokenService,
            VaultAuthorizationService authorizationService,
            VaultRegistry vaultRegistry,
            AuditLogger auditLogger
    ) {
        this.appProperties = appProperties;
        this.bootstrapTokenService = bootstrapTokenService;
        this.authorizationService = authorizationService;
        this.vaultRegistry = vaultRegistry;
        this.auditLogger = auditLogger;
    }

    @GetMapping("/status")
    public AuthStatusResponse getStatus(CsrfToken csrfToken) {
        if (csrfToken != null) {
            // Force CSRF token realization so the XSRF-TOKEN cookie is emitted.
            csrfToken.getToken();
        }
        Optional<AppPrincipal> principalOpt = authorizationService.getCurrentPrincipal();
        if (principalOpt.isEmpty()) {
            return buildStatusResponse(null, Map.of());
        }
        AppPrincipal principal = principalOpt.get();
        Map<String, Set<Permission>> permissionsByVault = resolvePermissionsSafely(principal);
        return buildStatusResponse(principal, permissionsByVault);
    }

    @PostMapping("/bootstrap")
    public AuthStatusResponse bootstrapLogin(
            @Valid @RequestBody BootstrapLoginRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse
    ) {
        String correlationId = CorrelationIdHolder.getOrGenerate();
        if (!appProperties.isLocalProfile()) {
            auditLogger.logDenied("anonymous", null, null, null, "BOOTSTRAP_LOGIN", "FEATURE_DISABLED", correlationId);
            throw AppException.featureDisabled("Local bootstrap authentication is disabled in server profile.");
        }

        boolean valid = bootstrapTokenService.consume(request.token());
        if (!valid) {
            auditLogger.logFailure("anonymous", null, null, null, "BOOTSTRAP_LOGIN", "BOOTSTRAP_TOKEN_INVALID", correlationId);
            throw AppException.bootstrapInvalid("Bootstrap token is invalid, expired, or has already been used.");
        }

        AppPrincipal principal = new AppPrincipal(
                "local-operator",
                "Local Operator",
                "local",
                Set.of("local-admin"),
                true
        );
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                principal,
                null,
                List.of(new SimpleGrantedAuthority("ROLE_LOCAL_OPERATOR"))
        );

        // Session fixation protection: rotate existing session ID or create a new session.
        HttpSession session = httpRequest.getSession(false);
        if (session != null) {
            httpRequest.changeSessionId();
        } else {
            session = httpRequest.getSession(true);
        }
        int idleSeconds = (int) Math.max(60L, appProperties.getLocal().getIdleTimeout().toSeconds());
        session.setMaxInactiveInterval(idleSeconds);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, httpRequest, httpResponse);

        auditLogger.logSuccess(principal.subject(), null, null, null, "BOOTSTRAP_LOGIN", correlationId);

        Map<String, Set<Permission>> permissionsByVault = resolvePermissionsSafely(principal);
        return buildStatusResponse(principal, permissionsByVault);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        String correlationId = CorrelationIdHolder.getOrGenerate();
        String subject = authorizationService.getCurrentPrincipal()
                .map(AppPrincipal::subject)
                .orElse("anonymous");

        HttpSession session = httpRequest.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();

        ResponseCookie expiredCookie = ResponseCookie.from(SESSION_COOKIE_NAME, "")
                .httpOnly(true)
                .secure(appProperties.isServerProfile())
                .sameSite(appProperties.isServerProfile() ? "Lax" : "Strict")
                .path("/")
                .maxAge(0)
                .build();
        httpResponse.addHeader(HttpHeaders.SET_COOKIE, expiredCookie.toString());

        auditLogger.logSuccess(subject, null, null, null, "LOGOUT", correlationId);
        return ResponseEntity.noContent().build();
    }

    private Map<String, Set<Permission>> resolvePermissionsSafely(AppPrincipal principal) {
        try {
            List<VaultDescriptor> vaults = vaultRegistry.listVaults();
            return authorizationService.getAllPermissionsByVault(principal, vaults);
        } catch (Exception ex) {
            log.warn("Unable to resolve vault permissions during auth status check [type={}]", ex.getClass().getName());
            return Map.of();
        }
    }

    private AuthStatusResponse buildStatusResponse(
            AppPrincipal principal,
            Map<String, Set<Permission>> permissionsByVault
    ) {
        boolean isServer = appProperties.isServerProfile();
        String profile = isServer ? "server" : "local";
        String authMode = isServer ? "OIDC" : "BOOTSTRAP_TOKEN";
        String oidcLoginUrl = isServer
                ? "/oauth2/authorization/" + LazyOidcClientRegistrationRepository.REGISTRATION_ID
                : null;
        long idleTimeoutSeconds = appProperties.getLocal().getIdleTimeout() != null
                ? appProperties.getLocal().getIdleTimeout().toSeconds()
                : 900L;

        return new AuthStatusResponse(
                principal != null,
                principal != null ? principal.subject() : null,
                principal != null ? principal.displayName() : null,
                profile,
                authMode,
                oidcLoginUrl,
                appProperties.isDeleteEnabled(),
                idleTimeoutSeconds,
                permissionsByVault != null ? permissionsByVault : Map.of()
        );
    }
}
