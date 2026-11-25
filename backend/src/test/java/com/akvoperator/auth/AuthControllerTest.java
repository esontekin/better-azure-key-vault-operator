package com.akvoperator.auth;

import com.akvoperator.audit.AuditLogger;
import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.dto.AuthStatusResponse;
import com.akvoperator.common.dto.BootstrapLoginRequest;
import com.akvoperator.common.dto.Permission;
import com.akvoperator.common.dto.VaultSource;
import com.akvoperator.common.exception.AppException;
import com.akvoperator.security.DefaultVaultAuthorizationService;
import com.akvoperator.security.RoleMappingResolver;
import com.akvoperator.vault.VaultDescriptor;
import com.akvoperator.vault.VaultRegistry;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthControllerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void unauthenticatedStatusDoesNotCallAzureRegistry() {
        AppProperties props = localProps();
        VaultRegistry registry = mock(VaultRegistry.class);
        AuditLogger auditLogger = mock(AuditLogger.class);
        BootstrapTokenService tokenService = new BootstrapTokenService(props);
        DefaultVaultAuthorizationService authz = new DefaultVaultAuthorizationService(
                props, registry, new RoleMappingResolver(props, objectMapper), auditLogger
        );
        AuthController controller = new AuthController(props, tokenService, authz, registry, auditLogger);

        AuthStatusResponse status = controller.getStatus(null);
        assertThat(status.authenticated()).isFalse();
        assertThat(status.profile()).isEqualTo("local");
        assertThat(status.authMode()).isEqualTo("BOOTSTRAP_TOKEN");
        assertThat(status.permissionsByVault()).isEmpty();
        verify(registry, never()).listVaults();
    }

    @Test
    void bootstrapLoginRotatesSessionIdSetsIdleTimeoutAndLogoutInvalidatesSession() {
        AppProperties props = localProps();
        props.getLocal().setIdleTimeout(Duration.ofMinutes(15));
        VaultRegistry registry = mock(VaultRegistry.class);
        VaultDescriptor vault = new VaultDescriptor(
                "vault_local_1234",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/kv-1",
                "kv-1", "sub-1", "rg-1", "westeurope", "https://kv-1.vault.azure.net",
                "dev", false, VaultSource.ARM_DISCOVERY
        );
        when(registry.listVaults()).thenReturn(List.of(vault));

        AuditLogger auditLogger = mock(AuditLogger.class);
        BootstrapTokenService tokenService = new BootstrapTokenService(props);
        String token = tokenService.regenerateToken();

        DefaultVaultAuthorizationService authz = new DefaultVaultAuthorizationService(
                props, registry, new RoleMappingResolver(props, objectMapper), auditLogger
        );
        AuthController controller = new AuthController(props, tokenService, authz, registry, auditLogger);

        // Pre-existing session to verify session fixation protection (session ID rotation)
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/v1/auth/bootstrap");
        MockHttpSession existingSession = new MockHttpSession();
        String originalSessionId = existingSession.getId();
        req.setSession(existingSession);
        MockHttpServletResponse res = new MockHttpServletResponse();

        AuthStatusResponse loginResponse = controller.bootstrapLogin(new BootstrapLoginRequest(token), req, res);
        assertThat(loginResponse.authenticated()).isTrue();
        assertThat(loginResponse.subject()).isEqualTo("local-operator");
        assertThat(loginResponse.permissionsByVault()).containsKey("vault_local_1234");
        assertThat(loginResponse.permissionsByVault().get("vault_local_1234"))
                .contains(Permission.SECRET_DELETE_RECOVER);

        HttpSession rotatedSession = req.getSession(false);
        assertThat(rotatedSession).isNotNull();
        assertThat(rotatedSession.getId()).isNotEqualTo(originalSessionId);
        assertThat(rotatedSession.getMaxInactiveInterval()).isEqualTo(900);

        // Replay must fail with 401
        assertThatThrownBy(() -> controller.bootstrapLogin(new BootstrapLoginRequest(token), req, new MockHttpServletResponse()))
                .isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
                    assertThat(appEx.getErrorCode()).isEqualTo("BOOTSTRAP_TOKEN_INVALID");
                });

        // Logout invalidates session and expires AKV_SESSION cookie
        MockHttpServletResponse logoutRes = new MockHttpServletResponse();
        var logoutEntity = controller.logout(req, logoutRes);
        assertThat(logoutEntity.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(existingSession.isInvalid()).isTrue();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(logoutRes.getHeader(HttpHeaders.SET_COOKIE))
                .contains("AKV_SESSION=")
                .contains("Max-Age=0")
                .contains("HttpOnly");
    }

    @Test
    void bootstrapEndpointIsDisabledInServerProfile() {
        AppProperties props = new AppProperties();
        props.setProfile("server");
        props.getLocal().setBootstrapTokenAutoPrint(false);

        VaultRegistry registry = mock(VaultRegistry.class);
        AuditLogger auditLogger = mock(AuditLogger.class);
        BootstrapTokenService tokenService = new BootstrapTokenService(props);
        DefaultVaultAuthorizationService authz = new DefaultVaultAuthorizationService(
                props, registry, new RoleMappingResolver(props, objectMapper), auditLogger
        );
        AuthController controller = new AuthController(props, tokenService, authz, registry, auditLogger);

        assertThatThrownBy(() -> controller.bootstrapLogin(
                new BootstrapLoginRequest("12345678901234567890"),
                new MockHttpServletRequest("POST", "/api/v1/auth/bootstrap"),
                new MockHttpServletResponse()
        ))
                .isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getStatus()).isEqualTo(HttpStatus.FORBIDDEN);
                    assertThat(appEx.getErrorCode()).isEqualTo("FEATURE_DISABLED");
                });
    }

    private static AppProperties localProps() {
        AppProperties props = new AppProperties();
        props.setProfile("local");
        props.getLocal().setBootstrapTokenAutoPrint(false);
        return props;
    }
}
