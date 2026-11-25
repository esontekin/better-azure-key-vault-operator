package com.akvoperator.security;

import com.akvoperator.audit.AuditLogger;
import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.correlation.CorrelationIdHolder;
import jakarta.servlet.SessionCookieConfig;
import jakarta.servlet.http.HttpSession;
import org.apache.tomcat.util.http.Rfc6265CookieProcessor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

/**
 * Central Spring Security 6 configuration enforcing same-origin, CSRF, strict headers,
 * Host/Origin validation, trusted proxy boundaries, session fixation protection, and profile-specific auth.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    public static final String CSP_POLICY =
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                    + "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "
                    + "frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'";

    @Bean
    @ConditionalOnProperty(name = "app.profile", havingValue = "server")
    public ClientRegistrationRepository clientRegistrationRepository(AppProperties appProperties) {
        return new LazyOidcClientRegistrationRepository(appProperties);
    }

    @Bean
    public ServletContextInitializer sessionCookieConfigInitializer(AppProperties appProperties) {
        return servletContext -> {
            SessionCookieConfig cookieConfig = servletContext.getSessionCookieConfig();
            cookieConfig.setHttpOnly(true);
            if (appProperties.isServerProfile()) {
                cookieConfig.setSecure(true);
                cookieConfig.setAttribute("SameSite", "Lax");
            }
        };
    }

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> tomcatSessionCookieCustomizer(
            AppProperties appProperties
    ) {
        return factory -> {
            if (appProperties.isServerProfile()) {
                factory.addContextCustomizers(context -> {
                    Rfc6265CookieProcessor cookieProcessor = new Rfc6265CookieProcessor();
                    cookieProcessor.setSameSiteCookies("Lax");
                    context.setCookieProcessor(cookieProcessor);
                });
            }
        };
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            AppProperties appProperties,
            ProblemDetailResponseWriter problemWriter,
            AuditLogger auditLogger,
            ObjectProvider<ClientRegistrationRepository> clientRegistrationRepositoryProvider
    ) throws Exception {

        // Instantiate security filters directly (not as @Component) so they execute once, in exact order.
        CorrelationIdFilter correlationIdFilter = new CorrelationIdFilter();
        TrustedProxyForwardedHeaderFilter trustedProxyFilter = new TrustedProxyForwardedHeaderFilter(appProperties);
        LocalLoopbackEnforcementFilter localLoopbackFilter =
                new LocalLoopbackEnforcementFilter(appProperties, problemWriter, auditLogger);
        HostOriginValidationFilter hostOriginValidationFilter =
                new HostOriginValidationFilter(appProperties, problemWriter, auditLogger);
        MaxRequestBodySizeFilter maxRequestBodySizeFilter =
                new MaxRequestBodySizeFilter(appProperties, problemWriter);
        RateLimitFilter rateLimitFilter =
                new RateLimitFilter(appProperties, problemWriter, auditLogger);
        NoStoreSensitiveResponseFilter noStoreSensitiveResponseFilter = new NoStoreSensitiveResponseFilter();

        http.addFilterBefore(correlationIdFilter, WebAsyncManagerIntegrationFilter.class);
        http.addFilterBefore(trustedProxyFilter, WebAsyncManagerIntegrationFilter.class);
        http.addFilterBefore(localLoopbackFilter, WebAsyncManagerIntegrationFilter.class);
        http.addFilterBefore(hostOriginValidationFilter, WebAsyncManagerIntegrationFilter.class);
        http.addFilterBefore(maxRequestBodySizeFilter, WebAsyncManagerIntegrationFilter.class);
        http.addFilterBefore(rateLimitFilter, WebAsyncManagerIntegrationFilter.class);
        http.addFilterBefore(noStoreSensitiveResponseFilter, WebAsyncManagerIntegrationFilter.class);

        http.cors(AbstractHttpConfigurer::disable);
        http.httpBasic(AbstractHttpConfigurer::disable);
        http.formLogin(AbstractHttpConfigurer::disable);
        http.logout(AbstractHttpConfigurer::disable);

        CookieCsrfTokenRepository csrfRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        csrfRepository.setCookiePath("/");
        csrfRepository.setCookieCustomizer(cookie -> {
            cookie.sameSite(appProperties.isServerProfile() ? "Lax" : "Strict");
            if (appProperties.isServerProfile()) {
                cookie.secure(true);
            }
        });
        CsrfTokenRequestAttributeHandler csrfRequestHandler = new CsrfTokenRequestAttributeHandler();
        // Opt out of deferred CSRF loading so Angular receives XSRF-TOKEN cookie immediately on status/GET requests.
        csrfRequestHandler.setCsrfRequestAttributeName(null);

        http.csrf(csrf -> csrf
                .csrfTokenRepository(csrfRepository)
                .csrfTokenRequestHandler(csrfRequestHandler)
        );

        http.sessionManagement(session -> session
                .sessionFixation(SessionManagementConfigurer.SessionFixationConfigurer::changeSessionId)
        );

        http.headers(headers -> {
            headers.contentSecurityPolicy(csp -> csp.policyDirectives(CSP_POLICY));
            headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::deny);
            headers.contentTypeOptions(Customizer.withDefaults());
            headers.referrerPolicy(referrer ->
                    referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER));
            headers.cacheControl(HeadersConfigurer.CacheControlConfig::disable);
            if (appProperties.isServerProfile()) {
                headers.httpStrictTransportSecurity(hsts -> hsts
                        .includeSubDomains(true)
                        .maxAgeInSeconds(31536000));
            } else {
                headers.httpStrictTransportSecurity(HeadersConfigurer.HstsConfig::disable);
            }
        });

        AuthenticationEntryPoint apiAuthenticationEntryPoint = (request, response, authException) -> {
            if (request.getRequestURI() != null && request.getRequestURI().startsWith("/api/")) {
                auditLogger.logDenied(
                        "anonymous",
                        null,
                        null,
                        null,
                        "API_AUTH_CHECK",
                        "AUTH_REQUIRED",
                        CorrelationIdHolder.getOrGenerate()
                );
            }
            problemWriter.write(
                    request,
                    response,
                    HttpStatus.UNAUTHORIZED,
                    "AUTH_REQUIRED",
                    "Authentication is required to access this resource."
            );
        };

        AccessDeniedHandler apiAccessDeniedHandler = (request, response, accessDeniedException) -> {
            String errorCode = accessDeniedException instanceof CsrfException
                    ? "CSRF_TOKEN_INVALID"
                    : "ACCESS_DENIED";
            String detail = accessDeniedException instanceof CsrfException
                    ? "Invalid or missing CSRF token."
                    : "You do not have permission to perform this action.";
            auditLogger.logDenied(
                    resolveCurrentSubject(),
                    null,
                    null,
                    null,
                    "HTTP_ACCESS",
                    errorCode,
                    CorrelationIdHolder.getOrGenerate()
            );
            problemWriter.write(request, response, HttpStatus.FORBIDDEN, errorCode, detail);
        };

        http.exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(apiAuthenticationEntryPoint)
                .accessDeniedHandler(apiAccessDeniedHandler)
        );

        http.authorizeHttpRequests(auth -> {
            auth.requestMatchers(HttpMethod.GET,
                    "/",
                    "/index.html",
                    "/favicon.ico",
                    "/assets/**",
                    "/*.js",
                    "/*.css",
                    "/*.ico",
                    "/*.png",
                    "/*.svg",
                    "/*.woff2",
                    "/*.json",
                    "/login",
                    "/vaults",
                    "/vaults/**",
                    "/deleted-secrets",
                    "/settings"
            ).permitAll();
            auth.requestMatchers(HttpMethod.GET, "/actuator/health", "/actuator/health/**").permitAll();
            auth.requestMatchers(HttpMethod.GET, "/api/v1/auth/status").permitAll();
            auth.requestMatchers(HttpMethod.POST, "/api/v1/auth/bootstrap").permitAll();
            if (appProperties.isServerProfile()) {
                auth.requestMatchers("/oauth2/**", "/login/oauth2/**").permitAll();
            }
            auth.requestMatchers("/api/**").authenticated();
            auth.anyRequest().denyAll();
        });

        if (appProperties.isServerProfile()) {
            ClientRegistrationRepository clientRegistrationRepository =
                    clientRegistrationRepositoryProvider.getIfAvailable();
            if (clientRegistrationRepository != null) {
                AppOidcUserService oidcUserService = new AppOidcUserService(appProperties, auditLogger);
                http.oauth2Login(oauth2 -> oauth2
                        .clientRegistrationRepository(clientRegistrationRepository)
                        .userInfoEndpoint(userInfo -> userInfo.oidcUserService(oidcUserService))
                        .successHandler((request, response, authentication) -> {
                            HttpSession session = request.getSession(false);
                            if (session != null) {
                                int idleSeconds = (int) Math.max(60L, appProperties.getLocal().getIdleTimeout().toSeconds());
                                session.setMaxInactiveInterval(idleSeconds);
                            }
                            response.sendRedirect("/");
                        })
                        .failureHandler((request, response, exception) -> {
                            auditLogger.logFailure(
                                    "anonymous",
                                    null,
                                    null,
                                    null,
                                    "OIDC_LOGIN",
                                    "OIDC_AUTH_FAILED",
                                    CorrelationIdHolder.getOrGenerate()
                            );
                            problemWriter.write(
                                    request,
                                    response,
                                    HttpStatus.UNAUTHORIZED,
                                    "OIDC_AUTH_FAILED",
                                    "OIDC authentication failed."
                            );
                        })
                );
            }
        }

        return http.build();
    }

    private static String resolveCurrentSubject() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return "anonymous";
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof AppPrincipal appPrincipal) {
            return appPrincipal.subject();
        }
        if (principal instanceof AppOidcUser oidcUser) {
            return oidcUser.toAppPrincipal().subject();
        }
        return "anonymous";
    }
}
