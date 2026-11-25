package com.akvoperator.security;

import com.akvoperator.audit.AuditLogger;
import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.correlation.CorrelationIdHolder;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Strict Host, Origin, and Referer validation filter to prevent DNS rebinding and cross-origin attacks.
 */
public class HostOriginValidationFilter extends OncePerRequestFilter {

    private static final Set<String> STATE_CHANGING_METHODS = Set.of("POST", "PUT", "PATCH", "DELETE");

    private final AppProperties appProperties;
    private final ProblemDetailResponseWriter problemWriter;
    private final AuditLogger auditLogger;
    private final Set<String> localAllowedHosts;
    private final URI serverPublicUri;

    public HostOriginValidationFilter(
            AppProperties appProperties,
            ProblemDetailResponseWriter problemWriter,
            AuditLogger auditLogger
    ) {
        this.appProperties = appProperties;
        this.problemWriter = problemWriter;
        this.auditLogger = auditLogger;
        this.localAllowedHosts = buildLocalAllowedHosts(appProperties);
        this.serverPublicUri = parseServerPublicUri(appProperties);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        if (isHealthProbeRequest(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String hostHeader = request.getHeader(HttpHeaders.HOST);
        String effectiveHostHeader = hostHeader;
        if (effectiveHostHeader == null && request.getServerName() != null && !request.getServerName().isBlank()) {
            int serverPort = request.getServerPort();
            String serverName = normalizeHost(request.getServerName());
            effectiveHostHeader = serverPort > 0 ? serverName + ":" + serverPort : serverName;
        }
        HostPort parsedHost = parseHostHeader(effectiveHostHeader);
        if (parsedHost == null || !isAllowedHost(parsedHost.host())) {
            auditLogger.logDenied(
                    "anonymous",
                    null,
                    null,
                    null,
                    "HOST_VALIDATION",
                    "HOST_HEADER_INVALID",
                    CorrelationIdHolder.getOrGenerate()
            );
            problemWriter.write(
                    request,
                    response,
                    HttpStatus.FORBIDDEN,
                    "HOST_HEADER_INVALID",
                    "The request Host header is not allowed."
            );
            return;
        }

        String method = request.getMethod() != null ? request.getMethod().toUpperCase(Locale.ROOT) : "";
        if (STATE_CHANGING_METHODS.contains(method)) {
            String originHeader = request.getHeader(HttpHeaders.ORIGIN);
            if (originHeader != null) {
                if (!isAllowedOrigin(originHeader, parsedHost, request, false)) {
                    rejectOrigin(request, response);
                    return;
                }
            } else {
                String refererHeader = request.getHeader(HttpHeaders.REFERER);
                if (refererHeader != null && !refererHeader.isBlank()) {
                    if (!isAllowedOrigin(refererHeader, parsedHost, request, true)) {
                        rejectOrigin(request, response);
                        return;
                    }
                }
            }
        }

        filterChain.doFilter(request, response);
    }

    private void rejectOrigin(HttpServletRequest request, HttpServletResponse response) throws IOException {
        auditLogger.logDenied(
                "anonymous",
                null,
                null,
                null,
                "ORIGIN_VALIDATION",
                "ORIGIN_NOT_ALLOWED",
                CorrelationIdHolder.getOrGenerate()
        );
        problemWriter.write(
                request,
                response,
                HttpStatus.FORBIDDEN,
                "ORIGIN_NOT_ALLOWED",
                "Cross-origin state-changing request rejected."
        );
    }

    private boolean isHealthProbeRequest(HttpServletRequest request) {
        String method = request.getMethod();
        if (!"GET".equalsIgnoreCase(method) && !"HEAD".equalsIgnoreCase(method)) {
            return false;
        }
        String uri = request.getRequestURI();
        return "/actuator/health".equals(uri) || (uri != null && uri.startsWith("/actuator/health/"));
    }

    private boolean isAllowedHost(String normalizedHost) {
        if (appProperties.isLocalProfile()) {
            return localAllowedHosts.contains(normalizedHost);
        }
        if (appProperties.isServerProfile() && serverPublicUri != null && serverPublicUri.getHost() != null) {
            return normalizeHost(serverPublicUri.getHost()).equals(normalizedHost);
        }
        return false;
    }

    private boolean isAllowedOrigin(
            String headerValue,
            HostPort requestHostPort,
            HttpServletRequest request,
            boolean allowPathAndQuery
    ) {
        String trimmed = headerValue.trim();
        if (trimmed.isEmpty() || "null".equalsIgnoreCase(trimmed)) {
            return false;
        }
        URI originUri;
        try {
            originUri = URI.create(trimmed);
        } catch (IllegalArgumentException ex) {
            return false;
        }
        String scheme = originUri.getScheme();
        String host = originUri.getHost();
        if (scheme == null || host == null || host.isBlank() || originUri.getUserInfo() != null) {
            return false;
        }
        if (!allowPathAndQuery) {
            String path = originUri.getRawPath();
            if ((path != null && !path.isEmpty() && !"/".equals(path))
                    || originUri.getRawQuery() != null
                    || originUri.getRawFragment() != null) {
                return false;
            }
        }

        String normalizedOriginHost = normalizeHost(host);
        int originPort = effectivePort(scheme, originUri.getPort());

        if (appProperties.isServerProfile()) {
            if (serverPublicUri == null) {
                return false;
            }
            String expectedScheme = serverPublicUri.getScheme();
            String expectedHost = normalizeHost(serverPublicUri.getHost());
            int expectedPort = effectivePort(expectedScheme, serverPublicUri.getPort());
            return expectedScheme.equalsIgnoreCase(scheme)
                    && expectedHost.equals(normalizedOriginHost)
                    && expectedPort == originPort;
        }

        if (appProperties.isLocalProfile()) {
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                return false;
            }
            if (!localAllowedHosts.contains(normalizedOriginHost) || !requestHostPort.host().equals(normalizedOriginHost)) {
                return false;
            }
            int expectedPort = requestHostPort.port() > 0
                    ? requestHostPort.port()
                    : (request.getServerPort() > 0 ? request.getServerPort() : effectivePort(request.getScheme(), -1));
            return originPort == expectedPort;
        }

        return false;
    }

    static HostPort parseHostHeader(String hostHeader) {
        if (hostHeader == null || hostHeader.isBlank()) {
            return null;
        }
        String trimmed = hostHeader.trim();
        if (trimmed.contains(" ") || trimmed.contains("\t") || trimmed.contains("/")
                || trimmed.contains("@") || trimmed.contains("\\")) {
            return null;
        }
        if (trimmed.startsWith("[")) {
            int closingBracket = trimmed.indexOf(']');
            if (closingBracket <= 1) {
                return null;
            }
            String ipv6Host = trimmed.substring(0, closingBracket + 1).toLowerCase(Locale.ROOT);
            String remainder = trimmed.substring(closingBracket + 1);
            if (remainder.isEmpty()) {
                return new HostPort(ipv6Host, -1);
            }
            if (!remainder.startsWith(":")) {
                return null;
            }
            int port = parsePort(remainder.substring(1));
            return port > 0 ? new HostPort(ipv6Host, port) : null;
        }

        int colonIdx = trimmed.indexOf(':');
        if (colonIdx < 0) {
            return new HostPort(trimmed.toLowerCase(Locale.ROOT), -1);
        }
        if (trimmed.indexOf(':', colonIdx + 1) >= 0) {
            // Multiple colons without brackets is invalid in HTTP Host header
            return null;
        }
        String host = trimmed.substring(0, colonIdx).toLowerCase(Locale.ROOT);
        if (host.isEmpty()) {
            return null;
        }
        int port = parsePort(trimmed.substring(colonIdx + 1));
        return port > 0 ? new HostPort(host, port) : null;
    }

    private static int parsePort(String portStr) {
        if (portStr == null || portStr.isEmpty() || portStr.length() > 5) {
            return -1;
        }
        try {
            int port = Integer.parseInt(portStr);
            return (port >= 1 && port <= 65535) ? port : -1;
        } catch (NumberFormatException ex) {
            return -1;
        }
    }

    private static int effectivePort(String scheme, int port) {
        if (port > 0) {
            return port;
        }
        if ("https".equalsIgnoreCase(scheme)) {
            return 443;
        }
        return 80;
    }

    private static String normalizeHost(String host) {
        String lower = host.trim().toLowerCase(Locale.ROOT);
        if (lower.contains(":") && !lower.startsWith("[")) {
            return "[" + lower + "]";
        }
        return lower;
    }

    private static Set<String> buildLocalAllowedHosts(AppProperties appProperties) {
        if (appProperties.getLocal().getAllowedHosts() == null) {
            return Set.of();
        }
        return appProperties.getLocal().getAllowedHosts().stream()
                .filter(h -> h != null && !h.isBlank())
                .map(HostOriginValidationFilter::normalizeHost)
                .collect(Collectors.toUnmodifiableSet());
    }

    private static URI parseServerPublicUri(AppProperties appProperties) {
        if (!appProperties.isServerProfile()) {
            return null;
        }
        String raw = appProperties.getServer().getPublicBaseUrl();
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return URI.create(raw.trim());
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    record HostPort(String host, int port) {
    }
}
