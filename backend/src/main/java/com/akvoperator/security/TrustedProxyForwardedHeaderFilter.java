package com.akvoperator.security;

import com.akvoperator.common.config.AppProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.ForwardedHeaderFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Processes Forwarded / X-Forwarded-* headers ONLY in server profile AND ONLY when the direct remote
 * peer IP matches configured trusted proxy CIDRs. Strips spoofed forwarded headers in all other cases
 * (including local profile).
 */
public class TrustedProxyForwardedHeaderFilter extends OncePerRequestFilter {

    private static final Set<String> FORWARDED_HEADERS = Set.of(
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-port",
            "x-forwarded-prefix"
    );

    private final AppProperties appProperties;
    private final List<CidrMatcher> trustedProxyMatchers;
    private final ForwardedHeaderFilter delegate = new ForwardedHeaderFilter();

    public TrustedProxyForwardedHeaderFilter(AppProperties appProperties) {
        this.appProperties = appProperties;
        this.trustedProxyMatchers = parseMatchers(appProperties);
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        if (appProperties.isServerProfile() && isTrustedProxy(request.getRemoteAddr())) {
            delegate.doFilter(request, response, filterChain);
            return;
        }
        filterChain.doFilter(new ForwardedHeaderStrippingRequestWrapper(request), response);
    }

    boolean isTrustedProxy(String remoteAddr) {
        if (remoteAddr == null || remoteAddr.isBlank() || trustedProxyMatchers.isEmpty()) {
            return false;
        }
        for (CidrMatcher matcher : trustedProxyMatchers) {
            if (matcher.matches(remoteAddr)) {
                return true;
            }
        }
        return false;
    }

    private static List<CidrMatcher> parseMatchers(AppProperties appProperties) {
        if (!appProperties.isServerProfile() || appProperties.getServer().getTrustedProxies() == null) {
            return List.of();
        }
        return appProperties.getServer().getTrustedProxies().stream()
                .filter(entry -> entry != null && !entry.isBlank())
                .map(CidrMatcher::parse)
                .toList();
    }

    private static final class ForwardedHeaderStrippingRequestWrapper extends HttpServletRequestWrapper {

        private ForwardedHeaderStrippingRequestWrapper(HttpServletRequest request) {
            super(request);
        }

        @Override
        public String getHeader(String name) {
            if (isForwardedHeader(name)) {
                return null;
            }
            return super.getHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            if (isForwardedHeader(name)) {
                return Collections.emptyEnumeration();
            }
            return super.getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            Enumeration<String> original = super.getHeaderNames();
            if (original == null) {
                return Collections.emptyEnumeration();
            }
            List<String> filtered = Collections.list(original).stream()
                    .filter(name -> !isForwardedHeader(name))
                    .toList();
            return Collections.enumeration(filtered);
        }

        @Override
        public int getIntHeader(String name) {
            if (isForwardedHeader(name)) {
                return -1;
            }
            return super.getIntHeader(name);
        }

        @Override
        public long getDateHeader(String name) {
            if (isForwardedHeader(name)) {
                return -1L;
            }
            return super.getDateHeader(name);
        }

        private static boolean isForwardedHeader(String name) {
            return name != null && FORWARDED_HEADERS.contains(name.toLowerCase(Locale.ROOT));
        }
    }
}
