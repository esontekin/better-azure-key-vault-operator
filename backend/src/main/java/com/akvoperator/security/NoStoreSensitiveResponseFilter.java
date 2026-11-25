package com.akvoperator.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Ensures sensitive API responses are never cached by browsers or intermediary proxies.
 */
public class NoStoreSensitiveResponseFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String uri = request.getRequestURI();
        if (uri != null && (uri.startsWith("/api/") || uri.equals("/api")
                || uri.startsWith("/oauth2/") || uri.startsWith("/login/oauth2/"))) {
            response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store, no-cache, max-age=0, must-revalidate");
            response.setHeader("Pragma", "no-cache");
            response.setHeader("Expires", "0");
        }
        filterChain.doFilter(request, response);
    }
}
