package com.akvoperator.security;

import com.akvoperator.common.config.AppProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Enforces configured maximum request payload size on API routes.
 */
public class MaxRequestBodySizeFilter extends OncePerRequestFilter {

    private final AppProperties appProperties;
    private final ProblemDetailResponseWriter problemWriter;

    public MaxRequestBodySizeFilter(
            AppProperties appProperties,
            ProblemDetailResponseWriter problemWriter
    ) {
        this.appProperties = appProperties;
        this.problemWriter = problemWriter;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String uri = request.getRequestURI();
        if (uri != null && uri.startsWith("/api/")) {
            long contentLength = request.getContentLengthLong();
            long maxBytes = appProperties.getSecurity().getMaxRequestBodyBytes();
            if (maxBytes > 0 && contentLength > maxBytes) {
                problemWriter.write(
                        request,
                        response,
                        HttpStatus.PAYLOAD_TOO_LARGE,
                        "REQUEST_BODY_TOO_LARGE",
                        "Request payload exceeds the maximum allowed size."
                );
                return;
            }
        }
        filterChain.doFilter(request, response);
    }
}
