package com.akvoperator.security;

import com.akvoperator.audit.AuditLogger;
import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.correlation.CorrelationIdHolder;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;

/**
 * Bounded per-client rate limiter protecting bootstrap login and API endpoints.
 */
public class RateLimitFilter extends OncePerRequestFilter {

    private static final String BOOTSTRAP_PATH = "/api/v1/auth/bootstrap";
    private static final long WINDOW_SECONDS = 60L;

    private final AppProperties appProperties;
    private final ProblemDetailResponseWriter problemWriter;
    private final AuditLogger auditLogger;
    private final Clock clock;
    private final Cache<String, RateWindow> buckets;

    public RateLimitFilter(
            AppProperties appProperties,
            ProblemDetailResponseWriter problemWriter,
            AuditLogger auditLogger
    ) {
        this(appProperties, problemWriter, auditLogger, Clock.systemUTC());
    }

    RateLimitFilter(
            AppProperties appProperties,
            ProblemDetailResponseWriter problemWriter,
            AuditLogger auditLogger,
            Clock clock
    ) {
        this.appProperties = appProperties;
        this.problemWriter = problemWriter;
        this.auditLogger = auditLogger;
        this.clock = clock;
        this.buckets = Caffeine.newBuilder()
                .maximumSize(10_000)
                .expireAfterAccess(Duration.ofMinutes(2))
                .build();
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String uri = request.getRequestURI();
        if (uri == null || !uri.startsWith("/api/")) {
            filterChain.doFilter(request, response);
            return;
        }

        boolean isBootstrap = BOOTSTRAP_PATH.equals(uri);
        int limit = isBootstrap
                ? appProperties.getSecurity().getBootstrapRateLimitPerMinute()
                : appProperties.getSecurity().getRateLimitPerMinute();
        if (limit <= 0) {
            filterChain.doFilter(request, response);
            return;
        }

        String clientKey = (isBootstrap ? "bootstrap:" : "api:")
                + (request.getRemoteAddr() != null ? request.getRemoteAddr() : "unknown");
        long nowSec = clock.instant().getEpochSecond();

        RateWindow window = buckets.get(clientKey, k -> new RateWindow(nowSec));
        int retryAfter = window.tryAcquire(nowSec, limit);
        if (retryAfter > 0) {
            auditLogger.logDenied(
                    "anonymous",
                    null,
                    null,
                    null,
                    isBootstrap ? "BOOTSTRAP_RATE_LIMIT" : "API_RATE_LIMIT",
                    "RATE_LIMIT_EXCEEDED",
                    CorrelationIdHolder.getOrGenerate()
            );
            problemWriter.write(
                    request,
                    response,
                    HttpStatus.TOO_MANY_REQUESTS,
                    "RATE_LIMIT_EXCEEDED",
                    "Too many requests. Please wait before retrying.",
                    retryAfter
            );
            return;
        }

        filterChain.doFilter(request, response);
    }

    private static final class RateWindow {
        private long windowStartEpochSec;
        private int count;

        private RateWindow(long startEpochSec) {
            this.windowStartEpochSec = startEpochSec;
            this.count = 0;
        }

        synchronized int tryAcquire(long nowEpochSec, int limit) {
            if (nowEpochSec - windowStartEpochSec >= WINDOW_SECONDS) {
                windowStartEpochSec = nowEpochSec;
                count = 0;
            }
            if (count >= limit) {
                long remaining = (windowStartEpochSec + WINDOW_SECONDS) - nowEpochSec;
                return (int) Math.max(1L, remaining);
            }
            count++;
            return 0;
        }
    }
}
