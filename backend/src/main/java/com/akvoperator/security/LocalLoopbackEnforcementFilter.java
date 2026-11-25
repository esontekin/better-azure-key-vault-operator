package com.akvoperator.security;

import com.akvoperator.audit.AuditLogger;
import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.correlation.CorrelationIdHolder;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Rejects non-loopback remote clients when running in local profile without explicit container-bind exception.
 */
public class LocalLoopbackEnforcementFilter extends OncePerRequestFilter {

    private final AppProperties appProperties;
    private final ProblemDetailResponseWriter problemWriter;
    private final AuditLogger auditLogger;

    public LocalLoopbackEnforcementFilter(
            AppProperties appProperties,
            ProblemDetailResponseWriter problemWriter,
            AuditLogger auditLogger
    ) {
        this.appProperties = appProperties;
        this.problemWriter = problemWriter;
        this.auditLogger = auditLogger;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        if (appProperties.isLocalProfile() && !appProperties.getLocal().isAllowContainerBind()) {
            String remoteAddr = request.getRemoteAddr();
            if (!CidrMatcher.isLoopbackIpLiteral(remoteAddr)) {
                auditLogger.logDenied(
                        "anonymous",
                        null,
                        null,
                        null,
                        "LOCAL_ACCESS_CHECK",
                        "LOCAL_EXTERNAL_ACCESS_DENIED",
                        CorrelationIdHolder.getOrGenerate()
                );
                problemWriter.write(
                        request,
                        response,
                        HttpStatus.FORBIDDEN,
                        "LOCAL_EXTERNAL_ACCESS_DENIED",
                        "External network access is denied in local profile."
                );
                return;
            }
        }
        filterChain.doFilter(request, response);
    }
}
