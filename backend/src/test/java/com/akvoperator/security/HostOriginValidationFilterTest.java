package com.akvoperator.security;

import com.akvoperator.audit.AuditLogger;
import com.akvoperator.common.config.AppProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class HostOriginValidationFilterTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void localProfileAllowsValidLoopbackHostAndSameOriginPost() throws Exception {
        AppProperties props = new AppProperties();
        props.setProfile("local");
        HostOriginValidationFilter filter = new HostOriginValidationFilter(
                props, new ProblemDetailResponseWriter(objectMapper), mock(AuditLogger.class)
        );

        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/v1/vaults/abc/secrets");
        req.addHeader("Host", "localhost:8765");
        req.addHeader("Origin", "http://localhost:8765");
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(req, res, chain);
        assertThat(res.getStatus()).isEqualTo(200);
        assertThat(chain.getRequest()).isNotNull();
    }

    @Test
    void localProfileRejectsDnsRebindingHostHeader() throws Exception {
        AppProperties props = new AppProperties();
        props.setProfile("local");
        AuditLogger auditLogger = mock(AuditLogger.class);
        HostOriginValidationFilter filter = new HostOriginValidationFilter(
                props, new ProblemDetailResponseWriter(objectMapper), auditLogger
        );

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/v1/vaults");
        req.addHeader("Host", "evil.example.com:8765");
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(req, res, chain);
        assertThat(res.getStatus()).isEqualTo(403);
        assertThat(res.getContentAsString()).contains("HOST_HEADER_INVALID");
        assertThat(chain.getRequest()).isNull();
        verify(auditLogger).logDenied(
                eq("anonymous"), eq(null), eq(null), eq(null),
                eq("HOST_VALIDATION"), eq("HOST_HEADER_INVALID"), any()
        );
    }

    @Test
    void localProfileRejectsCrossOriginAndNullOriginPost() throws Exception {
        AppProperties props = new AppProperties();
        props.setProfile("local");
        HostOriginValidationFilter filter = new HostOriginValidationFilter(
                props, new ProblemDetailResponseWriter(objectMapper), mock(AuditLogger.class)
        );

        MockHttpServletRequest evilOriginReq = new MockHttpServletRequest("POST", "/api/v1/auth/bootstrap");
        evilOriginReq.addHeader("Host", "localhost:8765");
        evilOriginReq.addHeader("Origin", "https://attacker.com");
        MockHttpServletResponse res1 = new MockHttpServletResponse();
        filter.doFilter(evilOriginReq, res1, new MockFilterChain());
        assertThat(res1.getStatus()).isEqualTo(403);
        assertThat(res1.getContentAsString()).contains("ORIGIN_NOT_ALLOWED");

        MockHttpServletRequest nullOriginReq = new MockHttpServletRequest("DELETE", "/api/v1/vaults/id/secrets/foo");
        nullOriginReq.addHeader("Host", "127.0.0.1:8765");
        nullOriginReq.addHeader("Origin", "null");
        MockHttpServletResponse res2 = new MockHttpServletResponse();
        filter.doFilter(nullOriginReq, res2, new MockFilterChain());
        assertThat(res2.getStatus()).isEqualTo(403);
        assertThat(res2.getContentAsString()).contains("ORIGIN_NOT_ALLOWED");

        MockHttpServletRequest wrongPortReq = new MockHttpServletRequest("PUT", "/api/v1/vaults/id/secrets/foo");
        wrongPortReq.addHeader("Host", "localhost:8765");
        wrongPortReq.addHeader("Origin", "http://localhost:9999");
        MockHttpServletResponse res3 = new MockHttpServletResponse();
        filter.doFilter(wrongPortReq, res3, new MockFilterChain());
        assertThat(res3.getStatus()).isEqualTo(403);
    }

    @Test
    void serverProfileMatchesPublicBaseUrlExactly() throws Exception {
        AppProperties props = new AppProperties();
        props.setProfile("server");
        props.getServer().setPublicBaseUrl("https://vaults.corp.example.com");
        HostOriginValidationFilter filter = new HostOriginValidationFilter(
                props, new ProblemDetailResponseWriter(objectMapper), mock(AuditLogger.class)
        );

        // Matching Host + Origin -> 200
        MockHttpServletRequest validReq = new MockHttpServletRequest("POST", "/api/v1/vaults/id/refresh");
        validReq.addHeader("Host", "vaults.corp.example.com");
        validReq.addHeader("Origin", "https://vaults.corp.example.com");
        MockHttpServletResponse validRes = new MockHttpServletResponse();
        MockFilterChain validChain = new MockFilterChain();
        filter.doFilter(validReq, validRes, validChain);
        assertThat(validRes.getStatus()).isEqualTo(200);
        assertThat(validChain.getRequest()).isNotNull();

        // Downgraded http Origin -> 403
        MockHttpServletRequest httpOriginReq = new MockHttpServletRequest("POST", "/api/v1/vaults/id/refresh");
        httpOriginReq.addHeader("Host", "vaults.corp.example.com");
        httpOriginReq.addHeader("Origin", "http://vaults.corp.example.com");
        MockHttpServletResponse httpOriginRes = new MockHttpServletResponse();
        filter.doFilter(httpOriginReq, httpOriginRes, new MockFilterChain());
        assertThat(httpOriginRes.getStatus()).isEqualTo(403);

        // Kubernetes health probe with pod IP Host -> allowed
        MockHttpServletRequest healthReq = new MockHttpServletRequest("GET", "/actuator/health/readiness");
        healthReq.addHeader("Host", "10.244.0.12:8765");
        MockHttpServletResponse healthRes = new MockHttpServletResponse();
        MockFilterChain healthChain = new MockFilterChain();
        filter.doFilter(healthReq, healthRes, healthChain);
        assertThat(healthRes.getStatus()).isEqualTo(200);
        assertThat(healthChain.getRequest()).isNotNull();
    }
}
