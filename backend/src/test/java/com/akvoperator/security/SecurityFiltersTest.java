package com.akvoperator.security;

import com.akvoperator.audit.AuditLogger;
import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.correlation.CorrelationIdHolder;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SecurityFiltersTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void localLoopbackFilterBlocksExternalRemoteIpUnlessContainerBindEnabled() throws Exception {
        AppProperties props = new AppProperties();
        props.setProfile("local");
        props.getLocal().setAllowContainerBind(false);

        LocalLoopbackEnforcementFilter filter = new LocalLoopbackEnforcementFilter(
                props, new ProblemDetailResponseWriter(objectMapper), mock(AuditLogger.class)
        );

        MockHttpServletRequest externalReq = new MockHttpServletRequest("GET", "/api/v1/vaults");
        externalReq.setRemoteAddr("192.168.1.44");
        MockHttpServletResponse externalRes = new MockHttpServletResponse();
        filter.doFilter(externalReq, externalRes, new MockFilterChain());
        assertThat(externalRes.getStatus()).isEqualTo(403);
        assertThat(externalRes.getContentAsString()).contains("LOCAL_EXTERNAL_ACCESS_DENIED");

        MockHttpServletRequest loopbackReq = new MockHttpServletRequest("GET", "/api/v1/vaults");
        loopbackReq.setRemoteAddr("127.0.0.1");
        MockHttpServletResponse loopbackRes = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(loopbackReq, loopbackRes, chain);
        assertThat(loopbackRes.getStatus()).isEqualTo(200);
        assertThat(chain.getRequest()).isNotNull();
    }

    @Test
    void rateLimitFilterEnforcesBootstrapLimitWithRetryAfterHeader() throws Exception {
        AppProperties props = new AppProperties();
        props.getSecurity().setBootstrapRateLimitPerMinute(2);
        Clock fixedClock = Clock.fixed(Instant.parse("2026-01-01T00:00:10Z"), ZoneOffset.UTC);

        RateLimitFilter filter = new RateLimitFilter(
                props, new ProblemDetailResponseWriter(objectMapper), mock(AuditLogger.class), fixedClock
        );

        for (int i = 0; i < 2; i++) {
            MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/v1/auth/bootstrap");
            req.setRemoteAddr("127.0.0.1");
            MockHttpServletResponse res = new MockHttpServletResponse();
            filter.doFilter(req, res, new MockFilterChain());
            assertThat(res.getStatus()).isEqualTo(200);
        }

        MockHttpServletRequest limitedReq = new MockHttpServletRequest("POST", "/api/v1/auth/bootstrap");
        limitedReq.setRemoteAddr("127.0.0.1");
        MockHttpServletResponse limitedRes = new MockHttpServletResponse();
        filter.doFilter(limitedReq, limitedRes, new MockFilterChain());
        assertThat(limitedRes.getStatus()).isEqualTo(429);
        assertThat(limitedRes.getHeader(HttpHeaders.RETRY_AFTER)).isNotBlank();
        assertThat(limitedRes.getContentAsString()).contains("RATE_LIMIT_EXCEEDED");
    }

    @Test
    void maxRequestBodySizeFilterRejectsOversizedPayloadWith413() throws Exception {
        AppProperties props = new AppProperties();
        props.getSecurity().setMaxRequestBodyBytes(1024);

        MaxRequestBodySizeFilter filter = new MaxRequestBodySizeFilter(
                props, new ProblemDetailResponseWriter(objectMapper)
        );

        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/v1/vaults/id/secrets");
        req.setContent(new byte[2048]);
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(req, res, new MockFilterChain());

        assertThat(res.getStatus()).isEqualTo(413);
        assertThat(res.getContentAsString()).contains("REQUEST_BODY_TOO_LARGE");
    }

    @Test
    void noStoreFilterSetsStrictCacheControlOnApiResponses() throws Exception {
        NoStoreSensitiveResponseFilter filter = new NoStoreSensitiveResponseFilter();
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/v1/vaults/id/secrets/s1/reveal");
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(req, res, new MockFilterChain());

        assertThat(res.getHeader(HttpHeaders.CACHE_CONTROL)).contains("no-store");
        assertThat(res.getHeader("Pragma")).isEqualTo("no-cache");
    }

    @Test
    void correlationIdFilterPropagatesValidHeaderAndReplacesInvalidHeader() throws Exception {
        CorrelationIdFilter filter = new CorrelationIdFilter();

        MockHttpServletRequest validReq = new MockHttpServletRequest("GET", "/api/v1/auth/status");
        validReq.addHeader(CorrelationIdHolder.HEADER_NAME, "trace-abc-123");
        MockHttpServletResponse validRes = new MockHttpServletResponse();
        filter.doFilter(validReq, validRes, new MockFilterChain());
        assertThat(validRes.getHeader(CorrelationIdHolder.HEADER_NAME)).isEqualTo("trace-abc-123");

        MockHttpServletRequest maliciousReq = new MockHttpServletRequest("GET", "/api/v1/auth/status");
        maliciousReq.addHeader(CorrelationIdHolder.HEADER_NAME, "bad\r\ninjection");
        MockHttpServletResponse maliciousRes = new MockHttpServletResponse();
        filter.doFilter(maliciousReq, maliciousRes, new MockFilterChain());
        String generated = maliciousRes.getHeader(CorrelationIdHolder.HEADER_NAME);
        assertThat(generated).isNotBlank().doesNotContain("\r").doesNotContain("\n").isNotEqualTo("bad\r\ninjection");
    }
}
