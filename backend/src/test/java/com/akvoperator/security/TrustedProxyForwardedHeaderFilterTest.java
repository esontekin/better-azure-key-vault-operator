package com.akvoperator.security;

import com.akvoperator.common.config.AppProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class TrustedProxyForwardedHeaderFilterTest {

    @Test
    void honorsForwardedHeadersFromTrustedProxyCidrInServerProfile() throws Exception {
        AppProperties props = new AppProperties();
        props.setProfile("server");
        props.getServer().setTrustedProxies(List.of("10.0.0.0/8"));
        TrustedProxyForwardedHeaderFilter filter = new TrustedProxyForwardedHeaderFilter(props);

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/v1/auth/status");
        req.setRemoteAddr("10.24.5.12");
        req.setScheme("http");
        req.setServerName("10.24.5.99");
        req.setServerPort(8765);
        req.addHeader("X-Forwarded-Proto", "https");
        req.addHeader("X-Forwarded-Host", "vaults.example.com");
        req.addHeader("X-Forwarded-Port", "443");

        AtomicReference<HttpServletRequest> captured = new AtomicReference<>();
        MockFilterChain chain = new MockFilterChain() {
            @Override
            public void doFilter(jakarta.servlet.ServletRequest request, jakarta.servlet.ServletResponse response) {
                captured.set((HttpServletRequest) request);
            }
        };

        filter.doFilter(req, new MockHttpServletResponse(), chain);

        HttpServletRequest downstream = captured.get();
        assertThat(downstream).isNotNull();
        assertThat(downstream.getScheme()).isEqualTo("https");
        assertThat(downstream.isSecure()).isTrue();
        assertThat(downstream.getServerName()).isEqualTo("vaults.example.com");
        assertThat(downstream.getServerPort()).isEqualTo(443);
    }

    @Test
    void stripsSpoofedForwardedHeadersFromUntrustedRemoteIp() throws Exception {
        AppProperties props = new AppProperties();
        props.setProfile("server");
        props.getServer().setTrustedProxies(List.of("10.0.0.0/8"));
        TrustedProxyForwardedHeaderFilter filter = new TrustedProxyForwardedHeaderFilter(props);

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/v1/auth/status");
        req.setRemoteAddr("203.0.113.42");
        req.setScheme("http");
        req.setServerName("internal-pod");
        req.setServerPort(8765);
        req.addHeader("X-Forwarded-Proto", "https");
        req.addHeader("X-Forwarded-Host", "spoofed.example.com");
        req.addHeader("X-Forwarded-For", "127.0.0.1");

        AtomicReference<HttpServletRequest> captured = new AtomicReference<>();
        MockFilterChain chain = new MockFilterChain() {
            @Override
            public void doFilter(jakarta.servlet.ServletRequest request, jakarta.servlet.ServletResponse response) {
                captured.set((HttpServletRequest) request);
            }
        };

        filter.doFilter(req, new MockHttpServletResponse(), chain);

        HttpServletRequest downstream = captured.get();
        assertThat(downstream).isNotNull();
        assertThat(downstream.getScheme()).isEqualTo("http");
        assertThat(downstream.isSecure()).isFalse();
        assertThat(downstream.getServerName()).isEqualTo("internal-pod");
        assertThat(downstream.getHeader("X-Forwarded-Proto")).isNull();
        assertThat(downstream.getHeader("X-Forwarded-Host")).isNull();
        assertThat(downstream.getHeader("X-Forwarded-For")).isNull();
    }

    @Test
    void alwaysIgnoresForwardedHeadersInLocalProfile() throws Exception {
        AppProperties props = new AppProperties();
        props.setProfile("local");
        TrustedProxyForwardedHeaderFilter filter = new TrustedProxyForwardedHeaderFilter(props);

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/v1/auth/status");
        req.setRemoteAddr("127.0.0.1");
        req.setScheme("http");
        req.addHeader("X-Forwarded-Proto", "https");
        req.addHeader("X-Forwarded-Host", "evil.com");

        AtomicReference<HttpServletRequest> captured = new AtomicReference<>();
        MockFilterChain chain = new MockFilterChain() {
            @Override
            public void doFilter(jakarta.servlet.ServletRequest request, jakarta.servlet.ServletResponse response) {
                captured.set((HttpServletRequest) request);
            }
        };

        filter.doFilter(req, new MockHttpServletResponse(), chain);

        HttpServletRequest downstream = captured.get();
        assertThat(downstream).isNotNull();
        assertThat(downstream.getScheme()).isEqualTo("http");
        assertThat(downstream.getHeader("X-Forwarded-Proto")).isNull();
        assertThat(downstream.getHeader("X-Forwarded-Host")).isNull();
    }
}
