package com.akvoperator.auth;

import com.akvoperator.common.config.AppProperties;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BootstrapTokenServiceTest {

    @Test
    void generatesHighEntropySingleUseTokenAndRejectsReplay() {
        AppProperties props = localProps(Duration.ofMinutes(10));
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        BootstrapTokenService service = new BootstrapTokenService(props, clock);

        String token1 = service.regenerateToken();
        assertThat(token1).hasSizeGreaterThanOrEqualTo(43); // 256 bits Base64URL without padding
        assertThat(token1).matches("^[A-Za-z0-9_-]+$");
        assertThat(service.getActiveTokenForOperatorChannel()).contains(token1);

        // Wrong token fails without consuming the valid token
        assertThat(service.consume("wrong-token-value-1234567890")).isFalse();
        assertThat(service.consume("")).isFalse();
        assertThat(service.consume(null)).isFalse();
        assertThat(service.hasActiveUnconsumedToken()).isTrue();

        // Valid token succeeds once
        assertThat(service.consume(token1)).isTrue();
        assertThat(service.hasActiveUnconsumedToken()).isFalse();
        assertThat(service.getActiveTokenForOperatorChannel()).isEmpty();

        // Replay is strictly rejected
        assertThat(service.consume(token1)).isFalse();

        // Regenerated token is distinct and usable
        String token2 = service.regenerateToken();
        assertThat(token2).isNotEqualTo(token1);
        assertThat(service.consume(token2)).isTrue();
    }

    @Test
    void rejectsExpiredToken() {
        AppProperties props = localProps(Duration.ofMinutes(5));
        MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        BootstrapTokenService service = new BootstrapTokenService(props, clock);

        String token = service.regenerateToken();
        clock.advance(Duration.ofMinutes(5).plusSeconds(1));

        assertThat(service.hasActiveUnconsumedToken()).isFalse();
        assertThat(service.getActiveTokenForOperatorChannel()).isEmpty();
        assertThat(service.consume(token)).isFalse();
    }

    @Test
    void rejectsOperationsInServerProfile() {
        AppProperties props = new AppProperties();
        props.setProfile("server");
        props.getLocal().setBootstrapTokenAutoPrint(false);

        BootstrapTokenService service = new BootstrapTokenService(props, Clock.systemUTC());
        service.initOnStartup();

        assertThat(service.getActiveTokenForOperatorChannel()).isEqualTo(Optional.empty());
        assertThat(service.consume("any-token-value-1234567890")).isFalse();
        assertThatThrownBy(service::regenerateToken).isInstanceOf(IllegalStateException.class);
    }

    private static AppProperties localProps(Duration ttl) {
        AppProperties props = new AppProperties();
        props.setProfile("local");
        props.getLocal().setBootstrapTokenTtl(ttl);
        props.getLocal().setBootstrapTokenAutoPrint(false);
        return props;
    }

    private static final class MutableClock extends Clock {
        private Instant current;

        private MutableClock(Instant initial) {
            this.current = initial;
        }

        void advance(Duration duration) {
            this.current = this.current.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return current;
        }
    }
}
