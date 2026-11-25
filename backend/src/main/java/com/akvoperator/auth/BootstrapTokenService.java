package com.akvoperator.auth;

import com.akvoperator.common.config.AppProperties;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

/**
 * Manages single-use, high-entropy (256-bit) local bootstrap tokens.
 * Only the SHA-256 digest and expiration timestamp are stored for verification;
 * plaintext tokens are NEVER written to SLF4J/Logback logs or exposed over REST.
 */
@Service
public class BootstrapTokenService {

    private static final int TOKEN_ENTROPY_BYTES = 32; // 256 bits

    private final AppProperties appProperties;
    private final Clock clock;
    private final SecureRandom secureRandom = new SecureRandom();

    private TokenState activeState;
    private String operatorChannelToken;

    @Autowired
    public BootstrapTokenService(AppProperties appProperties) {
        this(appProperties, Clock.systemUTC());
    }

    BootstrapTokenService(AppProperties appProperties, Clock clock) {
        this.appProperties = appProperties;
        this.clock = clock;
    }

    @PostConstruct
    void initOnStartup() {
        if (appProperties.isLocalProfile()) {
            regenerateToken();
        }
    }

    /**
     * Generates a fresh 256-bit single-use bootstrap token, replacing any previous token.
     * In local profile with auto-print enabled, prints the operator banner directly to stdout
     * (local terminal channel only — never SLF4J/Logback logs).
     */
    public synchronized String regenerateToken() {
        if (!appProperties.isLocalProfile()) {
            throw new IllegalStateException("Bootstrap tokens are only available in local profile.");
        }
        byte[] raw = new byte[TOKEN_ENTROPY_BYTES];
        secureRandom.nextBytes(raw);
        String plaintext = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        byte[] hash = sha256(plaintext);

        Duration ttl = appProperties.getLocal().getBootstrapTokenTtl();
        if (ttl == null || ttl.isNegative() || ttl.isZero()) {
            ttl = Duration.ofMinutes(10);
        }
        Instant expiresAt = clock.instant().plus(ttl);
        this.activeState = new TokenState(hash, expiresAt, false);
        this.operatorChannelToken = plaintext;

        if (appProperties.getLocal().isBootstrapTokenAutoPrint()) {
            printOperatorBanner(plaintext, ttl, expiresAt);
        }
        return plaintext;
    }

    /**
     * Atomically verifies and consumes the active single-use bootstrap token using constant-time digest comparison.
     */
    public synchronized boolean consume(String candidateToken) {
        if (!appProperties.isLocalProfile() || candidateToken == null || candidateToken.isBlank()) {
            return false;
        }
        if (activeState == null || activeState.consumed()) {
            return false;
        }
        Instant now = clock.instant();
        if (now.isAfter(activeState.expiresAt())) {
            this.operatorChannelToken = null;
            return false;
        }
        byte[] candidateHash = sha256(candidateToken.trim());
        if (MessageDigest.isEqual(activeState.sha256Hash(), candidateHash)) {
            this.activeState = new TokenState(activeState.sha256Hash(), activeState.expiresAt(), true);
            this.operatorChannelToken = null;
            return true;
        }
        return false;
    }

    /**
     * Controlled package-private access for local operator channel / integration tests only.
     * Never expose via any REST controller.
     */
    synchronized Optional<String> getActiveTokenForOperatorChannel() {
        if (!appProperties.isLocalProfile() || activeState == null || activeState.consumed()) {
            return Optional.empty();
        }
        if (clock.instant().isAfter(activeState.expiresAt())) {
            this.operatorChannelToken = null;
            return Optional.empty();
        }
        return Optional.ofNullable(operatorChannelToken);
    }

    synchronized boolean hasActiveUnconsumedToken() {
        return activeState != null && !activeState.consumed() && !clock.instant().isAfter(activeState.expiresAt());
    }

    private void printOperatorBanner(String token, Duration ttl, Instant expiresAt) {
        System.out.println();
        System.out.println("========================================================================");
        System.out.println("  Azure Key Vault Manager — Local Operator One-Time Bootstrap Token");
        System.out.println("  Enter this token in the local web UI login form (do NOT put in URLs).");
        System.out.println("  Token      : " + token);
        System.out.println("  Valid for  : " + ttl.toMinutes() + " minutes (expires " + expiresAt + ")");
        System.out.println("  Single-use : Restart application to issue a new token after use.");
        System.out.println("========================================================================");
        System.out.println();
    }

    private static byte[] sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 algorithm unavailable", ex);
        }
    }

    private record TokenState(byte[] sha256Hash, Instant expiresAt, boolean consumed) {
    }
}
