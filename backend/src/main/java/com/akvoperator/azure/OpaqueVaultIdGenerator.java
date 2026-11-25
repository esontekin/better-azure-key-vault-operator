package com.akvoperator.azure;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Locale;

/**
 * Generates deterministic, URL-safe opaque vault identifiers so raw Azure resource IDs or URLs
 * are never accepted directly as API path identifiers.
 */
public final class OpaqueVaultIdGenerator {

    private static final String PREFIX = "vlt_";
    private static final int HASH_PREFIX_LENGTH = 24;

    private OpaqueVaultIdGenerator() {
    }

    public static String generate(String resourceIdOrVaultUri) {
        if (resourceIdOrVaultUri == null || resourceIdOrVaultUri.isBlank()) {
            throw new IllegalArgumentException("Vault identifier input must not be blank");
        }
        String normalized = resourceIdOrVaultUri.trim().toLowerCase(Locale.ROOT);
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        byte[] digest = sha256(normalized);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        return PREFIX + encoded.substring(0, HASH_PREFIX_LENGTH);
    }

    private static byte[] sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 algorithm is unavailable", ex);
        }
    }
}
