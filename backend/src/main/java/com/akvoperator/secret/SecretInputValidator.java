package com.akvoperator.secret;

import com.akvoperator.common.exception.AppException;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Validates Azure Key Vault secret names, values (UTF-8 byte limit without trimming),
 * content types, tags, and UTC date ranges before issuing Azure SDK requests.
 */
@Component
public class SecretInputValidator {

    /**
     * Official Azure Key Vault maximum secret value size: 25 KB (25,600 UTF-8 bytes).
     */
    public static final int MAX_VALUE_UTF8_BYTES = 25_600;
    public static final int MAX_CONTENT_TYPE_LENGTH = 255;
    public static final int MAX_TAGS_COUNT = 15;
    public static final int MAX_TAG_KEY_LENGTH = 512;
    public static final int MAX_TAG_VALUE_LENGTH = 256;

    private static final Pattern SECRET_NAME_PATTERN = Pattern.compile("^[0-9a-zA-Z-]{1,127}$");
    private static final Pattern SECRET_VERSION_PATTERN = Pattern.compile("^[0-9a-zA-Z-]{1,128}$");

    public void validateSecretName(String name) {
        if (name == null || !SECRET_NAME_PATTERN.matcher(name).matches()) {
            throw AppException.badRequest(
                    "INVALID_SECRET_NAME",
                    "Secret name must be 1 to 127 characters containing only alphanumeric characters and hyphens."
            );
        }
    }

    public void validateVersion(String version) {
        if (version == null || version.isBlank()) {
            return;
        }
        if (!SECRET_VERSION_PATTERN.matcher(version.trim()).matches()) {
            throw AppException.badRequest(
                    "INVALID_SECRET_VERSION",
                    "Secret version identifier has an invalid format."
            );
        }
    }

    /**
     * Validates secret value size in UTF-8 bytes. Never trims or mutates the value.
     */
    public void validateSecretValue(String value) {
        if (value == null) {
            throw AppException.badRequest(
                    "INVALID_SECRET_VALUE",
                    "Secret value must not be null."
            );
        }
        int byteLength = value.getBytes(StandardCharsets.UTF_8).length;
        if (byteLength > MAX_VALUE_UTF8_BYTES) {
            throw AppException.badRequest(
                    "SECRET_VALUE_TOO_LARGE",
                    "Secret value exceeds the Azure Key Vault limit of 25,600 UTF-8 bytes."
            );
        }
    }

    public void validateContentType(String contentType) {
        if (contentType != null && contentType.length() > MAX_CONTENT_TYPE_LENGTH) {
            throw AppException.badRequest(
                    "INVALID_CONTENT_TYPE",
                    "Content type must not exceed 255 characters."
            );
        }
    }

    public void validateDateRange(Instant notBefore, Instant expiresOn) {
        if (notBefore != null && expiresOn != null && !notBefore.isBefore(expiresOn)) {
            throw AppException.badRequest(
                    "INVALID_DATE_RANGE",
                    "notBefore must be strictly earlier than expiresOn (UTC)."
            );
        }
    }

    public void validateTags(Map<String, String> tags) {
        if (tags == null) {
            return;
        }
        if (tags.size() > MAX_TAGS_COUNT) {
            throw AppException.badRequest(
                    "INVALID_TAGS",
                    "A secret may have at most 15 tags."
            );
        }
        for (Map.Entry<String, String> entry : tags.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            if (key == null || key.isEmpty() || key.length() > MAX_TAG_KEY_LENGTH) {
                throw AppException.badRequest(
                        "INVALID_TAGS",
                        "Each tag key must be between 1 and 512 characters."
                );
            }
            if (value != null && value.length() > MAX_TAG_VALUE_LENGTH) {
                throw AppException.badRequest(
                        "INVALID_TAGS",
                        "Each tag value must be at most 256 characters."
                );
            }
        }
    }
}
