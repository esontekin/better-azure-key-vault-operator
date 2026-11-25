package com.akvoperator.common.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.Map;

public record UpdateSecretRequest(
        @NotNull(message = "Secret value is required")
        String value,

        String expectedLatestVersion,
        Boolean preserveMetadata,
        Boolean enabled,

        @Size(max = 255, message = "Content type must be at most 255 characters")
        String contentType,

        Instant expiresOn,
        Instant notBefore,
        Map<String, String> tags
) {
    public boolean shouldPreserveMetadata() {
        return preserveMetadata == null || preserveMetadata;
    }

    @Override
    public String toString() {
        return "UpdateSecretRequest[value=[REDACTED], expectedLatestVersion=" + expectedLatestVersion
                + ", preserveMetadata=" + preserveMetadata + ", tags=[REDACTED]]";
    }
}
