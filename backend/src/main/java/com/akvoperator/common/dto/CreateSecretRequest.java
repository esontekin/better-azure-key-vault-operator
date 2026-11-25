package com.akvoperator.common.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.Map;

public record CreateSecretRequest(
        @NotNull(message = "Secret name is required")
        @Size(min = 1, max = 127, message = "Secret name must be between 1 and 127 characters")
        @Pattern(regexp = "^[0-9a-zA-Z-]+$", message = "Secret name may contain only alphanumeric characters and hyphens")
        String name,

        @NotNull(message = "Secret value is required")
        String value,

        Boolean enabled,

        @Size(max = 255, message = "Content type must be at most 255 characters")
        String contentType,

        Instant expiresOn,
        Instant notBefore,
        Map<String, String> tags
) {
    @Override
    public String toString() {
        return "CreateSecretRequest[name=" + name + ", value=[REDACTED], enabled=" + enabled + ", tags=[REDACTED]]";
    }
}
