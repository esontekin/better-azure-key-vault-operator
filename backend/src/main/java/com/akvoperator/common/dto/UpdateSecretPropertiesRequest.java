package com.akvoperator.common.dto;

import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.Map;

public record UpdateSecretPropertiesRequest(
        String version,
        Boolean enabled,

        @Size(max = 255, message = "Content type must be at most 255 characters")
        String contentType,

        Instant expiresOn,
        Instant notBefore,
        boolean clearExpiresOn,
        boolean clearNotBefore,
        Map<String, String> tags
) {
    @Override
    public String toString() {
        return "UpdateSecretPropertiesRequest[version=" + version + ", enabled=" + enabled + ", tags=[REDACTED]]";
    }
}
