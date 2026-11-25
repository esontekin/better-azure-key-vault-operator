package com.akvoperator.common.dto;

import java.time.Instant;
import java.util.Map;

public record SecretVersionDto(
        String version,
        boolean enabled,
        Instant createdOn,
        Instant updatedOn,
        Instant expiresOn,
        Instant notBefore,
        String contentType,
        Map<String, String> tags,
        boolean latest
) {
    public SecretVersionDto {
        tags = tags == null ? Map.of() : Map.copyOf(tags);
    }

    @Override
    public String toString() {
        return "SecretVersionDto[version=" + version + ", enabled=" + enabled + ", latest=" + latest + ", tags=[REDACTED]]";
    }
}
