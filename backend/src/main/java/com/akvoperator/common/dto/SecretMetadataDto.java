package com.akvoperator.common.dto;

import java.time.Instant;
import java.util.Map;

public record SecretMetadataDto(
        String name,
        String version,
        boolean enabled,
        Instant createdOn,
        Instant updatedOn,
        Instant expiresOn,
        Instant notBefore,
        String contentType,
        Map<String, String> tags,
        boolean managed
) {
    public SecretMetadataDto {
        tags = tags == null ? Map.of() : Map.copyOf(tags);
    }

    @Override
    public String toString() {
        return "SecretMetadataDto[name=" + name + ", version=" + version + ", enabled=" + enabled + ", tags=[REDACTED]]";
    }
}
