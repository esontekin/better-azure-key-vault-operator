package com.akvoperator.common.dto;

import java.time.Instant;
import java.util.Map;

public record DeletedSecretDto(
        String name,
        Instant deletedOn,
        Instant scheduledPurgeDate,
        String recoveryId,
        Boolean enabled,
        String contentType,
        Map<String, String> tags
) {
    public DeletedSecretDto {
        tags = tags == null ? Map.of() : Map.copyOf(tags);
    }

    @Override
    public String toString() {
        return "DeletedSecretDto[name=" + name + ", deletedOn=" + deletedOn + ", tags=[REDACTED]]";
    }
}
