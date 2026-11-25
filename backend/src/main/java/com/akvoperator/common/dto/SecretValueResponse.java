package com.akvoperator.common.dto;

import java.time.Instant;

public record SecretValueResponse(
        String name,
        String version,
        String value,
        String contentType,
        Instant updatedOn
) {
    @Override
    public String toString() {
        return "SecretValueResponse[name=" + name + ", version=" + version + ", value=[REDACTED]]";
    }
}
