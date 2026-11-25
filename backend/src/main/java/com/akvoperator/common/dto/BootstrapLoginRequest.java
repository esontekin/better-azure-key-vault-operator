package com.akvoperator.common.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record BootstrapLoginRequest(
        @NotBlank(message = "Bootstrap token is required")
        @Size(min = 16, max = 256, message = "Invalid bootstrap token length")
        String token
) {
    @Override
    public String toString() {
        return "BootstrapLoginRequest[token=[REDACTED]]";
    }
}
