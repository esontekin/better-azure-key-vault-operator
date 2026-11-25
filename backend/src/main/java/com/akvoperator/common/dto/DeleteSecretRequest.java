package com.akvoperator.common.dto;

import jakarta.validation.constraints.NotBlank;

public record DeleteSecretRequest(
        @NotBlank(message = "Secret name confirmation is required")
        String confirmSecretName
) {
}
