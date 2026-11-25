package com.akvoperator.secret;

import com.akvoperator.common.dto.DeletedSecretDto;
import com.akvoperator.common.dto.SecretMetadataDto;
import com.akvoperator.common.dto.SecretValueResponse;
import com.akvoperator.common.dto.SecretVersionDto;
import com.azure.security.keyvault.secrets.models.DeletedSecret;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.azure.security.keyvault.secrets.models.SecretProperties;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;

/**
 * Maps Azure Key Vault SDK models into application JSON DTOs.
 * SDK objects are never serialized directly over REST endpoints.
 */
final class SecretDtoMapper {

    private SecretDtoMapper() {
    }

    static SecretMetadataDto toMetadataDto(SecretProperties properties) {
        return new SecretMetadataDto(
                properties.getName(),
                properties.getVersion(),
                !Boolean.FALSE.equals(properties.isEnabled()),
                toInstant(properties.getCreatedOn()),
                toInstant(properties.getUpdatedOn()),
                toInstant(properties.getExpiresOn()),
                toInstant(properties.getNotBefore()),
                properties.getContentType(),
                properties.getTags() == null ? Map.of() : Map.copyOf(properties.getTags()),
                Boolean.TRUE.equals(properties.isManaged())
        );
    }

    static SecretVersionDto toVersionDto(SecretProperties properties, boolean latest) {
        return new SecretVersionDto(
                properties.getVersion(),
                !Boolean.FALSE.equals(properties.isEnabled()),
                toInstant(properties.getCreatedOn()),
                toInstant(properties.getUpdatedOn()),
                toInstant(properties.getExpiresOn()),
                toInstant(properties.getNotBefore()),
                properties.getContentType(),
                properties.getTags() == null ? Map.of() : Map.copyOf(properties.getTags()),
                latest
        );
    }

    static DeletedSecretDto toDeletedDto(DeletedSecret deleted) {
        SecretProperties props = deleted.getProperties();
        return new DeletedSecretDto(
                deleted.getName(),
                toInstant(deleted.getDeletedOn()),
                toInstant(deleted.getScheduledPurgeDate()),
                deleted.getRecoveryId(),
                props != null ? props.isEnabled() : null,
                props != null ? props.getContentType() : null,
                (props != null && props.getTags() != null) ? Map.copyOf(props.getTags()) : Map.of()
        );
    }

    static SecretValueResponse toValueResponse(KeyVaultSecret secret) {
        SecretProperties props = secret.getProperties();
        return new SecretValueResponse(
                secret.getName(),
                props != null ? props.getVersion() : null,
                secret.getValue(),
                props != null ? props.getContentType() : null,
                props != null ? toInstant(props.getUpdatedOn()) : null
        );
    }

    static Instant toInstant(OffsetDateTime dateTime) {
        return dateTime == null ? null : dateTime.toInstant();
    }

    static OffsetDateTime toOffsetDateTime(Instant instant) {
        return instant == null ? null : instant.atOffset(ZoneOffset.UTC);
    }
}
