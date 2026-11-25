package com.akvoperator.secret;

import com.akvoperator.common.dto.CreateSecretRequest;
import com.akvoperator.common.dto.DeleteSecretRequest;
import com.akvoperator.common.dto.DeletedSecretDto;
import com.akvoperator.common.dto.OperationStatusResponse;
import com.akvoperator.common.dto.RevealSecretRequest;
import com.akvoperator.common.dto.SecretListSnapshotResponse;
import com.akvoperator.common.dto.SecretMetadataDto;
import com.akvoperator.common.dto.SecretValueResponse;
import com.akvoperator.common.dto.SecretVersionDto;
import com.akvoperator.common.dto.UpdateSecretPropertiesRequest;
import com.akvoperator.common.dto.UpdateSecretRequest;
import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * REST endpoints for Azure Key Vault secret metadata snapshots, CRUD, versions,
 * soft-delete, and recovery. Permanent purge endpoints are intentionally excluded.
 */
@RestController
@RequestMapping("/api/v1/vaults/{id}")
public class SecretController {

    private final SecretService secretService;

    public SecretController(SecretService secretService) {
        this.secretService = secretService;
    }

    @GetMapping("/secrets")
    public ResponseEntity<SecretListSnapshotResponse> getSecretsSnapshot(@PathVariable("id") String vaultId) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(secretService.getSnapshot(vaultId));
    }

    @PostMapping("/refresh")
    public ResponseEntity<SecretListSnapshotResponse> refreshVaultSecrets(@PathVariable("id") String vaultId) {
        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .cacheControl(CacheControl.noStore())
                .body(secretService.triggerRefresh(vaultId));
    }

    @PostMapping("/secrets")
    public ResponseEntity<SecretMetadataDto> createSecret(
            @PathVariable("id") String vaultId,
            @Valid @RequestBody CreateSecretRequest request
    ) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .cacheControl(CacheControl.noStore())
                .body(secretService.createSecret(vaultId, request));
    }

    @GetMapping("/secrets/{name}")
    public ResponseEntity<SecretMetadataDto> getSecretMetadata(
            @PathVariable("id") String vaultId,
            @PathVariable("name") String secretName
    ) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(secretService.getSecretMetadata(vaultId, secretName));
    }

    @PostMapping("/secrets/{name}/reveal")
    public ResponseEntity<SecretValueResponse> revealSecret(
            @PathVariable("id") String vaultId,
            @PathVariable("name") String secretName,
            @RequestBody(required = false) RevealSecretRequest request
    ) {
        String version = request != null ? request.version() : null;
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(secretService.revealSecret(vaultId, secretName, version));
    }

    @PutMapping("/secrets/{name}")
    public ResponseEntity<SecretMetadataDto> updateSecretValue(
            @PathVariable("id") String vaultId,
            @PathVariable("name") String secretName,
            @Valid @RequestBody UpdateSecretRequest request
    ) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(secretService.updateSecret(vaultId, secretName, request));
    }

    @PatchMapping("/secrets/{name}/properties")
    public ResponseEntity<SecretMetadataDto> updateSecretProperties(
            @PathVariable("id") String vaultId,
            @PathVariable("name") String secretName,
            @Valid @RequestBody UpdateSecretPropertiesRequest request
    ) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(secretService.updateSecretProperties(vaultId, secretName, request));
    }

    @GetMapping("/secrets/{name}/versions")
    public ResponseEntity<List<SecretVersionDto>> listSecretVersions(
            @PathVariable("id") String vaultId,
            @PathVariable("name") String secretName
    ) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(secretService.listSecretVersions(vaultId, secretName));
    }

    @DeleteMapping("/secrets/{name}")
    public ResponseEntity<OperationStatusResponse> softDeleteSecret(
            @PathVariable("id") String vaultId,
            @PathVariable("name") String secretName,
            @Valid @RequestBody DeleteSecretRequest request
    ) {
        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .cacheControl(CacheControl.noStore())
                .body(secretService.softDeleteSecret(vaultId, secretName, request));
    }

    @GetMapping("/deleted-secrets")
    public ResponseEntity<List<DeletedSecretDto>> listDeletedSecrets(@PathVariable("id") String vaultId) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(secretService.listDeletedSecrets(vaultId));
    }

    @PostMapping("/deleted-secrets/{name}/recover")
    public ResponseEntity<OperationStatusResponse> recoverDeletedSecret(
            @PathVariable("id") String vaultId,
            @PathVariable("name") String secretName
    ) {
        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .cacheControl(CacheControl.noStore())
                .body(secretService.recoverDeletedSecret(vaultId, secretName));
    }
}
