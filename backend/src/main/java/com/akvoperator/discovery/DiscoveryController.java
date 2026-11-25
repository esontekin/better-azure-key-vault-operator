package com.akvoperator.discovery;

import com.akvoperator.audit.AuditLogger;
import com.akvoperator.common.correlation.CorrelationIdHolder;
import com.akvoperator.common.dto.SubscriptionDto;
import com.akvoperator.common.dto.VaultDto;
import com.akvoperator.security.AppPrincipal;
import com.akvoperator.security.VaultAuthorizationService;
import com.akvoperator.vault.VaultDescriptor;
import com.akvoperator.vault.VaultRegistry;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * REST endpoints for authorized Azure subscription and Key Vault discovery.
 * All discovery results are filtered through {@link VaultAuthorizationService} before returning.
 */
@RestController
@RequestMapping("/api/v1")
public class DiscoveryController {

    private final VaultRegistry vaultRegistry;
    private final VaultAuthorizationService vaultAuthorizationService;
    private final AuditLogger auditLogger;

    public DiscoveryController(
            VaultRegistry vaultRegistry,
            VaultAuthorizationService vaultAuthorizationService,
            AuditLogger auditLogger
    ) {
        this.vaultRegistry = vaultRegistry;
        this.vaultAuthorizationService = vaultAuthorizationService;
        this.auditLogger = auditLogger;
    }

    @GetMapping("/subscriptions")
    public ResponseEntity<List<SubscriptionDto>> listSubscriptions() {
        AppPrincipal principal = vaultAuthorizationService.requireCurrentPrincipal();
        String correlationId = CorrelationIdHolder.getOrGenerate();

        List<VaultDescriptor> allVaults = vaultRegistry.listVaults();
        List<SubscriptionDto> allSubscriptions = vaultRegistry.listSubscriptions();
        List<VaultDto> authorizedVaults = vaultAuthorizationService.filterAuthorizedVaults(allVaults);
        List<SubscriptionDto> authorizedSubscriptions = vaultAuthorizationService.filterAuthorizedSubscriptions(
                allSubscriptions,
                authorizedVaults
        );

        auditLogger.logSuccess(
                principal.subject(),
                null,
                null,
                null,
                "DISCOVERY_LIST_SUBSCRIPTIONS",
                correlationId
        );

        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(authorizedSubscriptions);
    }

    @GetMapping("/vaults")
    public ResponseEntity<List<VaultDto>> listVaults(
            @RequestParam(name = "subscriptionId", required = false) String subscriptionId
    ) {
        AppPrincipal principal = vaultAuthorizationService.requireCurrentPrincipal();
        String correlationId = CorrelationIdHolder.getOrGenerate();

        List<VaultDescriptor> allVaults = vaultRegistry.listVaults();
        List<VaultDto> authorizedVaults = vaultAuthorizationService.filterAuthorizedVaults(allVaults);

        List<VaultDto> filtered = (subscriptionId != null && !subscriptionId.isBlank())
                ? authorizedVaults.stream()
                        .filter(v -> v.subscriptionId() != null && subscriptionId.trim().equalsIgnoreCase(v.subscriptionId()))
                        .toList()
                : authorizedVaults;

        auditLogger.logSuccess(
                principal.subject(),
                null,
                null,
                null,
                "DISCOVERY_LIST_VAULTS",
                correlationId
        );

        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(filtered);
    }

    @PostMapping("/vaults/refresh")
    public ResponseEntity<List<VaultDto>> refreshVaults(
            @RequestParam(name = "subscriptionId", required = false) String subscriptionId
    ) {
        AppPrincipal principal = vaultAuthorizationService.requireCurrentPrincipal();
        String correlationId = CorrelationIdHolder.getOrGenerate();

        vaultRegistry.refreshDiscovery();

        List<VaultDescriptor> allVaults = vaultRegistry.listVaults();
        List<VaultDto> authorizedVaults = vaultAuthorizationService.filterAuthorizedVaults(allVaults);

        List<VaultDto> filtered = (subscriptionId != null && !subscriptionId.isBlank())
                ? authorizedVaults.stream()
                        .filter(v -> v.subscriptionId() != null && subscriptionId.trim().equalsIgnoreCase(v.subscriptionId()))
                        .toList()
                : authorizedVaults;

        auditLogger.logSuccess(
                principal.subject(),
                null,
                null,
                null,
                "DISCOVERY_REFRESH_VAULTS",
                correlationId
        );

        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(filtered);
    }
}
