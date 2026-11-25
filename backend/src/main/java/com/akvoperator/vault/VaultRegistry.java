package com.akvoperator.vault;

import com.akvoperator.common.dto.SubscriptionDto;

import java.util.List;
import java.util.Optional;

public interface VaultRegistry {

    List<SubscriptionDto> listSubscriptions();

    List<VaultDescriptor> listVaults();

    Optional<VaultDescriptor> findByOpaqueId(String opaqueVaultId);

    void refreshDiscovery();
}
