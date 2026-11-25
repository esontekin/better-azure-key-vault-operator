package com.akvoperator.common.dto;

public record SubscriptionDto(
        String subscriptionId,
        String displayName,
        String state
) {
}
