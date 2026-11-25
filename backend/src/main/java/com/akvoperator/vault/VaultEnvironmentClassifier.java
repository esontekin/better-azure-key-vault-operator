package com.akvoperator.vault;

import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Classifies Key Vault environment labels (e.g. prod, staging, dev, test, unknown) from ARM tags
 * or vault naming conventions, and parses standard ARM resource ID segments.
 */
public final class VaultEnvironmentClassifier {

    private static final Pattern RESOURCE_GROUP_PATTERN =
            Pattern.compile("/resourcegroups/([^/]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern SUBSCRIPTION_PATTERN =
            Pattern.compile("/subscriptions/([^/]+)", Pattern.CASE_INSENSITIVE);

    private VaultEnvironmentClassifier() {
    }

    public static String inferEnvironment(Map<String, String> tags, String vaultName) {
        if (tags != null && !tags.isEmpty()) {
            for (Map.Entry<String, String> entry : tags.entrySet()) {
                if (entry.getKey() == null || entry.getValue() == null) {
                    continue;
                }
                String key = entry.getKey().trim().toLowerCase(Locale.ROOT);
                if ("env".equals(key) || "environment".equals(key)) {
                    String normalized = normalizeEnvironmentLabel(entry.getValue());
                    if (!"unknown".equals(normalized)) {
                        return normalized;
                    }
                }
            }
        }
        return inferFromName(vaultName);
    }

    public static String normalizeEnvironmentLabel(String rawLabel) {
        if (rawLabel == null || rawLabel.isBlank()) {
            return "unknown";
        }
        String lower = rawLabel.trim().toLowerCase(Locale.ROOT);
        if ("prod".equals(lower) || "prd".equals(lower) || "production".equals(lower)) {
            return "prod";
        }
        if ("stg".equals(lower) || "stage".equals(lower) || "staging".equals(lower) || "preprod".equals(lower)) {
            return "staging";
        }
        if ("dev".equals(lower) || "development".equals(lower)) {
            return "dev";
        }
        if ("test".equals(lower) || "tst".equals(lower) || "qa".equals(lower) || "uat".equals(lower)) {
            return "test";
        }
        return lower;
    }

    public static boolean isProduction(String environment) {
        if (environment == null) {
            return false;
        }
        String lower = environment.trim().toLowerCase(Locale.ROOT);
        return "prod".equals(lower) || "production".equals(lower);
    }

    public static String extractResourceGroup(String resourceId) {
        if (resourceId == null || resourceId.isBlank()) {
            return null;
        }
        Matcher matcher = RESOURCE_GROUP_PATTERN.matcher(resourceId);
        return matcher.find() ? matcher.group(1) : null;
    }

    public static String extractSubscriptionId(String resourceId) {
        if (resourceId == null || resourceId.isBlank()) {
            return null;
        }
        Matcher matcher = SUBSCRIPTION_PATTERN.matcher(resourceId);
        return matcher.find() ? matcher.group(1) : null;
    }

    private static String inferFromName(String vaultName) {
        if (vaultName == null || vaultName.isBlank()) {
            return "unknown";
        }
        String lower = vaultName.trim().toLowerCase(Locale.ROOT);
        if (lower.endsWith("-prod") || lower.endsWith("-prd") || lower.endsWith("-production")
                || lower.contains("-prod-") || lower.contains("-prd-")) {
            return "prod";
        }
        if (lower.endsWith("-stg") || lower.endsWith("-stage") || lower.endsWith("-staging")
                || lower.contains("-stg-") || lower.contains("-staging-")) {
            return "staging";
        }
        if (lower.endsWith("-dev") || lower.endsWith("-development") || lower.contains("-dev-")) {
            return "dev";
        }
        if (lower.endsWith("-test") || lower.endsWith("-tst") || lower.endsWith("-qa")
                || lower.contains("-test-") || lower.contains("-qa-")) {
            return "test";
        }
        return "unknown";
    }
}
