package com.akvoperator.azure;

import com.akvoperator.common.exception.AppException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AzureVaultUrlValidatorTest {

    private final AzureVaultUrlValidator validator = new AzureVaultUrlValidator(true);

    @Test
    void acceptsValidPublicCloudVaultUrlsAndNormalizes() {
        assertThat(validator.validateAndNormalize("https://my-vault-01.vault.azure.net"))
                .isEqualTo("https://my-vault-01.vault.azure.net");
        assertThat(validator.validateAndNormalize("https://My-Vault-01.VAULT.AZURE.NET/"))
                .isEqualTo("https://my-vault-01.vault.azure.net");
        assertThat(validator.validateAndNormalize("https://abc.vault.azure.net:443/"))
                .isEqualTo("https://abc.vault.azure.net");
        assertThat(validator.extractVaultName("https://Prod-Vault-9.vault.azure.net/"))
                .isEqualTo("prod-vault-9");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "",
            "   ",
            "http://my-vault.vault.azure.net",
            "https://my-vault.vault.usgovcloudapi.net",
            "https://my-vault.vault.azure.cn",
            "https://my-vault.vault.azure.net.evil.com",
            "https://a.b.vault.azure.net",
            "https://evil.com.vault.azure.net",
            "https://127.0.0.1",
            "https://169.254.169.254/metadata/instance",
            "https://[::1]:443/",
            "https://my-vault.vault.azure.net:8443",
            "https://my-vault.vault.azure.net:80",
            "https://user:pass@my-vault.vault.azure.net",
            "https://my-vault.vault.azure.net/secrets/foo",
            "https://my-vault.vault.azure.net/?api-version=7.4",
            "https://my-vault.vault.azure.net/#frag",
            "https://ab.vault.azure.net",
            "https://1vault.vault.azure.net",
            "https://vault-.vault.azure.net",
            "https://a123456789012345678901234.vault.azure.net",
            "https://my-vault.vault.azure.net\\@evil.com"
    })
    void rejectsUntrustedOrMalformedVaultUrls(String invalidUrl) {
        assertThatThrownBy(() -> validator.validateAndNormalize(invalidUrl))
                .isInstanceOf(AppException.class)
                .satisfies(ex -> assertThat(((AppException) ex).getErrorCode()).isEqualTo("INVALID_VAULT_URI"));
    }

    @Test
    void rejectsNullVaultUrl() {
        assertThatThrownBy(() -> validator.validateAndNormalize(null))
                .isInstanceOf(AppException.class)
                .satisfies(ex -> assertThat(((AppException) ex).getErrorCode()).isEqualTo("INVALID_VAULT_URI"));
    }

    @Test
    void failsClosedWhenPublicCloudOnlyDisabledInMvp() {
        AzureVaultUrlValidator nonPublicValidator = new AzureVaultUrlValidator(false);
        assertThatThrownBy(() -> nonPublicValidator.validateAndNormalize("https://my-vault.vault.usgovcloudapi.net"))
                .isInstanceOf(AppException.class)
                .satisfies(ex -> assertThat(((AppException) ex).getErrorCode()).isEqualTo("INVALID_VAULT_URI"));
    }
}
