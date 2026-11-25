package com.akvoperator.security;

import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.exception.AppException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ProfileStartupValidatorTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void invalidProfileFailsClosed() {
        AppProperties props = new AppProperties();
        props.setProfile("staging");

        ProfileStartupValidator validator = new ProfileStartupValidator(props, objectMapper, "127.0.0.1");
        assertThatThrownBy(validator::validate)
                .isInstanceOf(AppException.class)
                .hasMessageContaining("APP_PROFILE");
    }

    @Test
    void localProfileLoopbackPasses() {
        AppProperties props = new AppProperties();
        props.setProfile("local");

        assertThatCode(() -> new ProfileStartupValidator(props, objectMapper, "127.0.0.1").validate())
                .doesNotThrowAnyException();
        assertThatCode(() -> new ProfileStartupValidator(props, objectMapper, "::1").validate())
                .doesNotThrowAnyException();
        assertThatCode(() -> new ProfileStartupValidator(props, objectMapper, "localhost").validate())
                .doesNotThrowAnyException();
    }

    @Test
    void localProfileNonLoopbackWithoutContainerBindFlagFailsClosed() {
        AppProperties props = new AppProperties();
        props.setProfile("local");
        props.getLocal().setAllowContainerBind(false);

        ProfileStartupValidator validator = new ProfileStartupValidator(props, objectMapper, "0.0.0.0");
        assertThatThrownBy(validator::validate)
                .isInstanceOf(AppException.class)
                .hasMessageContaining("loopback");
    }

    @Test
    void localProfileNonLoopbackWithExplicitContainerBindSucceeds() {
        AppProperties props = new AppProperties();
        props.setProfile("local");
        props.getLocal().setAllowContainerBind(true);

        ProfileStartupValidator validator = new ProfileStartupValidator(props, objectMapper, "0.0.0.0");
        assertThatCode(validator::validate).doesNotThrowAnyException();
    }

    @Test
    void serverProfileMissingAllowlistFailsClosed() {
        AppProperties props = validServerProps();
        props.setAllowedVaultIds(List.of());

        ProfileStartupValidator validator = new ProfileStartupValidator(props, objectMapper, "0.0.0.0");
        assertThatThrownBy(validator::validate)
                .isInstanceOf(AppException.class)
                .hasMessageContaining("APP_ALLOWED_VAULT_IDS");
    }

    @Test
    void serverProfileMissingOrNonHttpsOidcIssuerFailsClosed() {
        AppProperties missingIssuer = validServerProps();
        missingIssuer.getServer().setOidcIssuerUri("");
        assertThatThrownBy(() -> new ProfileStartupValidator(missingIssuer, objectMapper, "0.0.0.0").validate())
                .isInstanceOf(AppException.class)
                .hasMessageContaining("OIDC_ISSUER_URI");

        AppProperties httpIssuer = validServerProps();
        httpIssuer.getServer().setOidcIssuerUri("http://hydra.internal");
        assertThatThrownBy(() -> new ProfileStartupValidator(httpIssuer, objectMapper, "0.0.0.0").validate())
                .isInstanceOf(AppException.class)
                .hasMessageContaining("https://");
    }

    @Test
    void serverProfileMissingOidcClientCredentialsFailsClosed() {
        AppProperties missingClientId = validServerProps();
        missingClientId.getServer().setOidcClientId("");
        assertThatThrownBy(() -> new ProfileStartupValidator(missingClientId, objectMapper, "0.0.0.0").validate())
                .isInstanceOf(AppException.class)
                .hasMessageContaining("OIDC_CLIENT_ID");

        AppProperties missingSecret = validServerProps();
        missingSecret.getServer().setOidcClientSecret("");
        assertThatThrownBy(() -> new ProfileStartupValidator(missingSecret, objectMapper, "0.0.0.0").validate())
                .isInstanceOf(AppException.class)
                .hasMessageContaining("OIDC_CLIENT_SECRET");
    }

    @Test
    void serverProfileMissingOrNonHttpsPublicBaseUrlFailsClosed() {
        AppProperties props = validServerProps();
        props.getServer().setPublicBaseUrl("http://vaults.example.com");

        assertThatThrownBy(() -> new ProfileStartupValidator(props, objectMapper, "0.0.0.0").validate())
                .isInstanceOf(AppException.class)
                .hasMessageContaining("APP_SERVER_PUBLIC_BASE_URL");
    }

    @Test
    void serverProfileInvalidRoleMappingsJsonFailsClosed() {
        AppProperties props = validServerProps();
        props.getServer().setRoleMappingsJson("{not-valid-json");

        assertThatThrownBy(() -> new ProfileStartupValidator(props, objectMapper, "0.0.0.0").validate())
                .isInstanceOf(AppException.class)
                .hasMessageContaining("APP_SERVER_ROLE_MAPPINGS_JSON");
    }

    @Test
    void serverProfileInvalidTrustedProxyCidrFailsClosed() {
        AppProperties props = validServerProps();
        props.getServer().setTrustedProxies(List.of("not-a-cidr"));

        assertThatThrownBy(() -> new ProfileStartupValidator(props, objectMapper, "0.0.0.0").validate())
                .isInstanceOf(AppException.class)
                .hasMessageContaining("APP_SERVER_TRUSTED_PROXIES");
    }

    @Test
    void validServerProfilePasses() {
        AppProperties props = validServerProps();
        props.getServer().setTrustedProxies(List.of("10.0.0.0/8", "172.16.0.0/12"));
        props.getServer().setRoleMappingsJson(
                "[{\"group\":\"vault-admins\",\"vaultResourceId\":\"/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/kv-1\",\"role\":\"ADMIN\"}]"
        );

        assertThatCode(() -> new ProfileStartupValidator(props, objectMapper, "0.0.0.0").validate())
                .doesNotThrowAnyException();
    }

    private static AppProperties validServerProps() {
        AppProperties props = new AppProperties();
        props.setProfile("server");
        props.setAllowedVaultIds(List.of(
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/kv-1"
        ));
        props.getServer().setOidcIssuerUri("https://hydra.example.com");
        props.getServer().setOidcClientId("akv-operator-client");
        props.getServer().setOidcClientSecret("placeholder-oidc-secret");
        props.getServer().setPublicBaseUrl("https://vaults.example.com");
        return props;
    }
}
