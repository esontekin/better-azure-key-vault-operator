package com.akvoperator.azure;

import com.akvoperator.common.config.AppProperties;
import com.akvoperator.common.exception.AppException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientSecretCredentialFactoryTest {

    private static final String CANARY_SECRET = "CANARY-SP-SECRET-987654321-DO-NOT-LEAK";

    @Test
    void failsWhenTenantIdIsMissing() {
        AppProperties props = baseProperties();
        props.getAzure().setTenantId("   ");
        props.getAzure().setClientSecret(CANARY_SECRET);

        ClientSecretCredentialFactory factory = new ClientSecretCredentialFactory(props);

        assertThatThrownBy(factory::initialize)
                .isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getErrorCode()).isEqualTo("INVALID_CONFIGURATION");
                    assertThat(appEx.getSafeMessage()).contains("AZURE_TENANT_ID");
                    assertThat(appEx.getSafeMessage()).doesNotContain(CANARY_SECRET);
                });
    }

    @Test
    void failsWhenClientIdIsMissing() {
        AppProperties props = baseProperties();
        props.getAzure().setClientId("");
        props.getAzure().setClientSecret(CANARY_SECRET);

        ClientSecretCredentialFactory factory = new ClientSecretCredentialFactory(props);

        assertThatThrownBy(factory::initialize)
                .isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getErrorCode()).isEqualTo("INVALID_CONFIGURATION");
                    assertThat(appEx.getSafeMessage()).contains("AZURE_CLIENT_ID");
                    assertThat(appEx.getSafeMessage()).doesNotContain(CANARY_SECRET);
                });
    }

    @Test
    void failsWhenNeitherSecretNorSecretFileIsConfigured() {
        AppProperties props = baseProperties();
        ClientSecretCredentialFactory factory = new ClientSecretCredentialFactory(props);

        assertThatThrownBy(factory::initialize)
                .isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getErrorCode()).isEqualTo("INVALID_CONFIGURATION");
                    assertThat(appEx.getSafeMessage()).contains("AZURE_CLIENT_SECRET");
                    assertThat(appEx.getSafeMessage()).contains("AZURE_CLIENT_SECRET_FILE");
                });
    }

    @Test
    void failsWhenBothSecretAndSecretFileAreConfigured(@TempDir Path tempDir) throws Exception {
        Path secretFile = tempDir.resolve("sp-secret.txt");
        Files.writeString(secretFile, CANARY_SECRET + "\n", StandardCharsets.UTF_8);

        AppProperties props = baseProperties();
        props.getAzure().setClientSecret(CANARY_SECRET);
        props.getAzure().setClientSecretFile(secretFile.toString());

        ClientSecretCredentialFactory factory = new ClientSecretCredentialFactory(props);

        assertThatThrownBy(factory::initialize)
                .isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getErrorCode()).isEqualTo("INVALID_CONFIGURATION");
                    assertThat(appEx.getSafeMessage()).contains("Both AZURE_CLIENT_SECRET and AZURE_CLIENT_SECRET_FILE");
                    assertThat(appEx.getSafeMessage()).doesNotContain(CANARY_SECRET);
                });
    }

    @Test
    void succeedsWithInlineClientSecretAndRedactsToString() {
        AppProperties props = baseProperties();
        props.getAzure().setClientSecret(CANARY_SECRET);

        ClientSecretCredentialFactory factory = new ClientSecretCredentialFactory(props);
        factory.initialize();

        assertThat(factory.getCredential()).isNotNull();
        assertThat(factory.getCredential()).isSameAs(factory.getCredential());
        assertThat(factory.getTenantId()).isEqualTo("11111111-1111-1111-1111-111111111111");
        assertThat(factory.getClientId()).isEqualTo("22222222-2222-2222-2222-222222222222");
        assertThat(factory.getCredentialContextId()).hasSize(64);
        assertThat(factory.getCredentialContextId()).doesNotContain(CANARY_SECRET);
        assertThat(factory.toString()).contains("[REDACTED]").doesNotContain(CANARY_SECRET);
    }

    @Test
    void succeedsWithClientSecretFile(@TempDir Path tempDir) throws Exception {
        Path secretFile = tempDir.resolve("azure-secret");
        Files.writeString(secretFile, CANARY_SECRET + "\r\n", StandardCharsets.UTF_8);

        AppProperties props = baseProperties();
        props.getAzure().setClientSecretFile(secretFile.toString());

        ClientSecretCredentialFactory factory = new ClientSecretCredentialFactory(props);
        factory.initialize();

        assertThat(factory.getCredential()).isNotNull();
        assertThat(factory.getCredentialContextId()).hasSize(64);
        assertThat(factory.toString()).contains("[REDACTED]").doesNotContain(CANARY_SECRET);
    }

    @Test
    void failsWhenClientSecretFileDoesNotExist(@TempDir Path tempDir) {
        Path missingFile = tempDir.resolve("does-not-exist.secret");

        AppProperties props = baseProperties();
        props.getAzure().setClientSecretFile(missingFile.toString());

        ClientSecretCredentialFactory factory = new ClientSecretCredentialFactory(props);

        assertThatThrownBy(factory::initialize)
                .isInstanceOf(AppException.class)
                .satisfies(ex -> {
                    AppException appEx = (AppException) ex;
                    assertThat(appEx.getErrorCode()).isEqualTo("INVALID_CONFIGURATION");
                    assertThat(appEx.getSafeMessage()).contains("AZURE_CLIENT_SECRET_FILE");
                });
    }

    @Test
    void failsWhenClientSecretFileIsEmpty(@TempDir Path tempDir) throws Exception {
        Path emptyFile = tempDir.resolve("empty.secret");
        Files.writeString(emptyFile, "\r\n", StandardCharsets.UTF_8);

        AppProperties props = baseProperties();
        props.getAzure().setClientSecretFile(emptyFile.toString());

        ClientSecretCredentialFactory factory = new ClientSecretCredentialFactory(props);

        assertThatThrownBy(factory::initialize)
                .isInstanceOf(AppException.class)
                .satisfies(ex -> assertThat(((AppException) ex).getErrorCode()).isEqualTo("INVALID_CONFIGURATION"));
    }

    private static AppProperties baseProperties() {
        AppProperties props = new AppProperties();
        props.getAzure().setTenantId("11111111-1111-1111-1111-111111111111");
        props.getAzure().setClientId("22222222-2222-2222-2222-222222222222");
        return props;
    }
}
