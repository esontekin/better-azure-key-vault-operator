package com.akvoperator.azure;

import com.akvoperator.common.config.AppProperties;
import com.azure.core.http.HttpClient;
import com.azure.core.http.netty.NettyAsyncHttpClientBuilder;
import com.azure.core.http.policy.HttpLogDetailLevel;
import com.azure.core.http.policy.HttpLogOptions;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Builds and reuses a hardened Azure SDK {@link HttpClient} with bounded timeouts,
 * disabled HTTP redirects, and strictly disabled SDK HTTP body/header logging.
 */
@Component
public class AzureHttpClientFactory {

    private final HttpClient sharedHttpClient;
    private final NoCrossHostRedirectPolicy noCrossHostRedirectPolicy;

    public AzureHttpClientFactory(AppProperties appProperties) {
        AppProperties.AzureProperties azure = appProperties != null && appProperties.getAzure() != null
                ? appProperties.getAzure()
                : new AppProperties.AzureProperties();

        Duration connectTimeout = azure.getConnectTimeout() != null ? azure.getConnectTimeout() : Duration.ofSeconds(10);
        Duration responseTimeout = azure.getResponseTimeout() != null ? azure.getResponseTimeout() : Duration.ofSeconds(30);

        reactor.netty.http.client.HttpClient nettyClient = reactor.netty.http.client.HttpClient.create()
                .followRedirect(false);

        this.sharedHttpClient = new NettyAsyncHttpClientBuilder(nettyClient)
                .connectTimeout(connectTimeout)
                .responseTimeout(responseTimeout)
                .readTimeout(responseTimeout)
                .writeTimeout(connectTimeout)
                .build();
        this.noCrossHostRedirectPolicy = new NoCrossHostRedirectPolicy();
    }

    public HttpClient getHttpClient() {
        return sharedHttpClient;
    }

    public HttpLogOptions createNoLoggingOptions() {
        return new HttpLogOptions().setLogLevel(HttpLogDetailLevel.NONE);
    }

    public NoCrossHostRedirectPolicy getNoCrossHostRedirectPolicy() {
        return noCrossHostRedirectPolicy;
    }
}
