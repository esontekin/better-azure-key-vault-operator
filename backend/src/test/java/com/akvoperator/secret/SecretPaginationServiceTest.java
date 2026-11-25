package com.akvoperator.secret;

import com.akvoperator.azure.AzureExceptionTranslator;
import com.akvoperator.azure.SecretClientProvider;
import com.akvoperator.cache.SecretMetadataCache;
import com.akvoperator.cache.SecretSnapshotState;
import com.akvoperator.cache.VaultCacheKey;
import com.akvoperator.common.dto.SecretMetadataDto;
import com.akvoperator.common.dto.SyncStatus;
import com.akvoperator.common.dto.VaultSource;
import com.akvoperator.vault.VaultDescriptor;
import com.azure.core.exception.HttpResponseException;
import com.azure.core.http.HttpResponse;
import com.azure.core.http.rest.PagedIterable;
import com.azure.core.http.rest.PagedResponse;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.azure.security.keyvault.secrets.models.SecretProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SecretPaginationServiceTest {

    private ExecutorService executor;
    private SecretClientProvider clientProvider;
    private SecretClient readClient;
    private SecretMetadataCache cache;
    private SecretPaginationService paginationService;
    private VaultDescriptor vault;

    @BeforeEach
    void setUp() {
        executor = Executors.newFixedThreadPool(4);
        clientProvider = mock(SecretClientProvider.class);
        readClient = mock(SecretClient.class);
        cache = new SecretMetadataCache(50, Duration.ofMinutes(5), System::nanoTime);
        paginationService = new SecretPaginationService(
                clientProvider,
                cache,
                new AzureExceptionTranslator(),
                executor
        );
        vault = new VaultDescriptor(
                "vault_opaque_01",
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.KeyVault/vaults/kv-test",
                "kv-test",
                "sub-1",
                "rg-1",
                "westeurope",
                "https://kv-test.vault.azure.net",
                "dev",
                false,
                VaultSource.ARM_DISCOVERY
        );
        when(clientProvider.getTenantId()).thenReturn("tenant-1");
        when(clientProvider.getCredentialContextId()).thenReturn("ctx-1");
        when(clientProvider.getReadClient(vault)).thenReturn(readClient);
    }

    @AfterEach
    void tearDown() {
        executor.shutdownNow();
    }

    @Test
    void walksAllContinuationPagesIncludingEmptyMiddlePageAndDeduplicatesWithoutCallingGetSecret() throws Exception {
        PagedResponse<SecretProperties> page1 = mockPage(List.of(
                secretProps("secret-1", "v1"),
                secretProps("secret-2", "v1")
        ));
        PagedResponse<SecretProperties> emptyPage2 = mockPage(List.of());
        PagedResponse<SecretProperties> page3 = mockPage(List.of(
                secretProps("secret-2", "v2"), // duplicate name updated
                secretProps("secret-3", "v1"),
                secretProps("secret-4", "v1")
        ));

        PagedIterable<SecretProperties> pagedIterable = mockPagedIterable(List.of(page1, emptyPage2, page3));
        when(readClient.listPropertiesOfSecrets()).thenReturn(pagedIterable);

        paginationService.startOrCoalesceRefresh(vault);
        awaitRefresh();

        SecretSnapshotState state = cache.get(paginationService.cacheKeyFor(vault)).orElseThrow();
        assertThat(state.status()).isEqualTo(SyncStatus.COMPLETE);
        assertThat(state.pagesLoaded()).isEqualTo(3);
        assertThat(state.loadedCount()).isEqualTo(4);
        assertThat(state.stale()).isFalse();
        assertThat(state.lastSuccessfulSyncAt()).isNotNull();
        assertThat(state.items()).extracting(SecretMetadataDto::name)
                .containsExactly("secret-1", "secret-2", "secret-3", "secret-4");
        assertThat(state.items().get(1).version()).isEqualTo("v2");

        verify(readClient, never()).getSecret(anyString());
        verify(readClient, never()).getSecret(anyString(), anyString());
    }

    @Test
    void publishesProgressiveSnapshotImmediatelyAfterPageOneWhileLaterPagesAreLoading() throws Exception {
        CountDownLatch page1Published = new CountDownLatch(1);
        CountDownLatch allowPage2 = new CountDownLatch(1);

        PagedResponse<SecretProperties> page1 = mockPage(List.of(secretProps("first-secret", "v1")));
        PagedResponse<SecretProperties> page2 = mockPage(List.of(secretProps("second-secret", "v1")));

        Iterable<PagedResponse<SecretProperties>> gatedIterable = () -> new Iterator<>() {
            int idx = 0;

            @Override
            public boolean hasNext() {
                if (idx == 1) {
                    page1Published.countDown();
                    try {
                        allowPage2.await(5, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
                return idx < 2;
            }

            @Override
            public PagedResponse<SecretProperties> next() {
                if (idx == 0) {
                    idx++;
                    return page1;
                }
                if (idx == 1) {
                    idx++;
                    return page2;
                }
                throw new NoSuchElementException();
            }
        };

        @SuppressWarnings("unchecked")
        PagedIterable<SecretProperties> pagedIterable = mock(PagedIterable.class);
        when(pagedIterable.iterableByPage()).thenReturn(gatedIterable);
        when(readClient.listPropertiesOfSecrets()).thenReturn(pagedIterable);

        paginationService.startOrCoalesceRefresh(vault);

        assertThat(page1Published.await(5, TimeUnit.SECONDS)).isTrue();
        // Wait briefly for page 1 snapshot publication
        SecretSnapshotState midFlight = cache.get(paginationService.cacheKeyFor(vault)).orElseThrow();
        assertThat(midFlight.status()).isEqualTo(SyncStatus.LOADING);
        assertThat(midFlight.pagesLoaded()).isEqualTo(1);
        assertThat(midFlight.loadedCount()).isEqualTo(1);
        assertThat(midFlight.items()).extracting(SecretMetadataDto::name).containsExactly("first-secret");

        allowPage2.countDown();
        awaitRefresh();

        SecretSnapshotState finished = cache.get(paginationService.cacheKeyFor(vault)).orElseThrow();
        assertThat(finished.status()).isEqualTo(SyncStatus.COMPLETE);
        assertThat(finished.pagesLoaded()).isEqualTo(2);
        assertThat(finished.loadedCount()).isEqualTo(2);
        assertThat(finished.items()).extracting(SecretMetadataDto::name).containsExactly("first-secret", "second-secret");
    }

    @Test
    void publishesPartialErrorWithRetainedItemsWhenSecondPageFails() throws Exception {
        PagedResponse<SecretProperties> page1 = mockPage(List.of(
                secretProps("alpha", "v1"),
                secretProps("beta", "v1")
        ));

        HttpResponse response429 = mock(HttpResponse.class);
        when(response429.getStatusCode()).thenReturn(429);
        HttpResponseException throttled = new HttpResponseException("Too many requests", response429);

        Iterable<PagedResponse<SecretProperties>> failingIterable = () -> new Iterator<>() {
            int idx = 0;

            @Override
            public boolean hasNext() {
                return idx < 2;
            }

            @Override
            public PagedResponse<SecretProperties> next() {
                if (idx == 0) {
                    idx++;
                    return page1;
                }
                idx++;
                throw throttled;
            }
        };

        @SuppressWarnings("unchecked")
        PagedIterable<SecretProperties> pagedIterable = mock(PagedIterable.class);
        when(pagedIterable.iterableByPage()).thenReturn(failingIterable);
        when(readClient.listPropertiesOfSecrets()).thenReturn(pagedIterable);

        paginationService.startOrCoalesceRefresh(vault);
        awaitRefresh();

        SecretSnapshotState state = cache.get(paginationService.cacheKeyFor(vault)).orElseThrow();
        assertThat(state.status()).isEqualTo(SyncStatus.PARTIAL_ERROR);
        assertThat(state.stale()).isTrue();
        assertThat(state.pagesLoaded()).isEqualTo(1);
        assertThat(state.loadedCount()).isEqualTo(2);
        assertThat(state.errorCode()).isEqualTo("AZURE_THROTTLED");
        assertThat(state.errorMessage()).isNotBlank();
        assertThat(state.items()).extracting(SecretMetadataDto::name).containsExactly("alpha", "beta");
    }

    @Test
    void retainsPreviousSuccessfulSnapshotAsStaleWhenSubsequentRefreshFailsOnPageOne() throws Exception {
        // First refresh succeeds
        PagedResponse<SecretProperties> okPage = mockPage(List.of(secretProps("existing-secret", "v1")));
        PagedIterable<SecretProperties> firstIterable = mockPagedIterable(List.of(okPage));
        when(readClient.listPropertiesOfSecrets()).thenReturn(firstIterable);

        paginationService.startOrCoalesceRefresh(vault);
        awaitRefresh();

        SecretSnapshotState firstSuccess = cache.get(paginationService.cacheKeyFor(vault)).orElseThrow();
        assertThat(firstSuccess.status()).isEqualTo(SyncStatus.COMPLETE);
        assertThat(firstSuccess.lastSuccessfulSyncAt()).isNotNull();

        // Second refresh fails immediately on page 1
        HttpResponse response503 = mock(HttpResponse.class);
        when(response503.getStatusCode()).thenReturn(503);
        when(readClient.listPropertiesOfSecrets()).thenThrow(new HttpResponseException("Service unavailable", response503));

        paginationService.startOrCoalesceRefresh(vault);
        awaitRefresh();

        SecretSnapshotState failed = cache.get(paginationService.cacheKeyFor(vault)).orElseThrow();
        assertThat(failed.status()).isEqualTo(SyncStatus.ERROR);
        assertThat(failed.stale()).isTrue();
        assertThat(failed.errorCode()).isEqualTo("AZURE_UPSTREAM_ERROR");
        assertThat(failed.lastSuccessfulSyncAt()).isEqualTo(firstSuccess.lastSuccessfulSyncAt());
        assertThat(failed.items()).extracting(SecretMetadataDto::name).containsExactly("existing-secret");
    }

    @Test
    void coalescesConcurrentRefreshesIntoSingleAzureListCall() throws Exception {
        CountDownLatch insideList = new CountDownLatch(1);
        CountDownLatch releaseList = new CountDownLatch(1);
        AtomicInteger listCallCount = new AtomicInteger(0);

        PagedResponse<SecretProperties> page1 = mockPage(List.of(secretProps("shared", "v1")));
        PagedIterable<SecretProperties> sharedIterable = mockPagedIterable(List.of(page1));
        when(readClient.listPropertiesOfSecrets()).thenAnswer(invocation -> {
            listCallCount.incrementAndGet();
            insideList.countDown();
            releaseList.await(5, TimeUnit.SECONDS);
            return sharedIterable;
        });

        paginationService.startOrCoalesceRefresh(vault);
        assertThat(insideList.await(5, TimeUnit.SECONDS)).isTrue();

        // Second concurrent call while first is still LOADING must coalesce
        SecretSnapshotState coalesced = paginationService.startOrCoalesceRefresh(vault);
        assertThat(coalesced.status()).isEqualTo(SyncStatus.LOADING);

        releaseList.countDown();
        awaitRefresh();

        assertThat(listCallCount.get()).isEqualTo(1);
        verify(readClient, times(1)).listPropertiesOfSecrets();
    }

    private void awaitRefresh() throws Exception {
        VaultCacheKey key = paginationService.cacheKeyFor(vault);
        CompletableFuture<Void> future = paginationService.getInFlightRefresh(key).orElse(null);
        if (future != null) {
            future.get(5, TimeUnit.SECONDS);
        }
    }

    @SuppressWarnings("unchecked")
    private static PagedResponse<SecretProperties> mockPage(List<SecretProperties> items) {
        PagedResponse<SecretProperties> page = mock(PagedResponse.class);
        when(page.getValue()).thenReturn(items);
        return page;
    }

    @SuppressWarnings("unchecked")
    private static PagedIterable<SecretProperties> mockPagedIterable(List<PagedResponse<SecretProperties>> pages) {
        PagedIterable<SecretProperties> iterable = mock(PagedIterable.class);
        when(iterable.iterableByPage()).thenReturn(pages);
        return iterable;
    }

    private static SecretProperties secretProps(String name, String version) {
        SecretProperties props = spy(new KeyVaultSecret(name, "").getProperties());
        doReturn(version).when(props).getVersion();
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        doReturn(now).when(props).getCreatedOn();
        doReturn(now).when(props).getUpdatedOn();
        props.setEnabled(true);
        return props;
    }
}
