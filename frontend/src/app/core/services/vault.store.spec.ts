import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { VaultStore } from './vault.store';

describe('VaultStore progressive loading & generation ordering', () => {
  let store: VaultStore;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    vi.useFakeTimers();
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    store = TestBed.inject(VaultStore);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    store.ngOnDestroy();
    httpMock.verify();
    vi.useRealTimers();
  });

  it('triggers refresh when IDLE, polls while LOADING, and allows searching from first page', async () => {
    const selectPromise = store.selectVault('vault-01');

    // Initial GET returns IDLE -> triggers POST /refresh
    const initialGet = httpMock.expectOne('/api/v1/vaults/vault-01/secrets');
    initialGet.flush({
      vaultId: 'vault-01',
      status: 'IDLE',
      generationId: 1,
      loadedCount: 0,
      pagesLoaded: 0,
      stale: false,
      items: [],
    });

    await Promise.resolve();

    const refreshPost = httpMock.expectOne('/api/v1/vaults/vault-01/refresh');
    expect(refreshPost.request.method).toBe('POST');
    refreshPost.flush({
      vaultId: 'vault-01',
      status: 'LOADING',
      generationId: 2,
      loadedCount: 1,
      pagesLoaded: 1,
      stale: false,
      items: [{ name: 'page1-db-password', enabled: true }],
    });

    await selectPromise;

    // Search works immediately after page 1 while still LOADING
    store.updateSearchCriteria({ query: 'page1' });
    expect(store.filteredSecrets().map((s) => s.name)).toEqual(['page1-db-password']);

    // Advance poll timer -> receives COMPLETE with page 2 included
    vi.advanceTimersByTime(1200);
    const pollGet = httpMock.expectOne('/api/v1/vaults/vault-01/secrets');
    pollGet.flush({
      vaultId: 'vault-01',
      status: 'COMPLETE',
      generationId: 2,
      loadedCount: 2,
      pagesLoaded: 2,
      stale: false,
      items: [
        { name: 'page1-db-password', enabled: true },
        { name: 'page2-api-secret', enabled: true },
      ],
    });
    await Promise.resolve();

    store.updateSearchCriteria({ query: 'page2' });
    expect(store.filteredSecrets().map((s) => s.name)).toEqual(['page2-api-secret']);
  });

  it('ignores out-of-order snapshots with older generationId', async () => {
    const selectPromise = store.selectVault('vault-02');
    httpMock.expectOne('/api/v1/vaults/vault-02/secrets').flush({
      vaultId: 'vault-02',
      status: 'COMPLETE',
      generationId: 10,
      loadedCount: 1,
      pagesLoaded: 1,
      stale: false,
      items: [{ name: 'fresh-secret', enabled: true }],
    });
    await selectPromise;

    const reloadPromise = store.reloadCurrentSnapshot();
    httpMock.expectOne('/api/v1/vaults/vault-02/secrets').flush({
      vaultId: 'vault-02',
      status: 'COMPLETE',
      generationId: 9,
      loadedCount: 1,
      pagesLoaded: 1,
      stale: true,
      items: [{ name: 'stale-secret', enabled: true }],
    });
    await reloadPromise;

    expect(store.snapshot()?.generationId).toBe(10);
    expect(store.snapshot()?.items.map((s) => s.name)).toEqual(['fresh-secret']);
  });
});
