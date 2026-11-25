import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ApiService } from './api.service';

describe('ApiService REST contract', () => {
  let service: ApiService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(ApiService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('calls auth status, bootstrap login, and logout with credentials', () => {
    service.getAuthStatus().subscribe();
    const statusReq = httpMock.expectOne('/api/v1/auth/status');
    expect(statusReq.request.method).toBe('GET');
    expect(statusReq.request.withCredentials).toBe(true);
    statusReq.flush({ authenticated: false, profile: 'local', deleteEnabled: false, permissionsByVault: {} });

    service.localBootstrapLogin({ token: 'bootstrap-token-123456' }).subscribe();
    const loginReq = httpMock.expectOne('/api/v1/auth/bootstrap');
    expect(loginReq.request.method).toBe('POST');
    expect(loginReq.request.body).toEqual({ token: 'bootstrap-token-123456' });
    expect(loginReq.request.url).not.toContain('bootstrap-token');
    expect(loginReq.request.withCredentials).toBe(true);
    loginReq.flush({ authenticated: true, profile: 'local', deleteEnabled: false, permissionsByVault: {} });

    service.logout().subscribe();
    const logoutReq = httpMock.expectOne('/api/v1/auth/logout');
    expect(logoutReq.request.method).toBe('POST');
    expect(logoutReq.request.withCredentials).toBe(true);
    logoutReq.flush(null);
  });

  it('calls discovery, snapshot, and refresh endpoints', () => {
    service.listSubscriptions().subscribe();
    const subReq = httpMock.expectOne('/api/v1/subscriptions');
    expect(subReq.request.method).toBe('GET');
    subReq.flush([]);

    service.listVaults('sub-1').subscribe();
    const vaultReq = httpMock.expectOne('/api/v1/vaults?subscriptionId=sub-1');
    expect(vaultReq.request.method).toBe('GET');
    vaultReq.flush([]);

    service.getSecretsSnapshot('vault_opaque_1').subscribe();
    const snapReq = httpMock.expectOne('/api/v1/vaults/vault_opaque_1/secrets');
    expect(snapReq.request.method).toBe('GET');
    snapReq.flush({
      vaultId: 'vault_opaque_1',
      status: 'COMPLETE',
      generationId: 1,
      loadedCount: 0,
      pagesLoaded: 1,
      stale: false,
      items: [],
    });

    service.refreshVaultSecrets('vault_opaque_1').subscribe();
    const refreshReq = httpMock.expectOne('/api/v1/vaults/vault_opaque_1/refresh');
    expect(refreshReq.request.method).toBe('POST');
    refreshReq.flush({
      vaultId: 'vault_opaque_1',
      status: 'LOADING',
      generationId: 2,
      loadedCount: 0,
      pagesLoaded: 0,
      stale: false,
      items: [],
    });
  });

  it('uses POST for reveal and preserves raw whitespace/multiline values in JSON bodies', () => {
    const multilineSecret = '  line1\nline2\t  ';

    service.createSecret('vault_1', { name: 'my-secret', value: multilineSecret }).subscribe();
    const createReq = httpMock.expectOne('/api/v1/vaults/vault_1/secrets');
    expect(createReq.request.method).toBe('POST');
    expect(createReq.request.body.value).toBe(multilineSecret);
    expect(createReq.request.url).not.toContain('line1');
    createReq.flush({ name: 'my-secret', enabled: true });

    service.revealSecret('vault_1', 'my-secret', { version: 'v1' }).subscribe();
    const revealReq = httpMock.expectOne('/api/v1/vaults/vault_1/secrets/my-secret/reveal');
    expect(revealReq.request.method).toBe('POST');
    expect(revealReq.request.body).toEqual({ version: 'v1' });
    revealReq.flush({ name: 'my-secret', version: 'v1', value: multilineSecret });

    service
      .updateSecretValue('vault_1', 'my-secret', {
        value: multilineSecret,
        expectedLatestVersion: 'v1',
        preserveMetadata: true,
      })
      .subscribe();
    const updateReq = httpMock.expectOne('/api/v1/vaults/vault_1/secrets/my-secret');
    expect(updateReq.request.method).toBe('PUT');
    expect(updateReq.request.body.value).toBe(multilineSecret);
    expect(updateReq.request.body.expectedLatestVersion).toBe('v1');
    updateReq.flush({ name: 'my-secret', enabled: true, version: 'v2' });

    service
      .updateSecretProperties('vault_1', 'my-secret', { enabled: false, version: 'v2' })
      .subscribe();
    const patchReq = httpMock.expectOne('/api/v1/vaults/vault_1/secrets/my-secret/properties');
    expect(patchReq.request.method).toBe('PATCH');
    patchReq.flush({ name: 'my-secret', enabled: false, version: 'v2' });
  });

  it('calls versions, soft-delete with confirmation body, deleted-secrets, recover, and operations', () => {
    service.listSecretVersions('vault_1', 'my-secret').subscribe();
    const verReq = httpMock.expectOne('/api/v1/vaults/vault_1/secrets/my-secret/versions');
    expect(verReq.request.method).toBe('GET');
    verReq.flush([]);

    service.softDeleteSecret('vault_1', 'my-secret', { confirmSecretName: 'my-secret' }).subscribe();
    const delReq = httpMock.expectOne('/api/v1/vaults/vault_1/secrets/my-secret');
    expect(delReq.request.method).toBe('DELETE');
    expect(delReq.request.body).toEqual({ confirmSecretName: 'my-secret' });
    delReq.flush({
      operationId: 'op-1',
      vaultId: 'vault_1',
      secretName: 'my-secret',
      operationType: 'SOFT_DELETE',
      state: 'IN_PROGRESS',
      createdAt: '2026-11-25T10:00:00Z',
      updatedAt: '2026-11-25T10:00:00Z',
    });

    service.listDeletedSecrets('vault_1').subscribe();
    const listDelReq = httpMock.expectOne('/api/v1/vaults/vault_1/deleted-secrets');
    expect(listDelReq.request.method).toBe('GET');
    listDelReq.flush([]);

    service.recoverDeletedSecret('vault_1', 'my-secret').subscribe();
    const recReq = httpMock.expectOne('/api/v1/vaults/vault_1/deleted-secrets/my-secret/recover');
    expect(recReq.request.method).toBe('POST');
    recReq.flush({
      operationId: 'op-2',
      vaultId: 'vault_1',
      secretName: 'my-secret',
      operationType: 'RECOVER',
      state: 'PENDING',
      createdAt: '2026-11-25T10:01:00Z',
      updatedAt: '2026-11-25T10:01:00Z',
    });

    service.getOperationStatus('op-2').subscribe();
    const opReq = httpMock.expectOne('/api/v1/operations/op-2');
    expect(opReq.request.method).toBe('GET');
    opReq.flush({
      operationId: 'op-2',
      vaultId: 'vault_1',
      secretName: 'my-secret',
      operationType: 'RECOVER',
      state: 'SUCCEEDED',
      createdAt: '2026-11-25T10:01:00Z',
      updatedAt: '2026-11-25T10:02:00Z',
    });

    // Ensure no permanent purge method exists on ApiService
    expect('purgeDeletedSecret' in service).toBe(false);
    expect('purgeSecret' in service).toBe(false);
  });
});
