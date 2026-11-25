import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentRef } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretMetadataDto, VaultDto } from '../core/models/api.models';
import { AuthStore } from '../core/services/auth.store';
import {
  REVEAL_AUTO_CLEAR_SECONDS,
  SecretDetailDrawerComponent,
} from './secret-detail-drawer.component';

describe('SecretDetailDrawerComponent security & reveal lifecycle', () => {
  let httpMock: HttpTestingController;
  let authStore: AuthStore;

  const vaultA: VaultDto = {
    id: 'vault-alpha-01',
    name: 'kv-prod-payments',
    vaultUri: 'https://kv-prod-payments.vault.azure.net',
    environment: 'prod',
    production: true,
    source: 'ARM_DISCOVERY',
    permissions: ['SECRET_LIST', 'SECRET_REVEAL', 'SECRET_WRITE', 'SECRET_DELETE_RECOVER'],
  };

  const vaultB: VaultDto = {
    ...vaultA,
    id: 'vault-beta-02',
    name: 'kv-dev-payments',
    environment: 'dev',
    production: false,
  };

  const secretOne: SecretMetadataDto = {
    name: 'payment-gateway-key',
    version: 'v1',
    enabled: true,
    updatedOn: '2026-11-25T10:00:00Z',
  };

  const secretTwo: SecretMetadataDto = {
    name: 'webhook-signing-key',
    version: 'v2',
    enabled: true,
    updatedOn: '2026-11-25T10:05:00Z',
  };

  const canaryValue = 'CANARY_SECRET_VALUE_DO_NOT_LEAK_99182';

  beforeEach(() => {
    vi.useFakeTimers();
    localStorage.clear();
    sessionStorage.clear();

    TestBed.configureTestingModule({
      imports: [SecretDetailDrawerComponent],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });

    httpMock = TestBed.inject(HttpTestingController);
    authStore = TestBed.inject(AuthStore);
    authStore.status.set({
      authenticated: true,
      subject: 'local-operator',
      profile: 'local',
      deleteEnabled: true,
      permissionsByVault: {
        [vaultA.id]: vaultA.permissions,
        [vaultB.id]: vaultB.permissions,
      },
    });
  });

  afterEach(() => {
    httpMock.verify();
    vi.useRealTimers();
    localStorage.clear();
    sessionStorage.clear();
  });

  function createComponent(): {
    fixture: ReturnType<typeof TestBed.createComponent<SecretDetailDrawerComponent>>;
    ref: ComponentRef<SecretDetailDrawerComponent>;
  } {
    const fixture = TestBed.createComponent(SecretDetailDrawerComponent);
    const ref = fixture.componentRef;
    ref.setInput('vault', vaultA);
    ref.setInput('secret', secretOne);
    fixture.detectChanges();
    return { fixture, ref };
  }

  it('starts masked with zero reveal network calls and exposes no permanent purge controls', () => {
    const { fixture } = createComponent();
    const el = fixture.nativeElement as HTMLElement;

    expect(el.querySelector('[data-testid="masked-secret-box"]')).not.toBeNull();
    expect(el.querySelector('[data-testid="revealed-secret-value"]')).toBeNull();
    expect(el.textContent?.toLowerCase()).not.toContain('purge now');
    httpMock.expectNone('/api/v1/vaults/vault-alpha-01/secrets/payment-gateway-key/reveal');
  });

  it('reveals only on explicit click, auto-clears after 30 seconds, and never writes to storage', async () => {
    const { fixture } = createComponent();
    const el = fixture.nativeElement as HTMLElement;

    const revealBtn = el.querySelector('[data-testid="reveal-secret-btn"]') as HTMLButtonElement;
    revealBtn.click();
    fixture.detectChanges();

    const req = httpMock.expectOne('/api/v1/vaults/vault-alpha-01/secrets/payment-gateway-key/reveal');
    expect(req.request.method).toBe('POST');
    req.flush({ name: secretOne.name, version: 'v1', value: canaryValue });

    await Promise.resolve();
    fixture.detectChanges();

    const revealedBox = el.querySelector('[data-testid="revealed-secret-value"]');
    expect(revealedBox?.textContent).toBe(canaryValue);

    // Verify zero canary leakage to browser storage or URL
    expect(JSON.stringify(localStorage)).not.toContain(canaryValue);
    expect(JSON.stringify(sessionStorage)).not.toContain(canaryValue);
    expect(window.location.href).not.toContain(canaryValue);

    // Advance 29s -> still visible
    vi.advanceTimersByTime((REVEAL_AUTO_CLEAR_SECONDS - 1) * 1000);
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="revealed-secret-value"]')?.textContent).toBe(canaryValue);

    // Advance 1s more (30s total) -> automatically cleared!
    vi.advanceTimersByTime(1000);
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="revealed-secret-value"]')).toBeNull();
    expect(el.querySelector('[data-testid="masked-secret-box"]')).not.toBeNull();
  });

  it('immediately clears revealed secret when switching secret or switching vault', async () => {
    const { fixture, ref } = createComponent();
    const el = fixture.nativeElement as HTMLElement;

    (el.querySelector('[data-testid="reveal-secret-btn"]') as HTMLButtonElement).click();
    const req1 = httpMock.expectOne('/api/v1/vaults/vault-alpha-01/secrets/payment-gateway-key/reveal');
    req1.flush({ name: secretOne.name, version: 'v1', value: canaryValue });
    await Promise.resolve();
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="revealed-secret-value"]')?.textContent).toBe(canaryValue);

    // Switch secret -> immediately cleared
    ref.setInput('secret', secretTwo);
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="revealed-secret-value"]')).toBeNull();

    // Reveal second secret then switch vault -> immediately cleared
    (el.querySelector('[data-testid="reveal-secret-btn"]') as HTMLButtonElement).click();
    const req2 = httpMock.expectOne('/api/v1/vaults/vault-alpha-01/secrets/webhook-signing-key/reveal');
    req2.flush({ name: secretTwo.name, version: 'v2', value: canaryValue });
    await Promise.resolve();
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="revealed-secret-value"]')?.textContent).toBe(canaryValue);

    ref.setInput('vault', vaultB);
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="revealed-secret-value"]')).toBeNull();
  });
});
