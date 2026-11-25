import { Injectable, OnDestroy, computed, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import {
  ProblemDetail,
  SecretListSnapshotResponse,
  SecretMetadataDto,
  SubscriptionDto,
  VaultDto,
} from '../models/api.models';
import { ApiService } from './api.service';
import { AuthStore } from './auth.store';
import {
  DEFAULT_SEARCH_CRITERIA,
  SecretSearchCriteria,
  SecretSearchIndex,
} from './secret-search.engine';
import { extractProblemDetail } from '../utils/secret-validation.util';

const SNAPSHOT_POLL_INTERVAL_MS = 1200;

@Injectable({ providedIn: 'root' })
export class VaultStore implements OnDestroy {
  private readonly api = inject(ApiService);
  private readonly authStore = inject(AuthStore);

  readonly subscriptions = signal<SubscriptionDto[]>([]);
  readonly vaults = signal<VaultDto[]>([]);
  readonly selectedSubscriptionId = signal<string>('');
  readonly selectedVaultId = signal<string | null>(null);
  readonly loadingVaults = signal<boolean>(false);
  readonly snapshot = signal<SecretListSnapshotResponse | null>(null);
  readonly snapshotLoadingInitial = signal<boolean>(false);
  readonly error = signal<ProblemDetail | null>(null);
  readonly connected = signal<boolean>(true);

  readonly searchCriteria = signal<SecretSearchCriteria>({ ...DEFAULT_SEARCH_CRITERIA });

  readonly selectedVault = computed<VaultDto | null>(() => {
    const id = this.selectedVaultId();
    if (!id) {
      return null;
    }
    return this.vaults().find((v) => v.id === id) ?? null;
  });

  readonly filteredVaults = computed<VaultDto[]>(() => {
    const subId = this.selectedSubscriptionId();
    const list = this.vaults();
    if (!subId) {
      return list;
    }
    return list.filter((v) => v.subscriptionId === subId);
  });

  private readonly searchIndex = computed<SecretSearchIndex>(
    () => new SecretSearchIndex(this.snapshot()?.items ?? [])
  );

  readonly filteredSecrets = computed<SecretMetadataDto[]>(() =>
    this.searchIndex().search(this.searchCriteria())
  );

  private pollTimer: ReturnType<typeof setTimeout> | null = null;
  private activeVaultRequestSeq = 0;

  ngOnDestroy(): void {
    this.stopPolling();
  }

  async loadDiscovery(): Promise<void> {
    this.loadingVaults.set(true);
    this.error.set(null);
    try {
      const [subs, vaults] = await Promise.all([
        firstValueFrom(this.api.listSubscriptions()).catch(() => [] as SubscriptionDto[]),
        firstValueFrom(this.api.listVaults()),
      ]);
      this.subscriptions.set(subs);
      this.vaults.set(vaults);
      this.connected.set(true);

      const currentId = this.selectedVaultId();
      if (currentId && !vaults.some((v) => v.id === currentId)) {
        this.selectedVaultId.set(null);
        this.snapshot.set(null);
        this.stopPolling();
      } else if (!currentId && vaults.length === 1) {
        await this.selectVault(vaults[0].id);
      }
    } catch (err) {
      const problem = extractProblemDetail(err);
      this.error.set(problem);
      this.connected.set(problem.status !== 0);
      this.authStore.handleApiError(problem);
    } finally {
      this.loadingVaults.set(false);
    }
  }

  selectSubscription(subscriptionId: string): void {
    this.selectedSubscriptionId.set(subscriptionId);
  }

  async selectVault(vaultId: string): Promise<void> {
    this.stopPolling();
    const requestSeq = ++this.activeVaultRequestSeq;
    this.selectedVaultId.set(vaultId);
    this.snapshot.set(null);
    this.error.set(null);
    this.snapshotLoadingInitial.set(true);

    try {
      const snap = await firstValueFrom(this.api.getSecretsSnapshot(vaultId));
      if (requestSeq !== this.activeVaultRequestSeq) {
        return;
      }
      this.connected.set(true);
      this.applySnapshot(snap);

      if (snap.status === 'IDLE') {
        await this.triggerRefresh();
      } else if (snap.status === 'LOADING') {
        this.schedulePoll(vaultId, requestSeq);
      }
    } catch (err) {
      if (requestSeq !== this.activeVaultRequestSeq) {
        return;
      }
      const problem = extractProblemDetail(err);
      this.error.set(problem);
      this.connected.set(problem.status !== 0);
      this.authStore.handleApiError(problem);
    } finally {
      if (requestSeq === this.activeVaultRequestSeq) {
        this.snapshotLoadingInitial.set(false);
      }
    }
  }

  async triggerRefresh(): Promise<void> {
    const vaultId = this.selectedVaultId();
    if (!vaultId) {
      return;
    }
    this.stopPolling();
    const requestSeq = ++this.activeVaultRequestSeq;
    this.error.set(null);
    try {
      const snap = await firstValueFrom(this.api.refreshVaultSecrets(vaultId));
      if (requestSeq !== this.activeVaultRequestSeq) {
        return;
      }
      this.connected.set(true);
      this.applySnapshot(snap);
      if (snap.status === 'LOADING') {
        this.schedulePoll(vaultId, requestSeq);
      }
    } catch (err) {
      if (requestSeq !== this.activeVaultRequestSeq) {
        return;
      }
      const problem = extractProblemDetail(err);
      this.error.set(problem);
      this.connected.set(problem.status !== 0);
      this.authStore.handleApiError(problem);
    }
  }

  async reloadCurrentSnapshot(): Promise<void> {
    const vaultId = this.selectedVaultId();
    if (!vaultId) {
      return;
    }
    const requestSeq = this.activeVaultRequestSeq;
    try {
      const snap = await firstValueFrom(this.api.getSecretsSnapshot(vaultId));
      if (requestSeq !== this.activeVaultRequestSeq || this.selectedVaultId() !== vaultId) {
        return;
      }
      this.connected.set(true);
      this.applySnapshot(snap);
      if (snap.status === 'LOADING') {
        this.schedulePoll(vaultId, requestSeq);
      }
    } catch (err) {
      const problem = extractProblemDetail(err);
      this.error.set(problem);
      this.connected.set(problem.status !== 0);
      this.authStore.handleApiError(problem);
    }
  }

  updateSearchCriteria(patch: Partial<SecretSearchCriteria>): void {
    this.searchCriteria.update((current) => ({ ...current, ...patch }));
  }

  resetSearchCriteria(): void {
    this.searchCriteria.set({ ...DEFAULT_SEARCH_CRITERIA });
  }

  clearError(): void {
    this.error.set(null);
  }

  reset(): void {
    this.stopPolling();
    this.activeVaultRequestSeq++;
    this.subscriptions.set([]);
    this.vaults.set([]);
    this.selectedSubscriptionId.set('');
    this.selectedVaultId.set(null);
    this.snapshot.set(null);
    this.error.set(null);
    this.resetSearchCriteria();
  }

  private applySnapshot(incoming: SecretListSnapshotResponse): void {
    const current = this.snapshot();
    if (
      current &&
      current.vaultId === incoming.vaultId &&
      incoming.generationId < current.generationId
    ) {
      return;
    }
    this.snapshot.set(incoming);
  }

  private schedulePoll(vaultId: string, requestSeq: number): void {
    this.stopPolling();
    this.pollTimer = setTimeout(async () => {
      if (requestSeq !== this.activeVaultRequestSeq || this.selectedVaultId() !== vaultId) {
        return;
      }
      try {
        const snap = await firstValueFrom(this.api.getSecretsSnapshot(vaultId));
        if (requestSeq !== this.activeVaultRequestSeq || this.selectedVaultId() !== vaultId) {
          return;
        }
        this.connected.set(true);
        this.applySnapshot(snap);
        if (snap.status === 'LOADING') {
          this.schedulePoll(vaultId, requestSeq);
        }
      } catch (err) {
        if (requestSeq !== this.activeVaultRequestSeq) {
          return;
        }
        const problem = extractProblemDetail(err);
        this.error.set(problem);
        this.connected.set(problem.status !== 0);
        this.authStore.handleApiError(problem);
      }
    }, SNAPSHOT_POLL_INTERVAL_MS);
  }

  private stopPolling(): void {
    if (this.pollTimer !== null) {
      clearTimeout(this.pollTimer);
      this.pollTimer = null;
    }
  }
}
