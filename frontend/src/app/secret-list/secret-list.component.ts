import { ScrollingModule } from '@angular/cdk/scrolling';
import { ChangeDetectionStrategy, Component, computed, inject, output } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { I18nService } from '../core/i18n/i18n.service';
import { SecretMetadataDto, VaultDto } from '../core/models/api.models';
import { AuthStore } from '../core/services/auth.store';
import {
  ExpirationFilter,
  SearchMatchMode,
  SortField,
  StatusFilter,
} from '../core/services/secret-search.engine';
import { VaultStore } from '../core/services/vault.store';
import { formatUtcTimestamp } from '../core/utils/secret-validation.util';

const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

@Component({
  selector: 'app-secret-list',
  standalone: true,
  imports: [FormsModule, ScrollingModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="secret-panel" [attr.aria-label]="i18n.t().app.activeSecretsTab">
      <div class="sticky-controls">
      <!-- Sync & Actions Toolbar -->
      <div class="toolbar">
        <div class="toolbar__stats">
          <span
            class="sync-pill"
            [class]="'sync-pill sync-pill--' + (snapshot()?.status?.toLowerCase() || 'idle')"
          >
            @if (snapshot()?.status === 'LOADING') {
              <span class="spinner" aria-hidden="true"></span>
            }
            {{ syncStatusLabel() }}
          </span>
          <span class="stat-chip">
            {{ i18n.t().secrets.loadedCount }}:
            <strong>{{ snapshot()?.loadedCount ?? 0 }}</strong>
          </span>
          <span class="stat-chip">
            {{ i18n.t().secrets.pagesLoaded }}:
            <strong>{{ snapshot()?.pagesLoaded ?? 0 }}</strong>
          </span>
          <span class="stat-chip">
            {{ i18n.t().secrets.filteredCount }}:
            <strong>{{ vaultStore.filteredSecrets().length }}</strong>
          </span>
          <span class="stat-meta">
            {{ i18n.t().secrets.lastSync }}:
            <strong>{{ lastSyncFormatted() }}</strong>
          </span>
        </div>

        <div class="toolbar__actions">
          <button
            type="button"
            class="btn btn--secondary btn--sm"
            [disabled]="!vault() || snapshot()?.status === 'LOADING'"
            (click)="vaultStore.triggerRefresh()"
          >
            ↻ {{ i18n.t().secrets.refresh }}
          </button>

          <button
            type="button"
            class="btn btn--primary btn--sm"
            [disabled]="!canWrite()"
            [title]="canWrite() ? i18n.t().secrets.newSecret : i18n.t().secrets.unauthorizedTooltip"
            (click)="createSecret.emit()"
          >
            + {{ i18n.t().secrets.newSecret }}
          </button>
        </div>
      </div>

      <!-- Stale / Partial Warnings -->
      @if (snapshot()?.stale) {
        <div class="notice-banner notice-banner--warn" role="status">
          ⚠ {{ i18n.t().secrets.staleWarning }}
        </div>
      }
      @if (snapshot()?.status === 'PARTIAL_ERROR') {
        <div class="notice-banner notice-banner--warn" role="alert">
          ⚠ {{ i18n.t().secrets.partialWarning }}
          @if (snapshot()?.errorMessage) {
            <span>({{ snapshot()?.errorMessage }})</span>
          }
        </div>
      }
      @if (snapshot()?.status === 'ERROR' && snapshot()?.errorMessage) {
        <div class="notice-banner notice-banner--error" role="alert">
          {{ snapshot()?.errorMessage }}
        </div>
      }

      <!-- Search & Filter Bar (ALWAYS active even during LOADING) -->
      <div class="filter-bar">
        <div class="filter-bar__search">
          <input
            type="search"
            class="search-input"
            [placeholder]="i18n.t().secrets.searchPlaceholder"
            [attr.aria-label]="i18n.t().secrets.searchAria"
            [ngModel]="criteria().query"
            (ngModelChange)="updateCriteria({ query: $event })"
          />
          <select
            class="select-compact"
            aria-label="Match mode"
            [ngModel]="criteria().matchMode"
            (ngModelChange)="updateMatchMode($event)"
          >
            <option value="contains">{{ i18n.t().secrets.matchContains }}</option>
            <option value="prefix">{{ i18n.t().secrets.matchPrefix }}</option>
            <option value="exact">{{ i18n.t().secrets.matchExact }}</option>
          </select>
        </div>

        <div class="filter-bar__controls">
          <select
            class="select-compact"
            aria-label="Status filter"
            [ngModel]="criteria().status"
            (ngModelChange)="updateStatus($event)"
          >
            <option value="all">{{ i18n.t().secrets.statusAll }}</option>
            <option value="enabled">{{ i18n.t().secrets.statusEnabled }}</option>
            <option value="disabled">{{ i18n.t().secrets.statusDisabled }}</option>
          </select>

          <select
            class="select-compact"
            aria-label="Expiration filter"
            [ngModel]="criteria().expiration"
            (ngModelChange)="updateExpiration($event)"
          >
            <option value="all">{{ i18n.t().secrets.expiryAll }}</option>
            <option value="expiring_soon">{{ i18n.t().secrets.expirySoon }}</option>
            <option value="expired">{{ i18n.t().secrets.expiryExpired }}</option>
            <option value="no_expiry">{{ i18n.t().secrets.expiryNone }}</option>
            <option value="active">{{ i18n.t().secrets.expiryActive }}</option>
          </select>

          <input
            type="text"
            class="tag-input"
            [placeholder]="i18n.t().secrets.tagFilterPlaceholder"
            [attr.aria-label]="i18n.t().secrets.tagFilterPlaceholder"
            [ngModel]="criteria().tagFilter"
            (ngModelChange)="updateCriteria({ tagFilter: $event })"
          />

          <div class="sort-group">
            <select
              class="select-compact"
              aria-label="Sort field"
              [ngModel]="criteria().sortBy"
              (ngModelChange)="updateSortField($event)"
            >
              <option value="name">{{ i18n.t().secrets.sortName }}</option>
              <option value="updatedOn">{{ i18n.t().secrets.sortUpdated }}</option>
              <option value="expiresOn">{{ i18n.t().secrets.sortExpires }}</option>
            </select>
            <button
              type="button"
              class="btn btn--ghost btn--xs"
              (click)="toggleSortDir()"
              [attr.aria-label]="'Sort direction: ' + criteria().sortDir"
            >
              {{ criteria().sortDir === 'asc' ? '↑' : '↓' }}
            </button>
          </div>
        </div>
      </div>
      </div>

      <!-- Virtual Scroll Table -->
      <div class="table-container">
        <div class="table-header" role="row">
          <div class="col col--name">{{ i18n.t().secrets.colName }}</div>
          <div class="col col--status">{{ i18n.t().secrets.colStatus }}</div>
          <div class="col col--updated">{{ i18n.t().secrets.colUpdated }}</div>
          <div class="col col--expires">{{ i18n.t().secrets.colExpires }}</div>
          <div class="col col--actions">{{ i18n.t().secrets.colActions }}</div>
        </div>

        @if (vaultStore.filteredSecrets().length === 0) {
          <div class="empty-state" role="status">
            @if (snapshot()?.status === 'LOADING' || vaultStore.snapshotLoadingInitial()) {
              <span class="spinner spinner--lg" aria-hidden="true"></span>
              <p>{{ i18n.t().secrets.loadingNoMatches }}</p>
            } @else if ((snapshot()?.loadedCount ?? 0) === 0) {
              <p>{{ i18n.t().secrets.emptyVault }}</p>
            } @else {
              <p>{{ i18n.t().secrets.completeNoMatches }}</p>
            }
          </div>
        } @else {
          <cdk-virtual-scroll-viewport
            class="table-viewport"
            [itemSize]="52"
            [minBufferPx]="360"
            [maxBufferPx]="720"
          >
            <div
              *cdkVirtualFor="let secret of vaultStore.filteredSecrets(); let isOdd = odd; trackBy: trackByName"
              class="table-row"
              [class.table-row--zebra]="isOdd"
              role="row"
              tabindex="0"
              (click)="inspectSecret.emit(secret)"
              (keydown.enter)="inspectSecret.emit(secret)"
            >
              <div class="col col--name">
                <span class="secret-name" [title]="secret.name">{{ secret.name }}</span>
                @if (secret.contentType) {
                  <span class="content-type-pill">{{ secret.contentType }}</span>
                }
              </div>

              <div class="col col--status">
                <span
                  class="status-badge"
                  [class.status-badge--enabled]="secret.enabled"
                  [class.status-badge--disabled]="!secret.enabled"
                >
                  {{ secret.enabled ? i18n.t().secrets.enabled : i18n.t().secrets.disabled }}
                </span>
                @if (expiryState(secret) === 'expired') {
                  <span class="status-badge status-badge--expired">{{ i18n.t().secrets.expired }}</span>
                } @else if (expiryState(secret) === 'soon') {
                  <span class="status-badge status-badge--soon">{{ i18n.t().secrets.expiringSoon }}</span>
                }
              </div>

              <div class="col col--updated">
                {{ formatDate(secret.updatedOn) }}
              </div>

              <div class="col col--expires">
                {{ secret.expiresOn ? formatDate(secret.expiresOn) : i18n.t().secrets.noExpiry }}
              </div>

              <div class="col col--actions" (click)="$event.stopPropagation()">
                <button
                  type="button"
                  class="btn btn--ghost btn--xs"
                  (click)="inspectSecret.emit(secret)"
                >
                  {{ i18n.t().secrets.actionInspect }}
                </button>
                <button
                  type="button"
                  class="btn btn--ghost btn--xs"
                  [disabled]="!canWrite()"
                  [title]="canWrite() ? i18n.t().secrets.actionEdit : i18n.t().secrets.unauthorizedTooltip"
                  (click)="editSecret.emit(secret)"
                >
                  {{ i18n.t().secrets.actionEdit }}
                </button>
                <button
                  type="button"
                  class="btn btn--ghost btn--xs"
                  (click)="openVersions.emit(secret)"
                >
                  {{ i18n.t().secrets.actionVersions }}
                </button>
                <button
                  type="button"
                  class="btn btn--danger-ghost btn--xs"
                  [disabled]="!canDelete()"
                  [title]="deleteTooltip()"
                  (click)="deleteSecret.emit(secret)"
                >
                  {{ i18n.t().secrets.actionDelete }}
                </button>
              </div>
            </div>
          </cdk-virtual-scroll-viewport>
        }
      </div>
    </section>
  `,
  styles: `
    :host {
      display: flex;
      flex-direction: column;
      flex: 1 1 0%;
      min-height: 0;
      height: 100%;
      overflow: hidden;
    }
    .secret-panel {
      display: flex;
      flex-direction: column;
      flex: 1 1 0%;
      height: 100%;
      gap: 0.6rem;
      min-height: 0;
      overflow: hidden;
    }
    .sticky-controls {
      position: sticky;
      top: 0;
      z-index: 15;
      flex-shrink: 0;
      display: flex;
      flex-direction: column;
      gap: 0.6rem;
      background: #f1f5f9;
    }
    .toolbar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 0.6rem;
      padding: 0.55rem 0.9rem;
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
    }
    .toolbar__stats {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.65rem;
      font-size: 0.8125rem;
      color: #475569;
    }
    .toolbar__actions {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .sync-pill {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.2rem 0.6rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .sync-pill--idle { background: #f1f5f9; color: #475569; }
    .sync-pill--loading { background: #e0f2fe; color: #0369a1; }
    .sync-pill--complete { background: #dcfce7; color: #166534; }
    .sync-pill--partial_error { background: #fef3c7; color: #92400e; }
    .sync-pill--error { background: #fee2e2; color: #991b1b; }
    .stat-chip {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      padding: 0.15rem 0.5rem;
      border-radius: 6px;
    }
    .stat-meta {
      font-size: 0.75rem;
      color: #64748b;
    }
    .notice-banner {
      padding: 0.65rem 0.9rem;
      border-radius: 8px;
      font-size: 0.8125rem;
      font-weight: 500;
    }
    .notice-banner--warn {
      background: #fffbeb;
      border: 1px solid #fde68a;
      color: #92400e;
    }
    .notice-banner--error {
      background: #fef2f2;
      border: 1px solid #fecaca;
      color: #991b1b;
    }
    .filter-bar {
      display: flex;
      flex-direction: column;
      gap: 0.45rem;
      padding: 0.6rem 0.9rem;
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
    }
    .filter-bar__search {
      display: flex;
      gap: 0.5rem;
    }
    .search-input {
      flex: 1;
      padding: 0.5rem 0.75rem;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      font-size: 0.875rem;
    }
    .filter-bar__controls {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
    }
    .select-compact,
    .tag-input {
      padding: 0.4rem 0.6rem;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      font-size: 0.8125rem;
      background: #ffffff;
      color: #0f172a;
    }
    .tag-input {
      flex: 1;
      min-width: 170px;
    }
    .sort-group {
      display: inline-flex;
      align-items: center;
      gap: 0.25rem;
    }
    .table-container {
      flex: 1 1 0%;
      min-height: 0;
      display: flex;
      flex-direction: column;
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      overflow: hidden;
    }
    .table-header,
    .table-row {
      display: grid;
      grid-template-columns: minmax(210px, 2.2fr) minmax(120px, 1fr) minmax(150px, 1.15fr) minmax(140px, 1.1fr) minmax(270px, 1.6fr);
      align-items: center;
      gap: 0.5rem;
      padding: 0 1rem;
    }
    .table-header {
      height: 40px;
      flex-shrink: 0;
      background: #f8fafc;
      border-bottom: 1px solid #e2e8f0;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      color: #64748b;
    }
    .table-viewport {
      flex: 1 1 0%;
      min-height: 0;
      height: 100%;
      width: 100%;
    }
    .table-row {
      height: 52px;
      background: #ffffff;
      border-bottom: 1px solid #e2e8f0;
      font-size: 0.8125rem;
      color: #0f172a;
      cursor: pointer;
      transition: background-color 120ms ease;
    }
    .table-row--zebra {
      background: #f1f5f9;
    }
    .table-row:hover {
      background: #e2e8f0;
    }
    .table-row:focus-visible {
      outline: 2px solid #0f4c81;
      outline-offset: -2px;
    }
    .col {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .col--name {
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }
    .secret-name {
      font-weight: 600;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.8125rem;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .content-type-pill {
      font-size: 0.6875rem;
      background: #f1f5f9;
      color: #475569;
      padding: 0.1rem 0.4rem;
      border-radius: 4px;
      flex-shrink: 0;
    }
    .col--status {
      display: flex;
      align-items: center;
      gap: 0.3rem;
      flex-wrap: nowrap;
    }
    .col--actions {
      display: flex;
      align-items: center;
      gap: 0.25rem;
      justify-content: flex-end;
      overflow: visible;
    }
    .status-badge {
      padding: 0.15rem 0.45rem;
      border-radius: 9999px;
      font-size: 0.6875rem;
      font-weight: 600;
    }
    .status-badge--enabled { background: #dcfce7; color: #166534; }
    .status-badge--disabled { background: #f1f5f9; color: #64748b; }
    .status-badge--expired { background: #fee2e2; color: #991b1b; }
    .status-badge--soon { background: #fef3c7; color: #92400e; }
    .empty-state {
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: 0.75rem;
      padding: 2.5rem 1.5rem;
      text-align: center;
      color: #64748b;
      font-size: 0.875rem;
    }
  `,
})
export class SecretListComponent {
  protected readonly i18n = inject(I18nService);
  protected readonly vaultStore = inject(VaultStore);
  protected readonly authStore = inject(AuthStore);

  readonly createSecret = output<void>();
  readonly inspectSecret = output<SecretMetadataDto>();
  readonly editSecret = output<SecretMetadataDto>();
  readonly openVersions = output<SecretMetadataDto>();
  readonly deleteSecret = output<SecretMetadataDto>();

  protected readonly vault = computed<VaultDto | null>(() => this.vaultStore.selectedVault());
  protected readonly snapshot = computed(() => this.vaultStore.snapshot());
  protected readonly criteria = computed(() => this.vaultStore.searchCriteria());

  protected readonly canWrite = computed<boolean>(() => {
    const v = this.vault();
    return this.authStore.hasPermission(v?.id, 'SECRET_WRITE', v?.permissions);
  });

  protected readonly canDelete = computed<boolean>(() => {
    const v = this.vault();
    return this.authStore.canDelete(v?.id, v?.permissions);
  });

  protected readonly deleteTooltip = computed<string>(() => {
    if (!this.authStore.deleteEnabled()) {
      return this.i18n.t().secrets.deleteDisabledTooltip;
    }
    if (!this.canDelete()) {
      return this.i18n.t().secrets.unauthorizedTooltip;
    }
    return this.i18n.t().secrets.actionDelete;
  });

  protected readonly syncStatusLabel = computed<string>(() => {
    const t = this.i18n.t().secrets;
    switch (this.snapshot()?.status) {
      case 'LOADING':
        return t.statusLoading;
      case 'COMPLETE':
        return t.statusComplete;
      case 'PARTIAL_ERROR':
        return t.statusPartial;
      case 'ERROR':
        return t.statusError;
      default:
        return t.statusIdle;
    }
  });

  protected readonly lastSyncFormatted = computed<string>(() => {
    const ts = this.snapshot()?.lastSuccessfulSyncAt;
    if (!ts) {
      return this.i18n.t().secrets.neverSynced;
    }
    return formatUtcTimestamp(ts, this.i18n.locale());
  });

  protected trackByName(_index: number, item: SecretMetadataDto): string {
    return item.name;
  }

  protected formatDate(iso: string | null | undefined): string {
    return formatUtcTimestamp(iso, this.i18n.locale());
  }

  protected expiryState(item: SecretMetadataDto): 'expired' | 'soon' | 'ok' {
    if (!item.expiresOn) {
      return 'ok';
    }
    const expMs = Date.parse(item.expiresOn);
    if (Number.isNaN(expMs)) {
      return 'ok';
    }
    const now = Date.now();
    if (expMs <= now) {
      return 'expired';
    }
    if (expMs <= now + THIRTY_DAYS_MS) {
      return 'soon';
    }
    return 'ok';
  }

  protected updateCriteria(patch: Partial<ReturnType<typeof this.criteria>>): void {
    this.vaultStore.updateSearchCriteria(patch);
  }

  protected updateMatchMode(mode: SearchMatchMode): void {
    this.vaultStore.updateSearchCriteria({ matchMode: mode });
  }

  protected updateStatus(status: StatusFilter): void {
    this.vaultStore.updateSearchCriteria({ status });
  }

  protected updateExpiration(expiration: ExpirationFilter): void {
    this.vaultStore.updateSearchCriteria({ expiration });
  }

  protected updateSortField(sortBy: SortField): void {
    this.vaultStore.updateSearchCriteria({ sortBy });
  }

  protected toggleSortDir(): void {
    this.vaultStore.updateSearchCriteria({
      sortDir: this.criteria().sortDir === 'asc' ? 'desc' : 'asc',
    });
  }
}
