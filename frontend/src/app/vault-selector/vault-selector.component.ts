import { ChangeDetectionStrategy, Component, computed, inject, output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { I18nService } from '../core/i18n/i18n.service';
import { VaultDto } from '../core/models/api.models';
import { VaultStore } from '../core/services/vault.store';
import { EnvironmentBadgeComponent } from '../shared/environment-badge.component';

@Component({
  selector: 'app-vault-selector',
  standalone: true,
  imports: [FormsModule, EnvironmentBadgeComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <aside class="vault-sidebar" [attr.aria-label]="i18n.t().vaults.title">
      <div class="vault-sidebar__header">
        <h2>{{ i18n.t().vaults.title }}</h2>
        <button
          type="button"
          class="btn btn--ghost btn--xs"
          [disabled]="vaultStore.loadingVaults()"
          (click)="vaultStore.loadDiscovery()"
          [attr.aria-label]="i18n.t().secrets.refresh"
          title="Refresh vaults"
        >
          ↻
        </button>
      </div>

      @if (vaultStore.subscriptions().length > 0) {
        <div class="vault-sidebar__control">
          <label for="subscriptionSelect">{{ i18n.t().vaults.subscriptionLabel }}</label>
          <select
            id="subscriptionSelect"
            [ngModel]="vaultStore.selectedSubscriptionId()"
            (ngModelChange)="vaultStore.selectSubscription($event)"
          >
            <option value="">{{ i18n.t().vaults.allSubscriptions }}</option>
            @for (sub of vaultStore.subscriptions(); track sub.subscriptionId) {
              <option [value]="sub.subscriptionId">{{ sub.displayName }}</option>
            }
          </select>
        </div>
      }

      <div class="vault-sidebar__control">
        <input
          type="search"
          [placeholder]="i18n.t().vaults.searchPlaceholder"
          [attr.aria-label]="i18n.t().vaults.searchPlaceholder"
          [ngModel]="vaultFilter()"
          (ngModelChange)="vaultFilter.set($event)"
        />
      </div>

      <div class="vault-list" role="listbox" [attr.aria-label]="i18n.t().vaults.title">
        @if (vaultStore.loadingVaults()) {
          <div class="vault-list__state">{{ i18n.t().vaults.loading }}</div>
        } @else if (visibleVaults().length === 0) {
          <div class="vault-list__state">{{ i18n.t().vaults.empty }}</div>
        } @else {
          @for (vault of visibleVaults(); track vault.id) {
            <button
              type="button"
              role="option"
              class="vault-item"
              [class.vault-item--active]="vault.id === vaultStore.selectedVaultId()"
              [class.vault-item--prod]="vault.production === true"
              [attr.aria-selected]="vault.id === vaultStore.selectedVaultId()"
              (click)="select(vault)"
            >
              <div class="vault-item__top">
                <span class="vault-item__name" [title]="vault.name">{{ vault.name }}</span>
                <app-environment-badge
                  [environment]="vault.environment"
                  [production]="vault.production"
                />
              </div>
              <div class="vault-item__meta">
                <span>{{ vault.location || (vault.source === 'ARM_DISCOVERY' ? i18n.t().vaults.sourceArm : i18n.t().vaults.sourceStatic) }}</span>
                <span class="vault-item__role">{{ highestRoleLabel(vault) }}</span>
              </div>
            </button>
          }
        }
      </div>
    </aside>
  `,
  styles: `
    :host {
      display: block;
      min-height: 0;
      height: 100%;
    }
    .vault-sidebar {
      display: flex;
      flex-direction: column;
      height: 100%;
      background: #f8fafc;
      border-right: 1px solid #e2e8f0;
      padding: 1rem;
      gap: 0.75rem;
      overflow: hidden;
    }
    .vault-sidebar__header {
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .vault-sidebar__header h2 {
      font-size: 0.875rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: #475569;
      margin: 0;
    }
    .vault-sidebar__control {
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
    }
    .vault-sidebar__control label {
      font-size: 0.75rem;
      font-weight: 600;
      color: #64748b;
    }
    .vault-sidebar__control select,
    .vault-sidebar__control input {
      width: 100%;
      padding: 0.45rem 0.65rem;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      font-size: 0.8125rem;
      background: #ffffff;
      color: #0f172a;
    }
    .vault-list {
      flex: 1;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      padding-right: 2px;
    }
    .vault-list__state {
      font-size: 0.8125rem;
      color: #64748b;
      text-align: center;
      padding: 1.5rem 0.5rem;
    }
    .vault-item {
      width: 100%;
      text-align: left;
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 0.7rem 0.75rem;
      cursor: pointer;
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
      transition: border-color 0.15s, box-shadow 0.15s, background-color 0.15s;
    }
    .vault-item:hover {
      border-color: #94a3b8;
      background: #f8fafc;
    }
    .vault-item--active {
      border-color: #0f4c81;
      background: #f0f9ff;
      box-shadow: 0 0 0 1px #0f4c81;
    }
    .vault-item--prod.vault-item--active {
      border-color: #dc2626;
      background: #fef2f2;
      box-shadow: 0 0 0 1px #dc2626;
    }
    .vault-item__top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.5rem;
    }
    .vault-item__name {
      font-weight: 600;
      font-size: 0.875rem;
      color: #0f172a;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .vault-item__meta {
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 0.75rem;
      color: #64748b;
    }
    .vault-item__role {
      font-weight: 600;
      color: #334155;
      background: #f1f5f9;
      padding: 0.1rem 0.4rem;
      border-radius: 4px;
      font-size: 0.6875rem;
    }
  `,
})
export class VaultSelectorComponent {
  protected readonly i18n = inject(I18nService);
  protected readonly vaultStore = inject(VaultStore);

  readonly vaultSelected = output<VaultDto>();

  protected readonly vaultFilter = signal<string>('');

  protected readonly visibleVaults = computed<VaultDto[]>(() => {
    const q = this.vaultFilter().trim().toLowerCase();
    const list = this.vaultStore.filteredVaults();
    if (!q) {
      return list;
    }
    return list.filter(
      (v) =>
        v.name.toLowerCase().includes(q) ||
        v.environment.toLowerCase().includes(q) ||
        (v.resourceGroup ?? '').toLowerCase().includes(q)
    );
  });

  protected select(vault: VaultDto): void {
    this.vaultSelected.emit(vault);
    void this.vaultStore.selectVault(vault.id);
  }

  protected highestRoleLabel(vault: VaultDto): string {
    const perms = new Set(vault.permissions ?? []);
    if (perms.has('SECRET_DELETE_RECOVER')) {
      return 'ADMIN';
    }
    if (perms.has('SECRET_WRITE')) {
      return 'MANAGER';
    }
    if (perms.has('SECRET_REVEAL')) {
      return 'OPERATOR';
    }
    return 'VIEWER';
  }
}
