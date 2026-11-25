import {
  ChangeDetectionStrategy,
  Component,
  OnInit,
  computed,
  inject,
  signal,
} from '@angular/core';
import { I18nService } from '../core/i18n/i18n.service';
import { SecretMetadataDto, VaultDto } from '../core/models/api.models';
import { AuthStore } from '../core/services/auth.store';
import { VaultStore } from '../core/services/vault.store';
import { DeletedSecretsComponent } from '../deleted-secrets/deleted-secrets.component';
import {
  DrawerTab,
  SecretDetailDrawerComponent,
} from '../secret-editor/secret-detail-drawer.component';
import {
  SecretFormDialogComponent,
  SecretFormMode,
} from '../secret-editor/secret-form-dialog.component';
import { SecretListComponent } from '../secret-list/secret-list.component';
import { EnvironmentBadgeComponent } from '../shared/environment-badge.component';
import { ErrorBannerComponent } from '../shared/error-banner.component';
import { VaultSelectorComponent } from '../vault-selector/vault-selector.component';

type WorkspaceTab = 'active' | 'deleted';

interface FormDialogState {
  mode: SecretFormMode;
  secret: SecretMetadataDto | null;
}

@Component({
  selector: 'app-shell',
  standalone: true,
  imports: [
    VaultSelectorComponent,
    SecretListComponent,
    SecretDetailDrawerComponent,
    SecretFormDialogComponent,
    DeletedSecretsComponent,
    EnvironmentBadgeComponent,
    ErrorBannerComponent,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="shell">
      <!-- Top Navigation Bar -->
      <header class="topbar">
        <div class="topbar__brand">
          <svg viewBox="0 0 32 32" width="28" height="28" fill="none" aria-hidden="true">
            <rect width="32" height="32" rx="7" fill="#0F4C81" />
            <path
              d="M16 6.5a5.5 5.5 0 0 0-5.5 5.5v2H9a1.5 1.5 0 0 0-1.5 1.5v8A1.5 1.5 0 0 0 9 25h14a1.5 1.5 0 0 0 1.5-1.5v-8A1.5 1.5 0 0 0 23 14h-1.5v-2A5.5 5.5 0 0 0 16 6.5Zm-3 5.5a3 3 0 1 1 6 0v2h-6v-2Zm3 5.5a2 2 0 0 1 1 3.73V22.5a1 1 0 1 1-2 0v-1.27A2 2 0 0 1 16 17.5Z"
              fill="#FFFFFF"
            />
          </svg>
          <div>
            <h1 class="topbar__title">{{ i18n.t().app.title }}</h1>
          </div>
          <span
            class="profile-badge"
            [class.profile-badge--server]="authStore.profile() === 'server'"
          >
            {{ authStore.profile() === 'server' ? i18n.t().app.profileServer : i18n.t().app.profileLocal }}
          </span>
          <span
            class="conn-pill"
            [class.conn-pill--ok]="vaultStore.connected()"
            [class.conn-pill--err]="!vaultStore.connected()"
          >
            <span class="conn-dot" aria-hidden="true"></span>
            {{ vaultStore.connected() ? i18n.t().app.connected : i18n.t().app.disconnected }}
          </span>
        </div>

        <div class="topbar__actions">
          @if (authStore.subject()) {
            <span class="user-subject" [title]="authStore.subject()">
              {{ authStore.subject() }}
            </span>
          }

          <button
            type="button"
            class="btn btn--ghost btn--xs"
            (click)="i18n.toggleLanguage()"
            aria-label="Toggle language"
          >
            {{ i18n.language().toUpperCase() }}
          </button>

          <button
            type="button"
            class="btn btn--secondary btn--xs"
            (click)="logout()"
          >
            {{ i18n.t().app.logout }}
          </button>
        </div>
      </header>

      <!-- Workspace Grid -->
      <div class="workspace" [class.workspace--drawer-open]="selectedSecret() !== null">
        <app-vault-selector (vaultSelected)="onVaultChanged($event)" />

        <main class="main-area">
          <app-error-banner
            [problem]="vaultStore.error()"
            (dismiss)="vaultStore.clearError()"
          />

          @if (selectedVault(); as vault) {
            <div class="vault-header" [class.vault-header--prod]="vault.production === true">
              <div class="vault-header__info">
                <h2>{{ vault.name }}</h2>
                <app-environment-badge
                  [environment]="vault.environment"
                  [production]="vault.production"
                />
                @if (vault.resourceGroup) {
                  <span class="vault-header__sub">{{ vault.resourceGroup }}</span>
                }
              </div>

              <div class="workspace-tabs" role="tablist">
                <button
                  type="button"
                  role="tab"
                  class="ws-tab"
                  [class.ws-tab--active]="activeWorkspaceTab() === 'active'"
                  [attr.aria-selected]="activeWorkspaceTab() === 'active'"
                  (click)="activeWorkspaceTab.set('active')"
                >
                  {{ i18n.t().app.activeSecretsTab }}
                </button>
                @if (canViewDeleted()) {
                  <button
                    type="button"
                    role="tab"
                    class="ws-tab"
                    [class.ws-tab--active]="activeWorkspaceTab() === 'deleted'"
                    [attr.aria-selected]="activeWorkspaceTab() === 'deleted'"
                    (click)="openDeletedTab()"
                  >
                    {{ i18n.t().app.deletedSecretsTab }}
                  </button>
                }
              </div>
            </div>

            <div class="main-content">
              @if (activeWorkspaceTab() === 'active') {
                <app-secret-list
                  (createSecret)="openCreateDialog()"
                  (inspectSecret)="openDrawer($event, 'details')"
                  (editSecret)="openUpdateDialog($event)"
                  (openVersions)="openDrawer($event, 'versions')"
                  (deleteSecret)="openDrawer($event, 'details')"
                />
              } @else {
                <app-deleted-secrets
                  [vault]="vault"
                  (secretRecovered)="onSecretRecovered()"
                />
              }
            </div>
          } @else {
            <div class="no-vault-state">
              <h2>{{ i18n.t().app.noVaultSelected }}</h2>
              <p>{{ i18n.t().app.noVaultSelectedHint }}</p>
            </div>
          }
        </main>

        @if (selectedVault(); as vault) {
          @if (selectedSecret(); as secret) {
            <app-secret-detail-drawer
              [vault]="vault"
              [secret]="secret"
              [initialTab]="drawerTab()"
              (close)="closeDrawer()"
              (requestUpdateValue)="openUpdateDialog($event)"
              (requestEditProperties)="openPropertiesDialog($event)"
              (secretChanged)="onSecretMutated($event)"
              (secretDeleted)="onSecretDeleted()"
            />
          }
        }
      </div>

      @if (selectedVault(); as vault) {
        @if (formDialog(); as dlg) {
          <app-secret-form-dialog
            [vault]="vault"
            [mode]="dlg.mode"
            [secret]="dlg.secret"
            (close)="formDialog.set(null)"
            (saved)="onFormSaved($event)"
          />
        }
      }
    </div>
  `,
  styles: `
    .shell {
      display: flex;
      flex-direction: column;
      height: 100vh;
      overflow: hidden;
      background: #f1f5f9;
    }
    .topbar {
      height: 56px;
      flex-shrink: 0;
      position: sticky;
      top: 0;
      z-index: 20;
      background: #ffffff;
      border-bottom: 1px solid #e2e8f0;
      padding: 0 1.25rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
    }
    .topbar__brand {
      display: flex;
      align-items: center;
      gap: 0.65rem;
    }
    .topbar__title {
      font-size: 1rem;
      font-weight: 700;
      margin: 0;
      color: #0f172a;
    }
    .profile-badge {
      font-size: 0.6875rem;
      font-weight: 700;
      padding: 0.15rem 0.5rem;
      border-radius: 9999px;
      background: #e0f2fe;
      color: #0369a1;
      letter-spacing: 0.04em;
    }
    .profile-badge--server {
      background: #ede9fe;
      color: #5b21b6;
    }
    .conn-pill {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      font-size: 0.75rem;
      font-weight: 600;
      padding: 0.15rem 0.55rem;
      border-radius: 9999px;
    }
    .conn-pill--ok { background: #dcfce7; color: #166534; }
    .conn-pill--err { background: #fee2e2; color: #991b1b; }
    .conn-dot {
      width: 7px;
      height: 7px;
      border-radius: 9999px;
      background: currentColor;
    }
    .topbar__actions {
      display: flex;
      align-items: center;
      gap: 0.6rem;
    }
    .user-subject {
      font-size: 0.8125rem;
      color: #475569;
      font-weight: 500;
      max-width: 220px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .workspace {
      flex: 1 1 0%;
      min-height: 0;
      overflow: hidden;
      display: grid;
      grid-template-columns: 280px minmax(0, 1fr);
      grid-template-rows: minmax(0, 1fr);
    }
    .workspace--drawer-open {
      grid-template-columns: 280px minmax(0, 1fr) 420px;
    }
    .main-area {
      display: flex;
      flex-direction: column;
      min-height: 0;
      overflow: hidden;
      padding: 0.75rem 1rem;
      gap: 0.6rem;
    }
    .vault-header {
      flex-shrink: 0;
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
    .vault-header--prod {
      border-left: 4px solid #dc2626;
    }
    .vault-header__info {
      display: flex;
      align-items: center;
      gap: 0.6rem;
      flex-wrap: wrap;
    }
    .vault-header__info h2 {
      margin: 0;
      font-size: 1.0625rem;
      color: #0f172a;
    }
    .vault-header__sub {
      font-size: 0.78rem;
      color: #64748b;
    }
    .workspace-tabs {
      display: flex;
      gap: 0.35rem;
    }
    .ws-tab {
      padding: 0.4rem 0.85rem;
      border-radius: 6px;
      border: 1px solid transparent;
      background: transparent;
      font-size: 0.8125rem;
      font-weight: 600;
      color: #475569;
      cursor: pointer;
    }
    .ws-tab--active {
      background: #eff6ff;
      border-color: #bfdbfe;
      color: #0f4c81;
    }
    .main-content {
      flex: 1 1 0%;
      min-height: 0;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }
    .no-vault-state {
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      text-align: center;
      background: #ffffff;
      border: 1px dashed #cbd5e1;
      border-radius: 10px;
      padding: 2rem;
      color: #64748b;
    }
    .no-vault-state h2 {
      margin: 0 0 0.5rem;
      color: #0f172a;
      font-size: 1.125rem;
    }
    @media (max-width: 1180px) {
      .workspace--drawer-open {
        grid-template-columns: 240px minmax(0, 1fr) 360px;
      }
    }
    @media (max-width: 900px) {
      .workspace,
      .workspace--drawer-open {
        grid-template-columns: 1fr;
        overflow-y: auto;
      }
    }
  `,
})
export class AppShellComponent implements OnInit {
  protected readonly i18n = inject(I18nService);
  protected readonly authStore = inject(AuthStore);
  protected readonly vaultStore = inject(VaultStore);

  protected readonly selectedVault = computed<VaultDto | null>(() => this.vaultStore.selectedVault());
  protected readonly activeWorkspaceTab = signal<WorkspaceTab>('active');
  protected readonly selectedSecret = signal<SecretMetadataDto | null>(null);
  protected readonly drawerTab = signal<DrawerTab>('details');
  protected readonly formDialog = signal<FormDialogState | null>(null);

  protected readonly canViewDeleted = computed<boolean>(() => {
    const v = this.selectedVault();
    return this.authStore.hasPermission(v?.id, 'SECRET_DELETE_RECOVER', v?.permissions);
  });

  ngOnInit(): void {
    void this.vaultStore.loadDiscovery();
  }

  protected onVaultChanged(_vault: VaultDto): void {
    // Switching vaults immediately closes drawer and clears any revealed values
    this.selectedSecret.set(null);
    this.formDialog.set(null);
    this.activeWorkspaceTab.set('active');
  }

  protected openDeletedTab(): void {
    this.selectedSecret.set(null);
    this.activeWorkspaceTab.set('deleted');
  }

  protected openDrawer(secret: SecretMetadataDto, tab: DrawerTab): void {
    this.drawerTab.set(tab);
    this.selectedSecret.set(secret);
  }

  protected closeDrawer(): void {
    this.selectedSecret.set(null);
  }

  protected openCreateDialog(): void {
    this.formDialog.set({ mode: 'create', secret: null });
  }

  protected openUpdateDialog(secret: SecretMetadataDto): void {
    this.formDialog.set({ mode: 'update', secret });
  }

  protected openPropertiesDialog(secret: SecretMetadataDto): void {
    this.formDialog.set({ mode: 'properties', secret });
  }

  protected onFormSaved(updated: SecretMetadataDto): void {
    this.formDialog.set(null);
    this.selectedSecret.set(updated);
    void this.vaultStore.reloadCurrentSnapshot();
  }

  protected onSecretMutated(updated: SecretMetadataDto): void {
    this.selectedSecret.set(updated);
    void this.vaultStore.reloadCurrentSnapshot();
  }

  protected onSecretDeleted(): void {
    this.selectedSecret.set(null);
    void this.vaultStore.reloadCurrentSnapshot();
  }

  protected onSecretRecovered(): void {
    void this.vaultStore.reloadCurrentSnapshot();
  }

  protected async logout(): Promise<void> {
    this.selectedSecret.set(null);
    this.formDialog.set(null);
    this.vaultStore.reset();
    await this.authStore.logout();
  }
}
