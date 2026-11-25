import {
  ChangeDetectionStrategy,
  Component,
  OnDestroy,
  computed,
  effect,
  inject,
  input,
  output,
  signal,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Subscription, firstValueFrom } from 'rxjs';
import { I18nService } from '../core/i18n/i18n.service';
import {
  OperationStatusResponse,
  ProblemDetail,
  SecretMetadataDto,
  VaultDto,
} from '../core/models/api.models';
import { ApiService } from '../core/services/api.service';
import { AuthStore } from '../core/services/auth.store';
import { OperationPollerService } from '../core/services/operation-poller.service';
import { extractProblemDetail, formatUtcTimestamp } from '../core/utils/secret-validation.util';
import { EnvironmentBadgeComponent } from '../shared/environment-badge.component';
import { ErrorBannerComponent } from '../shared/error-banner.component';
import { SecretVersionsComponent } from '../versions/secret-versions.component';

export const REVEAL_AUTO_CLEAR_SECONDS = 30;

export type DrawerTab = 'details' | 'versions';

@Component({
  selector: 'app-secret-detail-drawer',
  standalone: true,
  imports: [
    FormsModule,
    EnvironmentBadgeComponent,
    ErrorBannerComponent,
    SecretVersionsComponent,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <aside class="drawer" role="region" [attr.aria-label]="i18n.t().detail.title">
      <div class="drawer__header">
        <div class="drawer__title-block">
          <div class="drawer__vault-row">
            <span>{{ vault().name }}</span>
            <app-environment-badge
              [environment]="vault().environment"
              [production]="vault().production"
            />
          </div>
          <h2 class="drawer__secret-name" [title]="secret().name">{{ secret().name }}</h2>
        </div>
        <button
          type="button"
          class="btn btn--ghost btn--xs"
          [attr.aria-label]="i18n.t().detail.close"
          (click)="onClose()"
        >
          ✕
        </button>
      </div>

      <div class="drawer__tabs" role="tablist">
        <button
          type="button"
          role="tab"
          class="tab-btn"
          [class.tab-btn--active]="activeTab() === 'details'"
          [attr.aria-selected]="activeTab() === 'details'"
          (click)="activeTab.set('details')"
        >
          {{ i18n.t().detail.detailsTab }}
        </button>
        <button
          type="button"
          role="tab"
          class="tab-btn"
          [class.tab-btn--active]="activeTab() === 'versions'"
          [attr.aria-selected]="activeTab() === 'versions'"
          (click)="activeTab.set('versions')"
        >
          {{ i18n.t().detail.versionsTab }}
        </button>
      </div>

      <div class="drawer__body">
        <app-error-banner [problem]="error()" (dismiss)="error.set(null)" />

        @if (activeTab() === 'details') {
          <!-- Reveal Section -->
          <section class="card">
            <div class="card__header">
              <h3>{{ i18n.t().detail.revealSection }}</h3>
              @if (revealedValue() !== null) {
                <span class="countdown-badge">
                  {{ i18n.t().detail.autoClearIn }}: {{ remainingSeconds() }}s
                </span>
              }
            </div>

            @if (!canReveal()) {
              <p class="muted-text">{{ i18n.t().detail.revealNoPermission }}</p>
            } @else {
              @if (revealedValue() !== null) {
                <pre class="secret-value-box" data-testid="revealed-secret-value">{{ revealedValue() }}</pre>
                <div class="btn-row">
                  <button
                    type="button"
                    class="btn btn--secondary btn--sm"
                    data-testid="copy-secret-btn"
                    (click)="copyRevealedValue()"
                  >
                    {{ copied() ? i18n.t().detail.copiedNotice : i18n.t().detail.copyButton }}
                  </button>
                  <button
                    type="button"
                    class="btn btn--ghost btn--sm"
                    data-testid="hide-secret-btn"
                    (click)="clearRevealed()"
                  >
                    {{ i18n.t().detail.hideButton }}
                  </button>
                </div>
                <small class="disclaimer">{{ i18n.t().detail.clipboardDisclaimer }}</small>
              } @else {
                <div class="masked-box" data-testid="masked-secret-box">
                  {{ i18n.t().detail.maskedPlaceholder }}
                </div>
                <button
                  type="button"
                  class="btn btn--primary btn--sm"
                  data-testid="reveal-secret-btn"
                  [disabled]="revealing()"
                  (click)="revealLatest()"
                >
                  {{ revealing() ? i18n.t().app.loading : i18n.t().detail.revealButton }}
                </button>
              }
            }
          </section>

          <!-- Management Actions -->
          @if (canWrite()) {
            <section class="card">
              <h3>{{ i18n.t().detail.actionsSection }}</h3>
              <div class="btn-row">
                <button
                  type="button"
                  class="btn btn--secondary btn--sm"
                  (click)="requestUpdateValue.emit(secret())"
                >
                  {{ i18n.t().detail.updateValueButton }}
                </button>
                <button
                  type="button"
                  class="btn btn--secondary btn--sm"
                  (click)="requestEditProperties.emit(secret())"
                >
                  {{ i18n.t().detail.editPropertiesButton }}
                </button>
              </div>
            </section>
          }

          <!-- Metadata Details -->
          <section class="card">
            <h3>{{ i18n.t().detail.metadataSection }}</h3>
            <dl class="meta-list">
              <dt>{{ i18n.t().detail.version }}</dt>
              <dd><code>{{ secret().version || '—' }}</code></dd>

              <dt>{{ i18n.t().detail.status }}</dt>
              <dd>{{ secret().enabled ? i18n.t().secrets.enabled : i18n.t().secrets.disabled }}</dd>

              <dt>{{ i18n.t().detail.contentType }}</dt>
              <dd>{{ secret().contentType || '—' }}</dd>

              <dt>{{ i18n.t().detail.createdOn }}</dt>
              <dd>{{ formatDate(secret().createdOn) }}</dd>

              <dt>{{ i18n.t().detail.updatedOn }}</dt>
              <dd>{{ formatDate(secret().updatedOn) }}</dd>

              <dt>{{ i18n.t().detail.notBefore }}</dt>
              <dd>{{ formatDate(secret().notBefore) }}</dd>

              <dt>{{ i18n.t().detail.expiresOn }}</dt>
              <dd>{{ formatDate(secret().expiresOn) }}</dd>
            </dl>

            <div class="tags-section">
              <h4>{{ i18n.t().detail.tags }}</h4>
              @if (tagEntries().length === 0) {
                <p class="muted-text">{{ i18n.t().detail.noTags }}</p>
              } @else {
                <div class="tag-chips">
                  @for (entry of tagEntries(); track entry[0]) {
                    <span class="tag-chip">
                      <strong>{{ entry[0] }}</strong>={{ entry[1] }}
                    </span>
                  }
                </div>
              }
            </div>
          </section>

          <!-- Soft-Delete Danger Zone (ADMIN + APP_DELETE_ENABLED only; NO PURGE) -->
          @if (canDelete()) {
            <section class="card card--danger">
              <h3>{{ i18n.t().detail.dangerZone }}</h3>
              @if (vault().production) {
                <div class="prod-danger-alert" role="alert">
                  {{ i18n.t().detail.prodDeleteWarning }}
                </div>
              }
              <p class="danger-text">{{ i18n.t().detail.deleteWarning }}</p>

              <div class="form-field">
                <label for="deleteConfirmInput">
                  {{ i18n.t().detail.deleteConfirmLabel }}: <code>{{ secret().name }}</code>
                </label>
                <input
                  id="deleteConfirmInput"
                  type="text"
                  autocomplete="off"
                  spellcheck="false"
                  [placeholder]="secret().name"
                  [ngModel]="deleteConfirmName()"
                  (ngModelChange)="deleteConfirmName.set($event)"
                />
              </div>

              @if (deleteOp(); as op) {
                <div class="op-status" role="status">
                  @if (op.state === 'PENDING' || op.state === 'IN_PROGRESS') {
                    <span class="spinner" aria-hidden="true"></span>
                    {{ i18n.t().detail.deleteInProgress }} ({{ op.state }})
                  } @else if (op.state === 'SUCCEEDED') {
                    ✓ {{ i18n.t().detail.deleteSuccess }}
                  } @else {
                    ✕ {{ i18n.t().detail.deleteFailed }}: {{ op.errorMessage || op.errorCode }}
                  }
                </div>
              }

              <button
                type="button"
                class="btn btn--danger btn--sm"
                [disabled]="deleteConfirmName() !== secret().name || deleting()"
                (click)="startSoftDelete()"
              >
                {{ deleting() ? i18n.t().detail.deleteInProgress : i18n.t().detail.deleteButton }}
              </button>

              <small class="muted-text">{{ i18n.t().detail.noPurgeNotice }}</small>
            </section>
          }
        } @else {
          <app-secret-versions
            [vault]="vault()"
            [secret]="secret()"
            (versionRestored)="secretChanged.emit($event)"
          />
        }
      </div>
    </aside>
  `,
  styles: `
    .drawer {
      height: 100%;
      background: #ffffff;
      border-left: 1px solid #e2e8f0;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }
    .drawer__header {
      padding: 1rem 1.15rem;
      border-bottom: 1px solid #e2e8f0;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 0.75rem;
      background: #f8fafc;
    }
    .drawer__title-block {
      min-width: 0;
      flex: 1;
    }
    .drawer__vault-row {
      display: flex;
      align-items: center;
      gap: 0.45rem;
      font-size: 0.75rem;
      color: #64748b;
      margin-bottom: 0.25rem;
    }
    .drawer__secret-name {
      margin: 0;
      font-size: 1rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      color: #0f172a;
      word-break: break-all;
    }
    .drawer__tabs {
      display: flex;
      border-bottom: 1px solid #e2e8f0;
      padding: 0 1rem;
      gap: 0.25rem;
      background: #ffffff;
    }
    .tab-btn {
      padding: 0.65rem 0.9rem;
      border: none;
      background: transparent;
      border-bottom: 2px solid transparent;
      font-size: 0.8125rem;
      font-weight: 600;
      color: #64748b;
      cursor: pointer;
    }
    .tab-btn--active {
      color: #0f4c81;
      border-bottom-color: #0f4c81;
    }
    .drawer__body {
      flex: 1;
      overflow-y: auto;
      padding: 1rem 1.15rem;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }
    .card {
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 0.9rem;
      display: flex;
      flex-direction: column;
      gap: 0.65rem;
    }
    .card h3 {
      margin: 0;
      font-size: 0.875rem;
      font-weight: 700;
      color: #0f172a;
    }
    .card__header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.5rem;
    }
    .countdown-badge {
      font-size: 0.75rem;
      font-weight: 700;
      color: #b45309;
      background: #fef3c7;
      padding: 0.15rem 0.5rem;
      border-radius: 9999px;
    }
    .masked-box {
      padding: 0.65rem 0.75rem;
      border-radius: 6px;
      background: #f1f5f9;
      color: #64748b;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      letter-spacing: 0.15em;
    }
    .secret-value-box {
      margin: 0;
      padding: 0.75rem;
      border-radius: 6px;
      background: #0f172a;
      color: #f8fafc;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.8125rem;
      white-space: pre-wrap;
      word-break: break-all;
      max-height: 240px;
      overflow-y: auto;
    }
    .btn-row {
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
    }
    .disclaimer,
    .muted-text {
      font-size: 0.75rem;
      color: #64748b;
      margin: 0;
      line-height: 1.4;
    }
    .meta-list {
      display: grid;
      grid-template-columns: 120px 1fr;
      gap: 0.4rem 0.75rem;
      margin: 0;
      font-size: 0.8125rem;
    }
    .meta-list dt {
      color: #64748b;
      font-weight: 500;
    }
    .meta-list dd {
      margin: 0;
      color: #0f172a;
      word-break: break-all;
    }
    .tags-section h4 {
      margin: 0.25rem 0 0.4rem;
      font-size: 0.8125rem;
      color: #475569;
    }
    .tag-chips {
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
    }
    .tag-chip {
      font-size: 0.75rem;
      background: #f1f5f9;
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      padding: 0.15rem 0.5rem;
      color: #334155;
    }
    .card--danger {
      border-color: #fecaca;
      background: #fffafa;
    }
    .card--danger h3 {
      color: #991b1b;
    }
    .prod-danger-alert {
      background: #dc2626;
      color: #ffffff;
      padding: 0.55rem 0.75rem;
      border-radius: 6px;
      font-size: 0.78rem;
      font-weight: 700;
    }
    .danger-text {
      margin: 0;
      font-size: 0.8125rem;
      color: #7f1d1d;
    }
    .op-status {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.8125rem;
      font-weight: 500;
      padding: 0.5rem 0.65rem;
      border-radius: 6px;
      background: #f8fafc;
      border: 1px solid #cbd5e1;
    }
  `,
})
export class SecretDetailDrawerComponent implements OnDestroy {
  protected readonly i18n = inject(I18nService);
  private readonly api = inject(ApiService);
  private readonly authStore = inject(AuthStore);
  private readonly opPoller = inject(OperationPollerService);

  readonly vault = input.required<VaultDto>();
  readonly secret = input.required<SecretMetadataDto>();
  readonly initialTab = input<DrawerTab>('details');

  readonly close = output<void>();
  readonly requestUpdateValue = output<SecretMetadataDto>();
  readonly requestEditProperties = output<SecretMetadataDto>();
  readonly secretChanged = output<SecretMetadataDto>();
  readonly secretDeleted = output<string>();

  protected readonly activeTab = signal<DrawerTab>('details');
  protected readonly error = signal<ProblemDetail | null>(null);

  protected readonly revealing = signal<boolean>(false);
  protected readonly revealedValue = signal<string | null>(null);
  protected readonly remainingSeconds = signal<number>(0);
  protected readonly copied = signal<boolean>(false);

  protected readonly deleteConfirmName = signal<string>('');
  protected readonly deleting = signal<boolean>(false);
  protected readonly deleteOp = signal<OperationStatusResponse | null>(null);

  protected readonly canReveal = computed<boolean>(() =>
    this.authStore.hasPermission(this.vault().id, 'SECRET_REVEAL', this.vault().permissions)
  );
  protected readonly canWrite = computed<boolean>(() =>
    this.authStore.hasPermission(this.vault().id, 'SECRET_WRITE', this.vault().permissions)
  );
  protected readonly canDelete = computed<boolean>(() =>
    this.authStore.canDelete(this.vault().id, this.vault().permissions)
  );
  protected readonly tagEntries = computed<[string, string][]>(() => {
    const tags = this.secret().tags;
    return tags ? Object.entries(tags) : [];
  });

  private countdownTimer: ReturnType<typeof setInterval> | null = null;
  private deleteSub: Subscription | null = null;

  constructor() {
    // Immediately clear revealed value whenever vault or secret changes!
    effect(() => {
      this.vault().id;
      this.secret().name;
      this.clearRevealed();
      this.deleteConfirmName.set('');
      this.deleteOp.set(null);
      this.error.set(null);
      this.cancelDeletePoll();
    });

    effect(() => {
      this.activeTab.set(this.initialTab());
    });
  }

  ngOnDestroy(): void {
    this.clearRevealed();
    this.cancelDeletePoll();
  }

  protected formatDate(iso: string | null | undefined): string {
    return formatUtcTimestamp(iso, this.i18n.locale());
  }

  protected onClose(): void {
    this.clearRevealed();
    this.close.emit();
  }

  protected async revealLatest(): Promise<void> {
    if (!this.canReveal() || this.revealing()) {
      return;
    }
    this.clearRevealed();
    this.revealing.set(true);
    this.error.set(null);

    try {
      const response = await firstValueFrom(
        this.api.revealSecret(this.vault().id, this.secret().name, {})
      );
      this.revealedValue.set(response.value);
      this.startAutoClearTimer();
    } catch (err) {
      const problem = extractProblemDetail(err);
      this.error.set(problem);
      this.authStore.handleApiError(problem);
    } finally {
      this.revealing.set(false);
    }
  }

  protected async copyRevealedValue(): Promise<void> {
    const value = this.revealedValue();
    if (value === null || !navigator.clipboard) {
      return;
    }
    await navigator.clipboard.writeText(value);
    this.copied.set(true);
    setTimeout(() => this.copied.set(false), 2500);
  }

  protected clearRevealed(): void {
    if (this.countdownTimer !== null) {
      clearInterval(this.countdownTimer);
      this.countdownTimer = null;
    }
    this.revealedValue.set(null);
    this.remainingSeconds.set(0);
    this.copied.set(false);
  }

  protected async startSoftDelete(): Promise<void> {
    if (!this.canDelete() || this.deleting()) {
      return;
    }
    if (this.deleteConfirmName() !== this.secret().name) {
      return;
    }

    this.deleting.set(true);
    this.error.set(null);
    this.cancelDeletePoll();

    try {
      const initialOp = await firstValueFrom(
        this.api.softDeleteSecret(this.vault().id, this.secret().name, {
          confirmSecretName: this.deleteConfirmName(),
        })
      );
      this.deleteOp.set(initialOp);

      this.deleteSub = this.opPoller.pollUntilTerminal(initialOp).subscribe({
        next: (op) => {
          this.deleteOp.set(op);
          if (op.state === 'SUCCEEDED') {
            this.deleting.set(false);
            this.clearRevealed();
            this.secretDeleted.emit(this.secret().name);
          } else if (op.state === 'FAILED') {
            this.deleting.set(false);
          }
        },
        error: (err) => {
          this.deleting.set(false);
          const problem = extractProblemDetail(err);
          this.error.set(problem);
          this.authStore.handleApiError(problem);
        },
      });
    } catch (err) {
      this.deleting.set(false);
      const problem = extractProblemDetail(err);
      this.error.set(problem);
      this.authStore.handleApiError(problem);
    }
  }

  private startAutoClearTimer(): void {
    this.remainingSeconds.set(REVEAL_AUTO_CLEAR_SECONDS);
    this.countdownTimer = setInterval(() => {
      const next = this.remainingSeconds() - 1;
      if (next <= 0) {
        this.clearRevealed();
      } else {
        this.remainingSeconds.set(next);
      }
    }, 1000);
  }

  private cancelDeletePoll(): void {
    if (this.deleteSub) {
      this.deleteSub.unsubscribe();
      this.deleteSub = null;
    }
  }
}
