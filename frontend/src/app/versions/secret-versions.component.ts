import {
  ChangeDetectionStrategy,
  Component,
  OnDestroy,
  effect,
  inject,
  input,
  output,
  signal,
} from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { I18nService } from '../core/i18n/i18n.service';
import {
  ProblemDetail,
  SecretMetadataDto,
  SecretVersionDto,
  VaultDto,
} from '../core/models/api.models';
import { ApiService } from '../core/services/api.service';
import { AuthStore } from '../core/services/auth.store';
import { extractProblemDetail, formatUtcTimestamp } from '../core/utils/secret-validation.util';
import { ErrorBannerComponent } from '../shared/error-banner.component';

const REVEAL_TTL_SECONDS = 30;

@Component({
  selector: 'app-secret-versions',
  standalone: true,
  imports: [ErrorBannerComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="versions-container">
      <p class="versions-notice">{{ i18n.t().versions.noAutoFetchNotice }}</p>

      <app-error-banner [problem]="error()" (dismiss)="error.set(null)" />

      @if (successMessage()) {
        <div class="notice-banner notice-banner--success" role="status">
          {{ successMessage() }}
        </div>
      }

      @if (pendingRestoreVersion(); as target) {
        <div class="restore-confirm" role="alertdialog" aria-labelledby="restoreTitle">
          <h4 id="restoreTitle">{{ i18n.t().versions.restoreConfirmTitle }}</h4>
          <p>{{ i18n.t().versions.restoreConfirmBody }}</p>
          <div class="restore-confirm__meta">
            <code>{{ target.version }}</code>
          </div>
          <div class="restore-confirm__actions">
            <button
              type="button"
              class="btn btn--primary btn--sm"
              [disabled]="restoring()"
              (click)="confirmRestore(target)"
            >
              {{ restoring() ? i18n.t().form.saving : i18n.t().versions.restoreConfirmProceed }}
            </button>
            <button
              type="button"
              class="btn btn--ghost btn--sm"
              [disabled]="restoring()"
              (click)="pendingRestoreVersion.set(null)"
            >
              {{ i18n.t().form.cancel }}
            </button>
          </div>
        </div>
      }

      @if (loading()) {
        <div class="versions-state">{{ i18n.t().versions.loading }}</div>
      } @else if (versions().length === 0) {
        <div class="versions-state">{{ i18n.t().versions.empty }}</div>
      } @else {
        <div class="version-list">
          @for (v of versions(); track v.version) {
            <div class="version-card" [class.version-card--latest]="v.latest">
              <div class="version-card__top">
                <code class="version-id">{{ v.version }}</code>
                <div class="version-badges">
                  @if (v.latest) {
                    <span class="badge badge--latest">{{ i18n.t().versions.latestBadge }}</span>
                  }
                  <span class="badge" [class.badge--enabled]="v.enabled" [class.badge--disabled]="!v.enabled">
                    {{ v.enabled ? i18n.t().secrets.enabled : i18n.t().secrets.disabled }}
                  </span>
                </div>
              </div>

              <div class="version-card__dates">
                <span>{{ i18n.t().detail.createdOn }}: {{ formatDate(v.createdOn) }}</span>
                <span>{{ i18n.t().detail.updatedOn }}: {{ formatDate(v.updatedOn) }}</span>
                @if (v.expiresOn) {
                  <span>{{ i18n.t().detail.expiresOn }}: {{ formatDate(v.expiresOn) }}</span>
                }
              </div>

              @if (revealedVersionId() === v.version && revealedValue() !== null) {
                <div class="revealed-box">
                  <pre class="revealed-value">{{ revealedValue() }}</pre>
                  <div class="revealed-box__footer">
                    <span class="countdown">{{ i18n.t().detail.autoClearIn }}: {{ remainingSeconds() }}s</span>
                    <div class="revealed-box__btns">
                      <button type="button" class="btn btn--secondary btn--xs" (click)="copyRevealed()">
                        {{ copied() ? i18n.t().detail.copiedNotice : i18n.t().versions.copyValue }}
                      </button>
                      <button type="button" class="btn btn--ghost btn--xs" (click)="clearRevealed()">
                        {{ i18n.t().versions.hideVersion }}
                      </button>
                    </div>
                  </div>
                  <small class="clipboard-note">{{ i18n.t().detail.clipboardDisclaimer }}</small>
                </div>
              }

              <div class="version-card__actions">
                @if (canReveal()) {
                  <button
                    type="button"
                    class="btn btn--secondary btn--xs"
                    [disabled]="revealingVersionId() === v.version"
                    (click)="revealVersion(v)"
                  >
                    {{ revealedVersionId() === v.version ? i18n.t().versions.hideVersion : i18n.t().versions.revealVersion }}
                  </button>
                }
                @if (canRestore() && !v.latest) {
                  <button
                    type="button"
                    class="btn btn--ghost btn--xs"
                    (click)="pendingRestoreVersion.set(v)"
                  >
                    {{ i18n.t().versions.restoreButton }}
                  </button>
                }
              </div>
            </div>
          }
        </div>
      }
    </div>
  `,
  styles: `
    .versions-container {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }
    .versions-notice {
      margin: 0;
      font-size: 0.75rem;
      color: #475569;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      padding: 0.5rem 0.75rem;
    }
    .versions-state {
      text-align: center;
      padding: 1.5rem;
      color: #64748b;
      font-size: 0.875rem;
    }
    .version-list {
      display: flex;
      flex-direction: column;
      gap: 0.65rem;
    }
    .version-card {
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 0.75rem;
      background: #ffffff;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }
    .version-card--latest {
      border-color: #93c5fd;
      background: #f8fbff;
    }
    .version-card__top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.5rem;
    }
    .version-id {
      font-size: 0.75rem;
      color: #0f172a;
      word-break: break-all;
    }
    .version-badges {
      display: flex;
      gap: 0.35rem;
      flex-shrink: 0;
    }
    .badge {
      padding: 0.1rem 0.45rem;
      border-radius: 9999px;
      font-size: 0.6875rem;
      font-weight: 600;
    }
    .badge--latest { background: #dbeafe; color: #1e40af; }
    .badge--enabled { background: #dcfce7; color: #166534; }
    .badge--disabled { background: #f1f5f9; color: #64748b; }
    .version-card__dates {
      display: flex;
      flex-direction: column;
      gap: 0.2rem;
      font-size: 0.75rem;
      color: #64748b;
    }
    .version-card__actions {
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
    }
    .revealed-box {
      background: #0f172a;
      color: #f8fafc;
      border-radius: 6px;
      padding: 0.65rem;
      display: flex;
      flex-direction: column;
      gap: 0.45rem;
    }
    .revealed-value {
      margin: 0;
      white-space: pre-wrap;
      word-break: break-all;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.8125rem;
      max-height: 180px;
      overflow-y: auto;
    }
    .revealed-box__footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.75rem;
    }
    .revealed-box__btns {
      display: flex;
      gap: 0.35rem;
    }
    .countdown {
      color: #fbbf24;
      font-weight: 600;
    }
    .clipboard-note {
      font-size: 0.7rem;
      color: #94a3b8;
    }
    .restore-confirm {
      background: #fffbeb;
      border: 1px solid #f59e0b;
      border-radius: 8px;
      padding: 0.85rem;
      font-size: 0.8125rem;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }
    .restore-confirm h4 {
      margin: 0;
      color: #92400e;
    }
    .restore-confirm p {
      margin: 0;
      color: #78350f;
    }
    .restore-confirm__actions {
      display: flex;
      gap: 0.5rem;
    }
    .notice-banner--success {
      padding: 0.6rem 0.75rem;
      border-radius: 6px;
      background: #dcfce7;
      border: 1px solid #86efac;
      color: #166534;
      font-size: 0.8125rem;
    }
  `,
})
export class SecretVersionsComponent implements OnDestroy {
  protected readonly i18n = inject(I18nService);
  private readonly api = inject(ApiService);
  private readonly authStore = inject(AuthStore);

  readonly vault = input.required<VaultDto>();
  readonly secret = input.required<SecretMetadataDto>();
  readonly versionRestored = output<SecretMetadataDto>();

  protected readonly versions = signal<SecretVersionDto[]>([]);
  protected readonly loading = signal<boolean>(false);
  protected readonly error = signal<ProblemDetail | null>(null);
  protected readonly successMessage = signal<string | null>(null);

  protected readonly revealingVersionId = signal<string | null>(null);
  protected readonly revealedVersionId = signal<string | null>(null);
  protected readonly revealedValue = signal<string | null>(null);
  protected readonly remainingSeconds = signal<number>(0);
  protected readonly copied = signal<boolean>(false);

  protected readonly pendingRestoreVersion = signal<SecretVersionDto | null>(null);
  protected readonly restoring = signal<boolean>(false);

  private countdownTimer: ReturnType<typeof setInterval> | null = null;

  constructor() {
    effect(() => {
      const v = this.vault();
      const s = this.secret();
      this.clearRevealed();
      this.pendingRestoreVersion.set(null);
      this.successMessage.set(null);
      void this.loadVersions(v.id, s.name);
    });
  }

  ngOnDestroy(): void {
    this.clearRevealed();
  }

  protected canReveal(): boolean {
    const v = this.vault();
    return this.authStore.hasPermission(v.id, 'SECRET_REVEAL', v.permissions);
  }

  protected canRestore(): boolean {
    const v = this.vault();
    return (
      this.authStore.hasPermission(v.id, 'SECRET_WRITE', v.permissions) &&
      this.authStore.hasPermission(v.id, 'SECRET_REVEAL', v.permissions)
    );
  }

  protected formatDate(iso: string | null | undefined): string {
    return formatUtcTimestamp(iso, this.i18n.locale());
  }

  private async loadVersions(vaultId: string, secretName: string): Promise<void> {
    this.loading.set(true);
    this.error.set(null);
    try {
      const list = await firstValueFrom(this.api.listSecretVersions(vaultId, secretName));
      this.versions.set(list);
    } catch (err) {
      const problem = extractProblemDetail(err);
      this.error.set(problem);
      this.authStore.handleApiError(problem);
    } finally {
      this.loading.set(false);
    }
  }

  protected async revealVersion(version: SecretVersionDto): Promise<void> {
    if (this.revealedVersionId() === version.version) {
      this.clearRevealed();
      return;
    }
    this.clearRevealed();
    this.revealingVersionId.set(version.version);
    this.error.set(null);

    try {
      const res = await firstValueFrom(
        this.api.revealSecret(this.vault().id, this.secret().name, { version: version.version })
      );
      this.revealedVersionId.set(version.version);
      this.revealedValue.set(res.value);
      this.startAutoClearTimer();
    } catch (err) {
      const problem = extractProblemDetail(err);
      this.error.set(problem);
      this.authStore.handleApiError(problem);
    } finally {
      this.revealingVersionId.set(null);
    }
  }

  protected async copyRevealed(): Promise<void> {
    const val = this.revealedValue();
    if (val === null || !navigator.clipboard) {
      return;
    }
    await navigator.clipboard.writeText(val);
    this.copied.set(true);
    setTimeout(() => this.copied.set(false), 2500);
  }

  protected async confirmRestore(target: SecretVersionDto): Promise<void> {
    this.restoring.set(true);
    this.error.set(null);
    this.successMessage.set(null);
    try {
      const revealed = await firstValueFrom(
        this.api.revealSecret(this.vault().id, this.secret().name, { version: target.version })
      );
      const updated = await firstValueFrom(
        this.api.updateSecretValue(this.vault().id, this.secret().name, {
          value: revealed.value,
          expectedLatestVersion: this.secret().version ?? null,
          preserveMetadata: true,
        })
      );
      this.pendingRestoreVersion.set(null);
      this.successMessage.set(this.i18n.t().versions.restoreSuccess);
      this.versionRestored.emit(updated);
      await this.loadVersions(this.vault().id, this.secret().name);
    } catch (err) {
      const problem = extractProblemDetail(err);
      this.error.set(problem);
      this.authStore.handleApiError(problem);
    } finally {
      this.restoring.set(false);
    }
  }

  protected clearRevealed(): void {
    if (this.countdownTimer !== null) {
      clearInterval(this.countdownTimer);
      this.countdownTimer = null;
    }
    this.revealedVersionId.set(null);
    this.revealedValue.set(null);
    this.remainingSeconds.set(0);
    this.copied.set(false);
  }

  private startAutoClearTimer(): void {
    this.remainingSeconds.set(REVEAL_TTL_SECONDS);
    this.countdownTimer = setInterval(() => {
      const next = this.remainingSeconds() - 1;
      if (next <= 0) {
        this.clearRevealed();
      } else {
        this.remainingSeconds.set(next);
      }
    }, 1000);
  }
}
