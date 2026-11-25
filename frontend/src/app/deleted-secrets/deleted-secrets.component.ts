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
import { Subscription, firstValueFrom } from 'rxjs';
import { I18nService } from '../core/i18n/i18n.service';
import {
  DeletedSecretDto,
  OperationStatusResponse,
  ProblemDetail,
  VaultDto,
} from '../core/models/api.models';
import { ApiService } from '../core/services/api.service';
import { AuthStore } from '../core/services/auth.store';
import { OperationPollerService } from '../core/services/operation-poller.service';
import { extractProblemDetail, formatUtcTimestamp } from '../core/utils/secret-validation.util';
import { ErrorBannerComponent } from '../shared/error-banner.component';

@Component({
  selector: 'app-deleted-secrets',
  standalone: true,
  imports: [ErrorBannerComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="deleted-panel" [attr.aria-label]="i18n.t().deleted.title">
      <div class="deleted-header">
        <div>
          <h3>{{ i18n.t().deleted.title }}</h3>
          <p class="deleted-subtitle">{{ i18n.t().deleted.subtitle }}</p>
        </div>
        @if (canRecover()) {
          <button
            type="button"
            class="btn btn--secondary btn--sm"
            [disabled]="loading()"
            (click)="loadDeletedSecrets()"
          >
            ↻ {{ i18n.t().deleted.refresh }}
          </button>
        }
      </div>

      <div class="retention-notice">{{ i18n.t().deleted.retentionNotice }}</div>

      <app-error-banner [problem]="error()" (dismiss)="error.set(null)" />

      @if (activeOp(); as op) {
        <div class="op-banner" role="status">
          @if (op.state === 'PENDING' || op.state === 'IN_PROGRESS') {
            <span class="spinner" aria-hidden="true"></span>
            <span>{{ op.secretName }} — {{ i18n.t().deleted.recovering }} ({{ op.state }})</span>
          } @else if (op.state === 'SUCCEEDED') {
            <span>✓ {{ op.secretName }} — {{ i18n.t().deleted.recoverSuccess }}</span>
          } @else {
            <span>✕ {{ op.secretName }} — {{ i18n.t().deleted.recoverFailed }}: {{ op.errorMessage || op.errorCode }}</span>
          }
        </div>
      }

      @if (!canRecover()) {
        <div class="deleted-state">{{ i18n.t().deleted.noPermission }}</div>
      } @else if (loading()) {
        <div class="deleted-state">{{ i18n.t().deleted.loading }}</div>
      } @else if (items().length === 0) {
        <div class="deleted-state">{{ i18n.t().deleted.empty }}</div>
      } @else {
        <div class="deleted-table-wrap">
          <table class="deleted-table">
            <thead>
              <tr>
                <th>{{ i18n.t().secrets.colName }}</th>
                <th>{{ i18n.t().deleted.deletedOn }}</th>
                <th>{{ i18n.t().deleted.scheduledPurge }}</th>
                <th>{{ i18n.t().secrets.colActions }}</th>
              </tr>
            </thead>
            <tbody>
              @for (item of items(); track item.name) {
                <tr>
                  <td><code>{{ item.name }}</code></td>
                  <td>{{ formatDate(item.deletedOn) }}</td>
                  <td>{{ formatDate(item.scheduledPurgeDate) }}</td>
                  <td>
                    <button
                      type="button"
                      class="btn btn--primary btn--xs"
                      [disabled]="recoveringName() !== null"
                      (click)="recover(item)"
                    >
                      {{ recoveringName() === item.name ? i18n.t().deleted.recovering : i18n.t().deleted.recoverButton }}
                    </button>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }
    </section>
  `,
  styles: `
    .deleted-panel {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 1rem;
      height: 100%;
      overflow-y: auto;
    }
    .deleted-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 0.75rem;
    }
    .deleted-header h3 {
      margin: 0 0 0.2rem;
      font-size: 1rem;
      color: #0f172a;
    }
    .deleted-subtitle {
      margin: 0;
      font-size: 0.8125rem;
      color: #64748b;
    }
    .retention-notice {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      padding: 0.6rem 0.75rem;
      font-size: 0.8rem;
      color: #475569;
    }
    .op-banner {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      background: #f0f9ff;
      border: 1px solid #bae6fd;
      color: #0369a1;
      padding: 0.65rem 0.85rem;
      border-radius: 6px;
      font-size: 0.8125rem;
      font-weight: 500;
    }
    .deleted-state {
      text-align: center;
      padding: 2rem;
      color: #64748b;
      font-size: 0.875rem;
    }
    .deleted-table-wrap {
      overflow-x: auto;
    }
    .deleted-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.8125rem;
    }
    .deleted-table th,
    .deleted-table td {
      text-align: left;
      padding: 0.65rem 0.75rem;
      border-bottom: 1px solid #e2e8f0;
    }
    .deleted-table th {
      background: #f8fafc;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      color: #64748b;
    }
  `,
})
export class DeletedSecretsComponent implements OnDestroy {
  protected readonly i18n = inject(I18nService);
  private readonly api = inject(ApiService);
  private readonly authStore = inject(AuthStore);
  private readonly opPoller = inject(OperationPollerService);

  readonly vault = input.required<VaultDto>();
  readonly secretRecovered = output<string>();

  protected readonly items = signal<DeletedSecretDto[]>([]);
  protected readonly loading = signal<boolean>(false);
  protected readonly error = signal<ProblemDetail | null>(null);
  protected readonly recoveringName = signal<string | null>(null);
  protected readonly activeOp = signal<OperationStatusResponse | null>(null);

  protected readonly canRecover = computed<boolean>(() =>
    this.authStore.hasPermission(this.vault().id, 'SECRET_DELETE_RECOVER', this.vault().permissions)
  );

  private pollSub: Subscription | null = null;

  constructor() {
    effect(() => {
      const v = this.vault();
      this.cancelPoll();
      this.activeOp.set(null);
      this.recoveringName.set(null);
      if (this.authStore.hasPermission(v.id, 'SECRET_DELETE_RECOVER', v.permissions)) {
        void this.loadDeletedSecrets();
      } else {
        this.items.set([]);
      }
    });
  }

  ngOnDestroy(): void {
    this.cancelPoll();
  }

  protected formatDate(iso: string | null | undefined): string {
    return formatUtcTimestamp(iso, this.i18n.locale());
  }

  protected async loadDeletedSecrets(): Promise<void> {
    this.loading.set(true);
    this.error.set(null);
    try {
      const list = await firstValueFrom(this.api.listDeletedSecrets(this.vault().id));
      this.items.set(list);
    } catch (err) {
      const problem = extractProblemDetail(err);
      this.error.set(problem);
      this.authStore.handleApiError(problem);
    } finally {
      this.loading.set(false);
    }
  }

  protected async recover(item: DeletedSecretDto): Promise<void> {
    if (!this.canRecover() || this.recoveringName() !== null) {
      return;
    }
    this.recoveringName.set(item.name);
    this.error.set(null);
    this.cancelPoll();

    try {
      const initialOp = await firstValueFrom(
        this.api.recoverDeletedSecret(this.vault().id, item.name)
      );
      this.activeOp.set(initialOp);

      this.pollSub = this.opPoller.pollUntilTerminal(initialOp).subscribe({
        next: (op) => {
          this.activeOp.set(op);
          if (op.state === 'SUCCEEDED') {
            this.recoveringName.set(null);
            this.secretRecovered.emit(item.name);
            void this.loadDeletedSecrets();
          } else if (op.state === 'FAILED') {
            this.recoveringName.set(null);
          }
        },
        error: (err) => {
          this.recoveringName.set(null);
          const problem = extractProblemDetail(err);
          this.error.set(problem);
          this.authStore.handleApiError(problem);
        },
      });
    } catch (err) {
      this.recoveringName.set(null);
      const problem = extractProblemDetail(err);
      this.error.set(problem);
      this.authStore.handleApiError(problem);
    }
  }

  private cancelPoll(): void {
    if (this.pollSub) {
      this.pollSub.unsubscribe();
      this.pollSub = null;
    }
  }
}
