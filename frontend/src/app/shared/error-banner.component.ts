import { ChangeDetectionStrategy, Component, computed, inject, input, output } from '@angular/core';
import { I18nService } from '../core/i18n/i18n.service';
import { ProblemDetail } from '../core/models/api.models';
import { isAppAuthError, isAzureAuthError } from '../core/utils/secret-validation.util';

@Component({
  selector: 'app-error-banner',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (problem(); as p) {
      <div
        class="error-banner"
        role="alert"
        [class.error-banner--azure]="azureAuth()"
        [class.error-banner--auth]="appAuth()"
      >
        <div class="error-banner__icon" aria-hidden="true">
          <svg viewBox="0 0 20 20" width="20" height="20" fill="currentColor">
            <path fill-rule="evenodd" d="M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16Zm-.75-11.25a.75.75 0 0 1 1.5 0v4.5a.75.75 0 0 1-1.5 0v-4.5Zm.75 7.5a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z" clip-rule="evenodd" />
          </svg>
        </div>
        <div class="error-banner__content">
          <div class="error-banner__title">
            @if (azureAuth()) {
              {{ i18n.t().errors.azureAuthTitle }}
            } @else if (appAuth()) {
              {{ i18n.t().errors.appAuthTitle }}
            } @else {
              {{ p.title }}
            }
          </div>
          <p class="error-banner__detail">{{ p.detail }}</p>
          @if (fieldErrorEntries().length > 0) {
            <ul class="error-banner__fields">
              @for (entry of fieldErrorEntries(); track entry[0]) {
                <li><strong>{{ entry[0] }}</strong>: {{ entry[1] }}</li>
              }
            </ul>
          }
          <div class="error-banner__meta">
            <span>{{ i18n.t().errors.errorCode }}: <code>{{ p.errorCode }}</code></span>
            <span>{{ i18n.t().errors.correlationId }}: <code>{{ p.correlationId }}</code></span>
            @if (p.retryAfterSeconds) {
              <span>{{ i18n.t().errors.retryAfter }}: <strong>{{ p.retryAfterSeconds }}s</strong></span>
            }
          </div>
        </div>
        @if (dismissible()) {
          <button
            type="button"
            class="btn-icon error-banner__close"
            [attr.aria-label]="i18n.t().errors.dismiss"
            (click)="dismiss.emit()"
          >
            ✕
          </button>
        }
      </div>
    }
  `,
  styles: `
    .error-banner {
      display: flex;
      align-items: flex-start;
      gap: 0.75rem;
      padding: 0.875rem 1rem;
      border-radius: 8px;
      background: #fef2f2;
      border: 1px solid #fecaca;
      color: #991b1b;
      font-size: 0.875rem;
      line-height: 1.45;
    }
    .error-banner--azure {
      background: #fffbeb;
      border-color: #fde68a;
      color: #92400e;
    }
    .error-banner--auth {
      background: #eff6ff;
      border-color: #bfdbfe;
      color: #1e40af;
    }
    .error-banner__icon {
      flex-shrink: 0;
      margin-top: 2px;
    }
    .error-banner__content {
      flex: 1;
      min-width: 0;
    }
    .error-banner__title {
      font-weight: 600;
      margin-bottom: 0.2rem;
    }
    .error-banner__detail {
      margin: 0 0 0.4rem;
      word-break: break-word;
    }
    .error-banner__fields {
      margin: 0.25rem 0 0.5rem 1.25rem;
      padding: 0;
    }
    .error-banner__meta {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      font-size: 0.75rem;
      opacity: 0.9;
    }
    .error-banner__meta code {
      background: rgba(0, 0, 0, 0.06);
      padding: 0.1rem 0.35rem;
      border-radius: 4px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }
    .error-banner__close {
      background: transparent;
      border: none;
      color: inherit;
      cursor: pointer;
      padding: 0.2rem 0.4rem;
      border-radius: 4px;
      font-size: 0.85rem;
    }
    .error-banner__close:hover {
      background: rgba(0, 0, 0, 0.08);
    }
  `,
})
export class ErrorBannerComponent {
  protected readonly i18n = inject(I18nService);

  readonly problem = input<ProblemDetail | null>(null);
  readonly dismissible = input<boolean>(true);
  readonly dismiss = output<void>();

  protected readonly azureAuth = computed(() => isAzureAuthError(this.problem()));
  protected readonly appAuth = computed(() => isAppAuthError(this.problem()));
  protected readonly fieldErrorEntries = computed(() => {
    const fields = this.problem()?.fieldErrors;
    return fields ? Object.entries(fields) : [];
  });
}
