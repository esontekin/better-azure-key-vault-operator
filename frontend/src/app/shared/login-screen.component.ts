import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { I18nService } from '../core/i18n/i18n.service';
import { AuthStore } from '../core/services/auth.store';
import { ErrorBannerComponent } from './error-banner.component';

@Component({
  selector: 'app-login-screen',
  standalone: true,
  imports: [FormsModule, ErrorBannerComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="login-page">
      <div class="login-card">
        <div class="login-card__header">
          <div class="login-logo" aria-hidden="true">
            <svg viewBox="0 0 32 32" width="36" height="36" fill="none">
              <rect width="32" height="32" rx="8" fill="#0F4C81" />
              <path
                d="M16 6.5a5.5 5.5 0 0 0-5.5 5.5v2H9a1.5 1.5 0 0 0-1.5 1.5v8A1.5 1.5 0 0 0 9 25h14a1.5 1.5 0 0 0 1.5-1.5v-8A1.5 1.5 0 0 0 23 14h-1.5v-2A5.5 5.5 0 0 0 16 6.5Zm-3 5.5a3 3 0 1 1 6 0v2h-6v-2Zm3 5.5a2 2 0 0 1 1 3.73V22.5a1 1 0 1 1-2 0v-1.27A2 2 0 0 1 16 17.5Z"
                fill="#FFFFFF"
              />
            </svg>
          </div>
          <div class="login-card__titles">
            <h1>{{ i18n.t().app.title }}</h1>
            <span class="profile-pill">
              {{ authStore.profile() === 'server' ? i18n.t().app.profileServer : i18n.t().app.profileLocal }}
            </span>
          </div>
          <button
            type="button"
            class="btn btn--ghost btn--sm"
            (click)="i18n.toggleLanguage()"
          >
            {{ i18n.language().toUpperCase() }}
          </button>
        </div>

        <app-error-banner
          [problem]="authStore.error()"
          (dismiss)="authStore.clearError()"
        />

        @if (authStore.authMode() === 'OIDC') {
          <div class="login-body">
            <h2>{{ i18n.t().login.serverTitle }}</h2>
            <p class="login-subtitle">{{ i18n.t().login.serverSubtitle }}</p>
            <button
              type="button"
              class="btn btn--primary btn--full"
              [disabled]="!safeOidcUrl()"
              (click)="startOidcLogin()"
            >
              {{ i18n.t().login.submitOidc }}
            </button>
          </div>
        } @else {
          <form class="login-body" (ngSubmit)="submitBootstrap()" autocomplete="off">
            <h2>{{ i18n.t().login.localTitle }}</h2>
            <p class="login-subtitle">{{ i18n.t().login.localSubtitle }}</p>

            <div class="form-field">
              <label for="bootstrapTokenInput">{{ i18n.t().login.tokenLabel }}</label>
              <input
                id="bootstrapTokenInput"
                name="bootstrapToken"
                type="password"
                autocomplete="off"
                spellcheck="false"
                required
                minlength="16"
                maxlength="256"
                [placeholder]="i18n.t().login.tokenPlaceholder"
                [ngModel]="token()"
                (ngModelChange)="token.set($event)"
              />
              <small class="form-hint">{{ i18n.t().login.tokenHint }}</small>
            </div>

            <button
              type="submit"
              class="btn btn--primary btn--full"
              [disabled]="authStore.submitting() || token().trim().length < 16"
            >
              {{ authStore.submitting() ? i18n.t().app.loading : i18n.t().login.submitLocal }}
            </button>
          </form>
        }

        <div class="login-footer">
          <svg viewBox="0 0 20 20" width="16" height="16" fill="currentColor" aria-hidden="true">
            <path fill-rule="evenodd" d="M10 1a4.5 4.5 0 0 0-4.5 4.5V9H5a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-6a2 2 0 0 0-2-2h-.5V5.5A4.5 4.5 0 0 0 10 1Zm3 8V5.5a3 3 0 1 0-6 0V9h6Z" clip-rule="evenodd" />
          </svg>
          <span>{{ i18n.t().login.securityNote }}</span>
        </div>
      </div>
    </div>
  `,
  styles: `
    .login-page {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
      background: linear-gradient(135deg, #f0f4f8 0%, #e2e8f0 100%);
    }
    .login-card {
      width: 100%;
      max-width: 460px;
      background: #ffffff;
      border-radius: 12px;
      box-shadow: 0 10px 30px rgba(15, 23, 42, 0.08);
      border: 1px solid #e2e8f0;
      padding: 1.75rem;
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
    }
    .login-card__header {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .login-card__titles {
      flex: 1;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      flex-wrap: wrap;
    }
    .login-card__titles h1 {
      font-size: 1.125rem;
      font-weight: 700;
      margin: 0;
      color: #0f172a;
    }
    .profile-pill {
      font-size: 0.6875rem;
      font-weight: 700;
      padding: 0.15rem 0.5rem;
      border-radius: 9999px;
      background: #e0f2fe;
      color: #0369a1;
      letter-spacing: 0.04em;
    }
    .login-body h2 {
      font-size: 1.0625rem;
      margin: 0 0 0.35rem;
      color: #0f172a;
    }
    .login-subtitle {
      margin: 0 0 1.25rem;
      font-size: 0.875rem;
      color: #475569;
      line-height: 1.5;
    }
    .login-footer {
      display: flex;
      align-items: flex-start;
      gap: 0.5rem;
      padding-top: 1rem;
      border-top: 1px solid #f1f5f9;
      font-size: 0.75rem;
      color: #64748b;
      line-height: 1.4;
    }
    .login-footer svg {
      flex-shrink: 0;
      margin-top: 1px;
      color: #0f4c81;
    }
  `,
})
export class LoginScreenComponent {
  protected readonly i18n = inject(I18nService);
  protected readonly authStore = inject(AuthStore);

  protected readonly token = signal<string>('');

  protected safeOidcUrl(): string | null {
    const raw = this.authStore.status()?.oidcLoginUrl;
    if (!raw) {
      return '/oauth2/authorization/oidc';
    }
    // Only allow relative same-origin OIDC start paths to prevent open redirect
    if (raw.startsWith('/') && !raw.startsWith('//')) {
      return raw;
    }
    return null;
  }

  protected async submitBootstrap(): Promise<void> {
    const value = this.token().trim();
    if (value.length < 16) {
      return;
    }
    // Clear token from component state immediately after reading
    this.token.set('');
    await this.authStore.loginWithBootstrapToken(value);
  }

  protected startOidcLogin(): void {
    const url = this.safeOidcUrl();
    if (url) {
      window.location.assign(url);
    }
  }
}
