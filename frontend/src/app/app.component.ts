import { ChangeDetectionStrategy, Component, OnInit, inject } from '@angular/core';
import { I18nService } from './core/i18n/i18n.service';
import { AuthStore } from './core/services/auth.store';
import { AppShellComponent } from './layout/app-shell.component';
import { LoginScreenComponent } from './shared/login-screen.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [LoginScreenComponent, AppShellComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (authStore.loading()) {
      <div class="boot-screen" role="status">
        <span class="spinner spinner--lg" aria-hidden="true"></span>
        <p>{{ i18n.t().app.loading }}</p>
      </div>
    } @else if (authStore.authenticated()) {
      <app-shell />
    } @else {
      <app-login-screen />
    }
  `,
  styles: `
    .boot-screen {
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: 0.75rem;
      color: #475569;
      font-size: 0.9rem;
    }
  `,
})
export class AppComponent implements OnInit {
  protected readonly i18n = inject(I18nService);
  protected readonly authStore = inject(AuthStore);

  ngOnInit(): void {
    void this.authStore.loadStatus();
  }
}
