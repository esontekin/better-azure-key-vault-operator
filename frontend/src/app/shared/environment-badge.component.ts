import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

@Component({
  selector: 'app-environment-badge',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <span class="env-badge" [class]="'env-badge env-badge--' + variant()">
      {{ label() }}
    </span>
  `,
  styles: `
    .env-badge {
      display: inline-flex;
      align-items: center;
      padding: 0.125rem 0.5rem;
      border-radius: 9999px;
      font-size: 0.6875rem;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      white-space: nowrap;
      border: 1px solid transparent;
    }
    .env-badge--prod {
      background: #dc2626;
      color: #ffffff;
      border-color: #b91c1c;
    }
    .env-badge--staging {
      background: #fef3c7;
      color: #92400e;
      border-color: #f59e0b;
    }
    .env-badge--dev {
      background: #dbeafe;
      color: #1e40af;
      border-color: #93c5fd;
    }
    .env-badge--other {
      background: #f1f5f9;
      color: #475569;
      border-color: #cbd5e1;
    }
  `,
})
export class EnvironmentBadgeComponent {
  readonly environment = input.required<string>();
  readonly production = input<boolean | undefined>(undefined);

  protected readonly variant = computed<'prod' | 'staging' | 'dev' | 'other'>(() => {
    const env = (this.environment() || '').toLowerCase();
    if (this.production() === true || env.includes('prod') || env === 'prd') {
      return 'prod';
    }
    if (env.includes('stag') || env === 'stg' || env === 'uat' || env === 'preprod') {
      return 'staging';
    }
    if (env.includes('dev') || env.includes('test') || env === 'qa' || env === 'local') {
      return 'dev';
    }
    return 'other';
  });

  protected readonly label = computed<string>(() => {
    if (this.variant() === 'prod') {
      return 'PROD';
    }
    const raw = (this.environment() || '').trim();
    return raw ? raw.toUpperCase() : 'UNKNOWN';
  });
}
