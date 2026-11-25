import {
  ChangeDetectionStrategy,
  Component,
  HostListener,
  OnInit,
  computed,
  inject,
  input,
  output,
  signal,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { firstValueFrom } from 'rxjs';
import { I18nService } from '../core/i18n/i18n.service';
import {
  ProblemDetail,
  SecretMetadataDto,
  VaultDto,
} from '../core/models/api.models';
import { ApiService } from '../core/services/api.service';
import { AuthStore } from '../core/services/auth.store';
import {
  MAX_CONTENT_TYPE_LENGTH,
  MAX_SECRET_VALUE_BYTES,
  extractProblemDetail,
  isValidSecretName,
  toDateTimeLocalValue,
  toUtcIso,
  utf8ByteLength,
} from '../core/utils/secret-validation.util';
import { EnvironmentBadgeComponent } from '../shared/environment-badge.component';
import { ErrorBannerComponent } from '../shared/error-banner.component';

export type SecretFormMode = 'create' | 'update' | 'properties';

interface TagRow {
  id: number;
  key: string;
  value: string;
}

@Component({
  selector: 'app-secret-form-dialog',
  standalone: true,
  imports: [FormsModule, EnvironmentBadgeComponent, ErrorBannerComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="modal-backdrop" (click)="close.emit()">
      <div
        class="modal-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="secretFormTitle"
        (click)="$event.stopPropagation()"
      >
        <div class="modal-header">
          <div class="modal-header__title">
            <h2 id="secretFormTitle">{{ dialogTitle() }}</h2>
            <div class="modal-header__vault">
              <span>{{ vault().name }}</span>
              <app-environment-badge
                [environment]="vault().environment"
                [production]="vault().production"
              />
            </div>
          </div>
          <button
            type="button"
            class="btn btn--ghost btn--xs"
            [attr.aria-label]="i18n.t().form.cancel"
            (click)="close.emit()"
          >
            ✕
          </button>
        </div>

        <form class="modal-body" (ngSubmit)="submit()" autocomplete="off">
          @if (mode() === 'create') {
            <div class="info-banner">{{ i18n.t().form.nonAtomicCreateWarning }}</div>
          } @else if (mode() === 'update') {
            <div class="info-banner">{{ i18n.t().form.nonAtomicUpdateWarning }}</div>
          }

          @if (conflictDetected()) {
            <div class="warn-banner" role="alert">{{ i18n.t().form.conflictBanner }}</div>
          }

          <app-error-banner [problem]="error()" (dismiss)="error.set(null)" />

          <!-- Secret Name -->
          <div class="form-field">
            <label for="secretNameInput">{{ i18n.t().form.nameLabel }}</label>
            <input
              id="secretNameInput"
              name="secretName"
              type="text"
              autocomplete="off"
              spellcheck="false"
              maxlength="127"
              [disabled]="mode() !== 'create'"
              [ngModel]="name()"
              (ngModelChange)="name.set($event)"
            />
            @if (mode() === 'create') {
              <small class="form-hint">{{ i18n.t().form.nameHint }}</small>
              @if (name().length > 0 && !nameValid()) {
                <small class="form-error">{{ i18n.t().form.nameInvalid }}</small>
              }
            }
          </div>

          <!-- Secret Value (create / update only; NEVER trimmed) -->
          @if (mode() !== 'properties') {
            <div class="form-field">
              <div class="field-label-row">
                <label for="secretValueInput">{{ i18n.t().form.valueLabel }}</label>
                <div class="value-tools">
                  <span class="byte-counter" [class.byte-counter--over]="bytesExceeded()">
                    {{ valueBytes() }} / {{ maxBytes }} {{ i18n.t().form.bytesUsed }}
                  </span>
                  <button
                    type="button"
                    class="btn btn--ghost btn--xs"
                    (click)="showValue.set(!showValue())"
                  >
                    {{ showValue() ? i18n.t().form.hideValue : i18n.t().form.showValue }}
                  </button>
                </div>
              </div>

              <textarea
                id="secretValueInput"
                name="secretValue"
                rows="5"
                autocomplete="off"
                spellcheck="false"
                class="secret-textarea"
                [class.secret-textarea--masked]="!showValue()"
                [ngModel]="value()"
                (ngModelChange)="value.set($event)"
              ></textarea>
              <small class="form-hint">{{ i18n.t().form.valueHint }}</small>
              @if (bytesExceeded()) {
                <small class="form-error">{{ i18n.t().form.bytesExceeded }}</small>
              }
            </div>
          }

          @if (mode() === 'update') {
            <label class="checkbox-row">
              <input
                type="checkbox"
                name="preserveMetadata"
                [ngModel]="preserveMetadata()"
                (ngModelChange)="preserveMetadata.set($event)"
              />
              <span>{{ i18n.t().form.preserveMetadataLabel }}</span>
            </label>
          }

          @if (mode() !== 'update' || !preserveMetadata()) {
            <div class="metadata-grid">
              <label class="checkbox-row">
                <input
                  type="checkbox"
                  name="enabled"
                  [ngModel]="enabled()"
                  (ngModelChange)="enabled.set($event)"
                />
                <span>{{ i18n.t().form.enabledLabel }}</span>
              </label>

              <div class="form-field">
                <label for="contentTypeInput">{{ i18n.t().form.contentTypeLabel }}</label>
                <input
                  id="contentTypeInput"
                  name="contentType"
                  type="text"
                  [maxLength]="maxContentTypeLength"
                  [ngModel]="contentType()"
                  (ngModelChange)="contentType.set($event)"
                />
              </div>

              <div class="date-row">
                <div class="form-field">
                  <label for="notBeforeInput">{{ i18n.t().form.notBeforeLabel }}</label>
                  <input
                    id="notBeforeInput"
                    name="notBefore"
                    type="datetime-local"
                    [disabled]="clearNotBefore()"
                    [ngModel]="notBeforeLocal()"
                    (ngModelChange)="notBeforeLocal.set($event)"
                  />
                  @if (mode() === 'properties') {
                    <label class="checkbox-row checkbox-row--sm">
                      <input
                        type="checkbox"
                        name="clearNotBefore"
                        [ngModel]="clearNotBefore()"
                        (ngModelChange)="clearNotBefore.set($event)"
                      />
                      <span>{{ i18n.t().form.clearNotBefore }}</span>
                    </label>
                  }
                </div>

                <div class="form-field">
                  <label for="expiresOnInput">{{ i18n.t().form.expiresOnLabel }}</label>
                  <input
                    id="expiresOnInput"
                    name="expiresOn"
                    type="datetime-local"
                    [disabled]="clearExpiresOn()"
                    [ngModel]="expiresOnLocal()"
                    (ngModelChange)="expiresOnLocal.set($event)"
                  />
                  @if (mode() === 'properties') {
                    <label class="checkbox-row checkbox-row--sm">
                      <input
                        type="checkbox"
                        name="clearExpiresOn"
                        [ngModel]="clearExpiresOn()"
                        (ngModelChange)="clearExpiresOn.set($event)"
                      />
                      <span>{{ i18n.t().form.clearExpiresOn }}</span>
                    </label>
                  }
                </div>
              </div>

              @if (dateOrderInvalid()) {
                <small class="form-error">{{ i18n.t().form.dateOrderError }}</small>
              }

              <!-- Tags editor -->
              <div class="tags-editor">
                <div class="field-label-row">
                  <label>{{ i18n.t().form.tagsLabel }}</label>
                  <button type="button" class="btn btn--ghost btn--xs" (click)="addTag()">
                    + {{ i18n.t().form.addTag }}
                  </button>
                </div>
                @for (tag of tags(); track tag.id) {
                  <div class="tag-row">
                    <input
                      type="text"
                      [placeholder]="i18n.t().form.tagKeyPlaceholder"
                      [ngModel]="tag.key"
                      [name]="'tagKey_' + tag.id"
                      (ngModelChange)="updateTagKey(tag.id, $event)"
                    />
                    <input
                      type="text"
                      [placeholder]="i18n.t().form.tagValuePlaceholder"
                      [ngModel]="tag.value"
                      [name]="'tagVal_' + tag.id"
                      (ngModelChange)="updateTagValue(tag.id, $event)"
                    />
                    <button
                      type="button"
                      class="btn btn--danger-ghost btn--xs"
                      [attr.aria-label]="i18n.t().form.removeTag"
                      (click)="removeTag(tag.id)"
                    >
                      ✕
                    </button>
                  </div>
                }
              </div>
            </div>
          }

          <div class="modal-footer">
            <button type="button" class="btn btn--ghost" [disabled]="saving()" (click)="close.emit()">
              {{ i18n.t().form.cancel }}
            </button>
            <button type="submit" class="btn btn--primary" [disabled]="!canSubmit() || saving()">
              {{ saving() ? i18n.t().form.saving : i18n.t().form.save }}
            </button>
          </div>
        </form>
      </div>
    </div>
  `,
  styles: `
    .modal-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(15, 23, 42, 0.55);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1rem;
      z-index: 1000;
    }
    .modal-dialog {
      width: 100%;
      max-width: 640px;
      max-height: 92vh;
      background: #ffffff;
      border-radius: 12px;
      box-shadow: 0 20px 50px rgba(15, 23, 42, 0.25);
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }
    .modal-header {
      padding: 1rem 1.25rem;
      border-bottom: 1px solid #e2e8f0;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 0.75rem;
    }
    .modal-header__title h2 {
      margin: 0 0 0.25rem;
      font-size: 1.0625rem;
      color: #0f172a;
    }
    .modal-header__vault {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.8125rem;
      color: #475569;
    }
    .modal-body {
      padding: 1.25rem;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }
    .info-banner {
      background: #f0f9ff;
      border: 1px solid #bae6fd;
      color: #0369a1;
      padding: 0.6rem 0.75rem;
      border-radius: 6px;
      font-size: 0.78rem;
      line-height: 1.4;
    }
    .warn-banner {
      background: #fffbeb;
      border: 1px solid #f59e0b;
      color: #92400e;
      padding: 0.65rem 0.75rem;
      border-radius: 6px;
      font-size: 0.8125rem;
      font-weight: 500;
    }
    .field-label-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.5rem;
    }
    .value-tools {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .byte-counter {
      font-size: 0.75rem;
      color: #64748b;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }
    .byte-counter--over {
      color: #dc2626;
      font-weight: 700;
    }
    .secret-textarea {
      width: 100%;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.875rem;
      padding: 0.6rem 0.75rem;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      resize: vertical;
    }
    .secret-textarea--masked {
      -webkit-text-security: disc;
      letter-spacing: 0.08em;
    }
    .checkbox-row {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.875rem;
      color: #0f172a;
      cursor: pointer;
    }
    .checkbox-row--sm {
      font-size: 0.75rem;
      color: #475569;
      margin-top: 0.25rem;
    }
    .metadata-grid {
      display: flex;
      flex-direction: column;
      gap: 0.85rem;
      padding-top: 0.25rem;
    }
    .date-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.75rem;
    }
    .tags-editor {
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }
    .tag-row {
      display: grid;
      grid-template-columns: 1fr 1fr auto;
      gap: 0.5rem;
      align-items: center;
    }
    .tag-row input {
      padding: 0.4rem 0.6rem;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      font-size: 0.8125rem;
    }
    .modal-footer {
      display: flex;
      justify-content: flex-end;
      gap: 0.5rem;
      padding-top: 0.75rem;
      border-top: 1px solid #e2e8f0;
    }
  `,
})
export class SecretFormDialogComponent implements OnInit {
  protected readonly i18n = inject(I18nService);
  private readonly api = inject(ApiService);
  private readonly authStore = inject(AuthStore);

  readonly vault = input.required<VaultDto>();
  readonly mode = input.required<SecretFormMode>();
  readonly secret = input<SecretMetadataDto | null>(null);

  readonly saved = output<SecretMetadataDto>();
  readonly close = output<void>();

  protected readonly maxBytes = MAX_SECRET_VALUE_BYTES;
  protected readonly maxContentTypeLength = MAX_CONTENT_TYPE_LENGTH;

  protected readonly name = signal<string>('');
  protected readonly value = signal<string>('');
  protected readonly showValue = signal<boolean>(false);
  protected readonly enabled = signal<boolean>(true);
  protected readonly contentType = signal<string>('');
  protected readonly notBeforeLocal = signal<string>('');
  protected readonly expiresOnLocal = signal<string>('');
  protected readonly clearNotBefore = signal<boolean>(false);
  protected readonly clearExpiresOn = signal<boolean>(false);
  protected readonly preserveMetadata = signal<boolean>(true);
  protected readonly tags = signal<TagRow[]>([]);

  protected readonly saving = signal<boolean>(false);
  protected readonly error = signal<ProblemDetail | null>(null);
  protected readonly conflictDetected = signal<boolean>(false);

  private nextTagId = 1;

  protected readonly dialogTitle = computed<string>(() => {
    const f = this.i18n.t().form;
    switch (this.mode()) {
      case 'create':
        return f.createTitle;
      case 'update':
        return f.updateTitle;
      case 'properties':
        return f.propertiesTitle;
    }
  });

  protected readonly nameValid = computed<boolean>(() => isValidSecretName(this.name()));
  protected readonly valueBytes = computed<number>(() => utf8ByteLength(this.value()));
  protected readonly bytesExceeded = computed<boolean>(() => this.valueBytes() > MAX_SECRET_VALUE_BYTES);

  protected readonly dateOrderInvalid = computed<boolean>(() => {
    if (this.clearNotBefore() || this.clearExpiresOn()) {
      return false;
    }
    const nbf = toUtcIso(this.notBeforeLocal());
    const exp = toUtcIso(this.expiresOnLocal());
    if (!nbf || !exp) {
      return false;
    }
    return Date.parse(exp) <= Date.parse(nbf);
  });

  protected readonly canSubmit = computed<boolean>(() => {
    if (this.dateOrderInvalid()) {
      return false;
    }
    if (this.mode() === 'create') {
      return this.nameValid() && !this.bytesExceeded();
    }
    if (this.mode() === 'update') {
      return !this.bytesExceeded();
    }
    return true;
  });

  ngOnInit(): void {
    const existing = this.secret();
    if (existing) {
      this.name.set(existing.name);
      this.enabled.set(existing.enabled);
      this.contentType.set(existing.contentType ?? '');
      this.notBeforeLocal.set(toDateTimeLocalValue(existing.notBefore));
      this.expiresOnLocal.set(toDateTimeLocalValue(existing.expiresOn));
      if (existing.tags) {
        this.tags.set(
          Object.entries(existing.tags).map(([key, value]) => ({
            id: this.nextTagId++,
            key,
            value,
          }))
        );
      }
    }
  }

  @HostListener('document:keydown.escape')
  protected onEscape(): void {
    if (!this.saving()) {
      this.close.emit();
    }
  }

  protected addTag(): void {
    this.tags.update((list) => [...list, { id: this.nextTagId++, key: '', value: '' }]);
  }

  protected updateTagKey(id: number, key: string): void {
    this.tags.update((list) => list.map((row) => (row.id === id ? { ...row, key } : row)));
  }

  protected updateTagValue(id: number, value: string): void {
    this.tags.update((list) => list.map((row) => (row.id === id ? { ...row, value } : row)));
  }

  protected removeTag(id: number): void {
    this.tags.update((list) => list.filter((row) => row.id !== id));
  }

  protected async submit(): Promise<void> {
    if (!this.canSubmit() || this.saving()) {
      return;
    }
    this.saving.set(true);
    this.error.set(null);
    this.conflictDetected.set(false);

    const tagRecord = this.buildTagRecord();
    const nbfIso = this.clearNotBefore() ? null : toUtcIso(this.notBeforeLocal());
    const expIso = this.clearExpiresOn() ? null : toUtcIso(this.expiresOnLocal());
    const contentTypeVal = this.contentType().trim() || null;

    try {
      let result: SecretMetadataDto;

      if (this.mode() === 'create') {
        result = await firstValueFrom(
          this.api.createSecret(this.vault().id, {
            name: this.name(),
            value: this.value(), // NEVER trim secret value!
            enabled: this.enabled(),
            contentType: contentTypeVal,
            notBefore: nbfIso,
            expiresOn: expIso,
            tags: tagRecord,
          })
        );
      } else if (this.mode() === 'update') {
        const existing = this.secret()!;
        const preserve = this.preserveMetadata();
        result = await firstValueFrom(
          this.api.updateSecretValue(this.vault().id, existing.name, {
            value: this.value(), // NEVER trim secret value!
            expectedLatestVersion: existing.version ?? null,
            preserveMetadata: preserve,
            enabled: preserve ? null : this.enabled(),
            contentType: preserve ? null : contentTypeVal,
            notBefore: preserve ? null : nbfIso,
            expiresOn: preserve ? null : expIso,
            tags: preserve ? null : tagRecord,
          })
        );
      } else {
        const existing = this.secret()!;
        result = await firstValueFrom(
          this.api.updateSecretProperties(this.vault().id, existing.name, {
            version: existing.version ?? null,
            enabled: this.enabled(),
            contentType: contentTypeVal,
            notBefore: nbfIso,
            expiresOn: expIso,
            clearNotBefore: this.clearNotBefore(),
            clearExpiresOn: this.clearExpiresOn(),
            tags: tagRecord,
          })
        );
      }

      // Clear secret value from form memory immediately on success
      this.value.set('');
      this.saved.emit(result);
    } catch (err) {
      const problem = extractProblemDetail(err);
      if (problem.status === 409) {
        this.conflictDetected.set(true);
      }
      this.error.set(problem);
      this.authStore.handleApiError(problem);
    } finally {
      this.saving.set(false);
    }
  }

  private buildTagRecord(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const row of this.tags()) {
      const k = row.key.trim();
      if (k.length > 0) {
        out[k] = row.value;
      }
    }
    return out;
  }
}
