import { Injectable, computed, signal } from '@angular/core';
import { EN_TRANSLATIONS } from './en';
import { Language, TranslationCatalog } from './i18n.types';
import { TR_TRANSLATIONS } from './tr';

@Injectable({ providedIn: 'root' })
export class I18nService {
  readonly language = signal<Language>('tr');

  readonly t = computed<TranslationCatalog>(() =>
    this.language() === 'tr' ? TR_TRANSLATIONS : EN_TRANSLATIONS
  );

  readonly locale = computed<string>(() => (this.language() === 'tr' ? 'tr-TR' : 'en-US'));

  setLanguage(lang: Language): void {
    this.language.set(lang);
  }

  toggleLanguage(): void {
    this.language.update((cur) => (cur === 'tr' ? 'en' : 'tr'));
  }
}
