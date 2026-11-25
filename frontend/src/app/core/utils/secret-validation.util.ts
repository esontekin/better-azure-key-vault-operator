import { HttpErrorResponse } from '@angular/common/http';
import { ProblemDetail } from '../models/api.models';

export const SECRET_NAME_REGEX = /^[0-9a-zA-Z-]{1,127}$/;
export const MAX_SECRET_VALUE_BYTES = 25_600;
export const MAX_CONTENT_TYPE_LENGTH = 255;

const textEncoder = new TextEncoder();

export function isValidSecretName(name: string): boolean {
  return SECRET_NAME_REGEX.test(name);
}

export function utf8ByteLength(value: string): number {
  return textEncoder.encode(value).length;
}

export function isWithinSecretByteLimit(value: string): boolean {
  return utf8ByteLength(value) <= MAX_SECRET_VALUE_BYTES;
}

export function toUtcIso(dateTimeLocal: string | null | undefined): string | null {
  if (!dateTimeLocal || dateTimeLocal.trim().length === 0) {
    return null;
  }
  const parsed = new Date(dateTimeLocal);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }
  return parsed.toISOString();
}

export function toDateTimeLocalValue(isoString: string | null | undefined): string {
  if (!isoString) {
    return '';
  }
  const parsed = new Date(isoString);
  if (Number.isNaN(parsed.getTime())) {
    return '';
  }
  const pad = (n: number) => String(n).padStart(2, '0');
  const year = parsed.getFullYear();
  const month = pad(parsed.getMonth() + 1);
  const day = pad(parsed.getDate());
  const hours = pad(parsed.getHours());
  const minutes = pad(parsed.getMinutes());
  return `${year}-${month}-${day}T${hours}:${minutes}`;
}

export function formatUtcTimestamp(isoString: string | null | undefined, locale = 'tr-TR'): string {
  if (!isoString) {
    return '—';
  }
  const parsed = new Date(isoString);
  if (Number.isNaN(parsed.getTime())) {
    return '—';
  }
  return new Intl.DateTimeFormat(locale, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZone: 'UTC',
    hour12: false,
  }).format(parsed) + ' UTC';
}

export function isAzureAuthError(problem: ProblemDetail | null | undefined): boolean {
  if (!problem) {
    return false;
  }
  const code = (problem.errorCode ?? '').toUpperCase();
  return problem.status === 401 && code.startsWith('AZURE_');
}

export function isAppAuthError(problem: ProblemDetail | null | undefined): boolean {
  if (!problem) {
    return false;
  }
  return problem.status === 401 && !isAzureAuthError(problem);
}

export function extractProblemDetail(err: unknown): ProblemDetail {
  if (err instanceof HttpErrorResponse) {
    const body = err.error;
    if (body && typeof body === 'object' && 'errorCode' in body && 'detail' in body) {
      const p = body as Partial<ProblemDetail>;
      return {
        type: p.type ?? 'about:blank',
        title: p.title ?? err.statusText ?? 'Error',
        status: p.status ?? err.status,
        detail: p.detail ?? 'Beklenmeyen bir hata oluştu.',
        instance: p.instance,
        errorCode: p.errorCode ?? `HTTP_${err.status}`,
        correlationId: p.correlationId ?? 'n/a',
        retryAfterSeconds: p.retryAfterSeconds ?? null,
        fieldErrors: p.fieldErrors,
      };
    }

    if (err.status === 0) {
      return {
        type: 'about:blank',
        title: 'Network Error',
        status: 0,
        detail: 'Sunucuya ulaşılamadı. Bağlantınızı veya yerel servisin çalıştığını kontrol edin.',
        errorCode: 'NETWORK_UNREACHABLE',
        correlationId: 'client',
      };
    }

    return {
      type: 'about:blank',
      title: err.statusText || 'HTTP Error',
      status: err.status,
      detail: typeof body === 'string' && body.length < 240 ? body : `İstek başarısız oldu (HTTP ${err.status}).`,
      errorCode: `HTTP_${err.status}`,
      correlationId: 'n/a',
    };
  }

  return {
    type: 'about:blank',
    title: 'Unexpected Error',
    status: 500,
    detail: 'İşlem sırasında beklenmeyen bir hata oluştu.',
    errorCode: 'CLIENT_ERROR',
    correlationId: 'client',
  };
}
