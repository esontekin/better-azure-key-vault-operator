import { describe, expect, it } from 'vitest';
import {
  MAX_SECRET_VALUE_BYTES,
  isAppAuthError,
  isAzureAuthError,
  isValidSecretName,
  isWithinSecretByteLimit,
  utf8ByteLength,
} from './secret-validation.util';

describe('secret-validation utilities', () => {
  it('validates Azure Key Vault secret name rules (1-127 alphanumeric or hyphen)', () => {
    expect(isValidSecretName('db-password-01')).toBe(true);
    expect(isValidSecretName('A')).toBe(true);
    expect(isValidSecretName('a'.repeat(127))).toBe(true);

    expect(isValidSecretName('')).toBe(false);
    expect(isValidSecretName('a'.repeat(128))).toBe(false);
    expect(isValidSecretName('db_password')).toBe(false);
    expect(isValidSecretName('db password')).toBe(false);
    expect(isValidSecretName('db.password')).toBe(false);
  });

  it('counts UTF-8 byte length accurately including multi-byte characters and preserves whitespace', () => {
    expect(utf8ByteLength('  abc\n')).toBe(6);
    // 'ğ' is 2 bytes in UTF-8, '🔐' is 4 bytes in UTF-8
    expect(utf8ByteLength('ğ')).toBe(2);
    expect(utf8ByteLength('🔐')).toBe(4);

    expect(isWithinSecretByteLimit('a'.repeat(MAX_SECRET_VALUE_BYTES))).toBe(true);
    expect(isWithinSecretByteLimit('a'.repeat(MAX_SECRET_VALUE_BYTES + 1))).toBe(false);
    expect(isWithinSecretByteLimit('ğ'.repeat(MAX_SECRET_VALUE_BYTES / 2 + 1))).toBe(false);
  });

  it('distinguishes Azure service principal 401 from application authentication 401', () => {
    const azure401 = {
      type: 'about:blank',
      title: 'Azure Auth Failed',
      status: 401,
      detail: 'Azure credential expired',
      errorCode: 'AZURE_AUTH_FAILED',
      correlationId: 'cid-1',
    };
    const app401 = {
      type: 'about:blank',
      title: 'Unauthorized',
      status: 401,
      detail: 'Session expired',
      errorCode: 'APP_UNAUTHORIZED',
      correlationId: 'cid-2',
    };

    expect(isAzureAuthError(azure401)).toBe(true);
    expect(isAppAuthError(azure401)).toBe(false);

    expect(isAzureAuthError(app401)).toBe(false);
    expect(isAppAuthError(app401)).toBe(true);
  });
});
