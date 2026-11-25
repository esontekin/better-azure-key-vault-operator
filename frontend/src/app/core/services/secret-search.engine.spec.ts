import { describe, expect, it } from 'vitest';
import { SecretMetadataDto } from '../models/api.models';
import {
  DEFAULT_SEARCH_CRITERIA,
  SecretSearchCriteria,
  SecretSearchIndex,
} from './secret-search.engine';

describe('SecretSearchIndex', () => {
  const fixedNow = Date.parse('2026-11-25T12:00:00Z');

  const sampleSecrets: SecretMetadataDto[] = [
    {
      name: 'prod-db-primary-password',
      enabled: true,
      updatedOn: '2026-11-20T10:00:00Z',
      expiresOn: '2026-12-10T10:00:00Z', // expiring within 30d
      contentType: 'text/plain',
      tags: { env: 'prod', service: 'orders', owner: 'platform' },
    },
    {
      name: 'prod-redis-token',
      enabled: true,
      updatedOn: '2026-11-24T10:00:00Z',
      expiresOn: '2027-06-01T00:00:00Z', // active (> 30d)
      contentType: 'application/json',
      tags: { env: 'prod', service: 'cache' },
    },
    {
      name: 'dev-api-key',
      enabled: false,
      updatedOn: '2026-10-01T10:00:00Z',
      expiresOn: '2026-11-01T00:00:00Z', // expired
      contentType: 'text/plain',
      tags: { env: 'dev', team: 'payments' },
    },
    {
      name: 'shared-jwt-signing',
      enabled: true,
      updatedOn: '2026-11-22T10:00:00Z',
      expiresOn: null, // no expiry
      contentType: 'application/x-pem-file',
      tags: { env: 'shared', rotation: 'manual' },
    },
  ];

  const searchWith = (
    index: SecretSearchIndex,
    patch: Partial<SecretSearchCriteria>
  ): SecretMetadataDto[] => index.search({ ...DEFAULT_SEARCH_CRITERIA, ...patch }, fixedNow);

  it('supports case-insensitive contains, prefix, and exact match modes', () => {
    const index = new SecretSearchIndex(sampleSecrets);

    expect(searchWith(index, { query: 'REDIS', matchMode: 'contains' }).map((s) => s.name)).toEqual([
      'prod-redis-token',
    ]);

    expect(searchWith(index, { query: 'PROD-', matchMode: 'prefix' }).map((s) => s.name)).toEqual([
      'prod-db-primary-password',
      'prod-redis-token',
    ]);

    expect(searchWith(index, { query: 'DEV-API-KEY', matchMode: 'exact' }).map((s) => s.name)).toEqual([
      'dev-api-key',
    ]);

    expect(searchWith(index, { query: 'dev-api', matchMode: 'exact' })).toHaveLength(0);
  });

  it('supports multi-word AND search across name, contentType, and tags', () => {
    const index = new SecretSearchIndex(sampleSecrets);

    expect(searchWith(index, { query: 'prod orders' }).map((s) => s.name)).toEqual([
      'prod-db-primary-password',
    ]);

    expect(searchWith(index, { query: 'prod json' }).map((s) => s.name)).toEqual([
      'prod-redis-token',
    ]);

    expect(searchWith(index, { query: 'prod payments' })).toHaveLength(0);
  });

  it('filters by enabled/disabled status and expiration categories', () => {
    const index = new SecretSearchIndex(sampleSecrets);

    expect(searchWith(index, { status: 'disabled' }).map((s) => s.name)).toEqual(['dev-api-key']);
    expect(searchWith(index, { status: 'enabled' })).toHaveLength(3);

    expect(searchWith(index, { expiration: 'expiring_soon' }).map((s) => s.name)).toEqual([
      'prod-db-primary-password',
    ]);
    expect(searchWith(index, { expiration: 'expired' }).map((s) => s.name)).toEqual(['dev-api-key']);
    expect(searchWith(index, { expiration: 'no_expiry' }).map((s) => s.name)).toEqual([
      'shared-jwt-signing',
    ]);
    expect(searchWith(index, { expiration: 'active' }).map((s) => s.name)).toEqual([
      'prod-db-primary-password',
      'prod-redis-token',
      'shared-jwt-signing',
    ]);
  });

  it('filters by tag key or key=value', () => {
    const index = new SecretSearchIndex(sampleSecrets);

    expect(searchWith(index, { tagFilter: 'rotation' }).map((s) => s.name)).toEqual([
      'shared-jwt-signing',
    ]);
    expect(searchWith(index, { tagFilter: 'env=prod' }).map((s) => s.name)).toEqual([
      'prod-db-primary-password',
      'prod-redis-token',
    ]);
    expect(searchWith(index, { tagFilter: 'service=cache' }).map((s) => s.name)).toEqual([
      'prod-redis-token',
    ]);
  });

  it('sorts by name, updatedOn, and expiresOn in asc and desc order', () => {
    const index = new SecretSearchIndex(sampleSecrets);

    expect(
      searchWith(index, { sortBy: 'updatedOn', sortDir: 'desc' }).map((s) => s.name)
    ).toEqual([
      'prod-redis-token',
      'shared-jwt-signing',
      'prod-db-primary-password',
      'dev-api-key',
    ]);

    expect(
      searchWith(index, { sortBy: 'expiresOn', sortDir: 'asc' }).map((s) => s.name)
    ).toEqual([
      'dev-api-key',
      'prod-db-primary-password',
      'prod-redis-token',
      'shared-jwt-signing',
    ]);
  });

  it('searches 10,000 synthetic secrets with p95 latency strictly under 100 ms', () => {
    const synthetic: SecretMetadataDto[] = [];
    const services = ['orders', 'billing', 'identity', 'search', 'gateway', 'ledger'];
    const envs = ['prod', 'staging', 'dev'];

    for (let i = 0; i < 10_000; i++) {
      const svc = services[i % services.length];
      const env = envs[Math.floor(i / services.length) % envs.length];
      const hasExp = i % 4 !== 0;
      const expOffsetDays = (i % 90) - 15;
      const expIso = hasExp
        ? new Date(fixedNow + expOffsetDays * 24 * 60 * 60 * 1000).toISOString()
        : null;

      synthetic.push({
        name: `${env}-${svc}-secret-${String(i).padStart(5, '0')}`,
        enabled: i % 10 !== 0,
        updatedOn: new Date(fixedNow - (i % 365) * 3600_000).toISOString(),
        expiresOn: expIso,
        contentType: i % 3 === 0 ? 'application/json' : 'text/plain',
        tags: { env, service: svc, tier: `t${i % 5}` },
      });
    }

    const index = new SecretSearchIndex(synthetic);
    expect(index.size).toBe(10_000);

    const workloads: SecretSearchCriteria[] = [
      { ...DEFAULT_SEARCH_CRITERIA, query: 'prod billing' },
      { ...DEFAULT_SEARCH_CRITERIA, query: 'prod-', matchMode: 'prefix', status: 'enabled' },
      { ...DEFAULT_SEARCH_CRITERIA, query: 'secret-05432', matchMode: 'contains' },
      { ...DEFAULT_SEARCH_CRITERIA, expiration: 'expiring_soon', sortBy: 'expiresOn', sortDir: 'asc' },
      { ...DEFAULT_SEARCH_CRITERIA, tagFilter: 'service=identity', sortBy: 'updatedOn', sortDir: 'desc' },
      { ...DEFAULT_SEARCH_CRITERIA, query: 'staging gateway t3', status: 'enabled', expiration: 'active' },
    ];

    // Warm-up run
    for (const w of workloads) {
      index.search(w, fixedNow);
    }

    const durationsMs: number[] = [];
    for (let iter = 0; iter < 5; iter++) {
      for (const w of workloads) {
        const start = performance.now();
        const res = index.search(w, fixedNow);
        const elapsed = performance.now() - start;
        expect(res.length).toBeGreaterThan(0);
        durationsMs.push(elapsed);
      }
    }

    durationsMs.sort((a, b) => a - b);
    const p50 = durationsMs[Math.floor(durationsMs.length * 0.5)];
    const p95 = durationsMs[Math.min(durationsMs.length - 1, Math.ceil(durationsMs.length * 0.95) - 1)];

    console.info(
      `[Perf Benchmark] 10,000 secrets client search (${durationsMs.length} runs): p50=${p50.toFixed(2)}ms, p95=${p95.toFixed(2)}ms`
    );

    expect(p95).toBeLessThan(100);
  });
});
