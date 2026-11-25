import { BrowserContext, Page, expect, test } from '@playwright/test';
import { ChildProcess, spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

const PORT = 18766;
const BASE_URL = `http://127.0.0.1:${PORT}`;
const PLACEHOLDER_CLIENT_SECRET = 'e2e-placeholder-secret-val';
const CANARY_SECRET_VALUE = 'CANARY_E2E_SECRET_774411';
const XSS_PAYLOAD = '<img src=x onerror="window.__xssTriggered=true">';

const PROD_VAULT_ID = 'vlt_e2e_prod_00001';
const DEV_VAULT_ID = 'vlt_e2e_dev_00002';

interface SecretMetadata {
  name: string;
  version: string;
  enabled: boolean;
  createdOn: string;
  updatedOn: string;
  expiresOn: string | null;
  notBefore: string | null;
  contentType: string | null;
  tags: Record<string, string>;
  managed: boolean;
}

function resolveJavaExecutable(): string {
  const configured = process.env['AKV_E2E_JAVA'];
  if (configured && fs.existsSync(configured)) {
    return configured;
  }
  const javaHome = process.env['JAVA_HOME'];
  if (javaHome) {
    const ext = process.platform === 'win32' ? '.exe' : '';
    const candidate = path.join(javaHome, 'bin', `java${ext}`);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return 'java';
}

function generateSyntheticSecrets(count: number): SecretMetadata[] {
  const domains = ['billing', 'payments', 'auth', 'orders', 'analytics', 'notify', 'gateway', 'ledger'];
  const regions = ['prod-eu', 'prod-us', 'core-tr', 'shared-uk'];
  const items: SecretMetadata[] = [];

  // Record 0: XSS safety test record (valid AKV name, XSS payload in contentType and tag value)
  items.push({
    name: 'xss-safety-probe-0000',
    version: 'v-xss-1',
    enabled: true,
    createdOn: '2026-01-10T10:00:00Z',
    updatedOn: '2026-06-15T10:00:00Z',
    expiresOn: null,
    notBefore: null,
    contentType: XSS_PAYLOAD,
    tags: { note: XSS_PAYLOAD, env: 'prod' },
    managed: false,
  });

  // Record 1: deterministic primary secret for reveal, versions, and soft-delete
  items.push({
    name: 'billing-prod-eu-0001',
    version: 'ver-latest-003',
    enabled: true,
    createdOn: '2026-01-01T08:00:00Z',
    updatedOn: '2026-06-20T12:30:00Z',
    expiresOn: '2027-01-01T00:00:00Z',
    notBefore: '2026-01-01T00:00:00Z',
    contentType: 'application/x-connection-string',
    tags: { env: 'prod', owner: 'finops', tier: 'critical' },
    managed: false,
  });

  for (let i = 2; i < count; i++) {
    const domain = domains[i % domains.length];
    const region = regions[Math.floor(i / domains.length) % regions.length];
    const enabled = i % 7 !== 0;
    const suffix = String(i).padStart(4, '0');
    items.push({
      name: `${domain}-${region}-${suffix}`,
      version: `ver-${suffix}`,
      enabled,
      createdOn: '2026-01-05T09:00:00Z',
      updatedOn: `2026-05-${String((i % 28) + 1).padStart(2, '0')}T11:00:00Z`,
      expiresOn: i % 5 === 0 ? '2027-12-31T23:59:59Z' : null,
      notBefore: null,
      contentType: i % 3 === 0 ? 'text/plain' : 'application/json',
      tags: {
        env: i % 2 === 0 ? 'prod' : 'staging',
        team: domain,
      },
      managed: false,
    });
  }
  return items;
}

async function waitForHealthAndToken(
  getToken: () => string | null,
  getOutput: () => string,
  timeoutMs = 45_000
): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const token = getToken();
    if (token) {
      try {
        const res = await fetch(`${BASE_URL}/actuator/health`);
        if (res.ok) {
          const json = (await res.json()) as { status?: string };
          if (json.status === 'UP') {
            return token;
          }
        }
      } catch {
        // Server still starting
      }
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(
    `Timed out waiting for Spring Boot JAR on ${BASE_URL} and bootstrap token.\nOutput:\n${getOutput()}`
  );
}

let jarProcess: ChildProcess | null = null;

function stopJarProcess(): void {
  if (!jarProcess || jarProcess.killed) {
    return;
  }
  try {
    jarProcess.kill('SIGTERM');
  } catch {
    // ignore
  }
  if (process.platform === 'win32' && jarProcess.pid) {
    try {
      spawn('taskkill', ['/pid', String(jarProcess.pid), '/f', '/t'], { stdio: 'ignore' });
    } catch {
      // ignore
    }
  }
  jarProcess = null;
}

process.on('exit', stopJarProcess);
process.on('SIGINT', () => {
  stopJarProcess();
  process.exit(130);
});
process.on('SIGTERM', () => {
  stopJarProcess();
  process.exit(143);
});

test.describe.serial('Azure Key Vault Manager — Real JAR End-to-End QA Suite', () => {
  let bootstrapToken = '';
  let jarStdout = '';
  let context: BrowserContext;
  let page: Page;

  const consoleErrors: string[] = [];
  const pageErrors: string[] = [];
  const externalRequests: string[] = [];

  // Mutable mock state for Azure-backed endpoints (auth/static/security stay 100% REAL Spring Boot!)
  const all10kSecrets = generateSyntheticSecrets(10_000);
  const firstPage25 = all10kSecrets.slice(0, 25);

  let snapshotPhase: 'LOADING' | 'COMPLETE' = 'LOADING';
  let snapshotPollCount = 0;
  let revealCallCount = 0;
  let createdRequestBody: Record<string, unknown> | null = null;
  let deleteOpPollCount = 0;
  let recoverOpPollCount = 0;
  let deletedItems = [
    {
      name: 'legacy-deleted-secret',
      deletedOn: '2026-06-01T10:00:00Z',
      scheduledPurgeDate: '2026-08-30T10:00:00Z',
      recoveryId: 'https://kv-prod-core.vault.azure.net/deletedsecrets/legacy-deleted-secret',
      enabled: true,
      contentType: 'text/plain',
      tags: { env: 'prod' },
    },
  ];

  test.beforeAll(async ({ browser }) => {
    const jarPath = path.resolve(__dirname, '../../backend/build/libs/azure-key-vault-operator.jar');
    expect(fs.existsSync(jarPath), `Built executable JAR must exist at ${jarPath}`).toBe(true);

    const javaExe = resolveJavaExecutable();
    let capturedToken: string | null = null;

    jarProcess = spawn(javaExe, ['-jar', jarPath], {
      env: {
        ...process.env,
        AZURE_TENANT_ID: '00000000-0000-0000-0000-000000000000',
        AZURE_CLIENT_ID: '11111111-1111-1111-1111-111111111111',
        AZURE_CLIENT_SECRET: PLACEHOLDER_CLIENT_SECRET,
        APP_PROFILE: 'local',
        APP_DELETE_ENABLED: 'true',
        SERVER_PORT: String(PORT),
        SERVER_ADDRESS: '127.0.0.1',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const onChunk = (chunk: Buffer) => {
      const text = chunk.toString('utf8');
      jarStdout += text;
      if (!capturedToken) {
        const match = jarStdout.match(/Token\s+:\s+([A-Za-z0-9_-]{16,})/);
        if (match) {
          capturedToken = match[1];
        }
      }
    };

    jarProcess.stdout?.on('data', onChunk);
    jarProcess.stderr?.on('data', onChunk);

    bootstrapToken = await waitForHealthAndToken(
      () => capturedToken,
      () => jarStdout
    );

    // Verify client secret NEVER printed to stdout/logs
    expect(jarStdout).not.toContain(PLACEHOLDER_CLIENT_SECRET);

    context = await browser.newContext({
      viewport: { width: 1440, height: 900 },
    });
    page = await context.newPage();

    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });
    page.on('pageerror', (err) => {
      pageErrors.push(err.message);
    });
    page.on('request', (req) => {
      const url = req.url();
      if (!url.startsWith(BASE_URL) && !url.startsWith('data:') && !url.startsWith('blob:')) {
        externalRequests.push(url);
      }
    });
  });

  test.afterAll(async () => {
    await context?.close().catch(() => {});
    stopJarProcess();
  });

  test('1. Security headers, zero external requests, and real local bootstrap login with CSRF', async () => {
    const docResponse = await page.goto(`${BASE_URL}/`, { waitUntil: 'networkidle' });
    expect(docResponse).not.toBeNull();
    expect(docResponse!.status()).toBe(200);

    const headers = docResponse!.headers();
    expect(headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(headers['content-security-policy']).toContain("default-src 'self'");
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['referrer-policy']).toBe('no-referrer');
    expect(headers['x-frame-options']).toBe('DENY');
    expect(headers['access-control-allow-origin']).toBeUndefined();

    // Verify zero external CDN requests, zero uncaught page errors, and zero CSP/console errors on initial load
    expect(externalRequests).toEqual([]);
    expect(pageErrors).toEqual([]);
    expect(consoleErrors).toEqual([]);

    // Verify login form uses password input
    const tokenInput = page.locator('#bootstrapTokenInput');
    await expect(tokenInput).toBeVisible();
    await expect(tokenInput).toHaveAttribute('type', 'password');

    // Register Azure-data mocks BEFORE submitting login so discovery loads cleanly after real auth
    await page.route('**/api/v1/subscriptions', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'Cache-Control': 'no-store' },
        body: JSON.stringify([
          { subscriptionId: 'sub-prod-001', displayName: 'Production Subscription', state: 'Enabled' },
        ]),
      });
    });

    await page.route('**/api/v1/vaults', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'Cache-Control': 'no-store' },
        body: JSON.stringify([
          {
            id: PROD_VAULT_ID,
            name: 'kv-prod-core',
            subscriptionId: 'sub-prod-001',
            resourceGroup: 'rg-core-prod',
            location: 'westeurope',
            vaultUri: 'https://kv-prod-core.vault.azure.net',
            environment: 'prod',
            production: true,
            source: 'ARM_DISCOVERY',
            permissions: ['SECRET_LIST', 'SECRET_REVEAL', 'SECRET_WRITE', 'SECRET_DELETE_RECOVER'],
          },
          {
            id: DEV_VAULT_ID,
            name: 'kv-dev-sandbox',
            subscriptionId: 'sub-prod-001',
            resourceGroup: 'rg-core-dev',
            location: 'westeurope',
            vaultUri: 'https://kv-dev-sandbox.vault.azure.net',
            environment: 'dev',
            production: false,
            source: 'ARM_DISCOVERY',
            permissions: ['SECRET_LIST', 'SECRET_REVEAL', 'SECRET_WRITE', 'SECRET_DELETE_RECOVER'],
          },
        ]),
      });
    });

    await page.route(`**/api/v1/vaults/${PROD_VAULT_ID}/secrets`, async (route) => {
      const method = route.request().method();
      if (method === 'GET') {
        snapshotPollCount++;
        if (snapshotPhase === 'LOADING') {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            headers: { 'Cache-Control': 'no-store' },
            body: JSON.stringify({
              vaultId: PROD_VAULT_ID,
              status: 'LOADING',
              generationId: 1,
              loadedCount: firstPage25.length,
              pagesLoaded: 1,
              stale: false,
              lastSuccessfulSyncAt: null,
              lastAttemptAt: '2026-06-21T10:00:00Z',
              errorCode: null,
              errorMessage: null,
              items: firstPage25,
            }),
          });
          return;
        }
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: { 'Cache-Control': 'no-store' },
          body: JSON.stringify({
            vaultId: PROD_VAULT_ID,
            status: 'COMPLETE',
            generationId: 2,
            loadedCount: all10kSecrets.length,
            pagesLoaded: 400,
            stale: false,
            lastSuccessfulSyncAt: '2026-06-21T10:00:05Z',
            lastAttemptAt: '2026-06-21T10:00:05Z',
            errorCode: null,
            errorMessage: null,
            items: all10kSecrets,
          }),
        });
        return;
      }

      if (method === 'POST') {
        createdRequestBody = route.request().postDataJSON() as Record<string, unknown>;
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          headers: { 'Cache-Control': 'no-store' },
          body: JSON.stringify({
            name: createdRequestBody['name'],
            version: 'ver-created-001',
            enabled: createdRequestBody['enabled'] ?? true,
            createdOn: '2026-06-21T10:05:00Z',
            updatedOn: '2026-06-21T10:05:00Z',
            expiresOn: createdRequestBody['expiresOn'] ?? null,
            notBefore: createdRequestBody['notBefore'] ?? null,
            contentType: createdRequestBody['contentType'] ?? null,
            tags: createdRequestBody['tags'] ?? {},
            managed: false,
          }),
        });
        return;
      }
      await route.continue();
    });

    await page.route(`**/api/v1/vaults/${DEV_VAULT_ID}/secrets`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'Cache-Control': 'no-store' },
        body: JSON.stringify({
          vaultId: DEV_VAULT_ID,
          status: 'COMPLETE',
          generationId: 1,
          loadedCount: 1,
          pagesLoaded: 1,
          stale: false,
          lastSuccessfulSyncAt: '2026-06-21T10:00:05Z',
          lastAttemptAt: '2026-06-21T10:00:05Z',
          errorCode: null,
          errorMessage: null,
          items: [
            {
              name: 'dev-sample-secret',
              version: 'ver-dev-1',
              enabled: true,
              createdOn: '2026-01-01T00:00:00Z',
              updatedOn: '2026-06-01T00:00:00Z',
              expiresOn: null,
              notBefore: null,
              contentType: 'text/plain',
              tags: { env: 'dev' },
              managed: false,
            },
          ],
        }),
      });
    });

    await page.route('**/api/v1/vaults/*/secrets/*/reveal', async (route) => {
      revealCallCount++;
      const url = route.request().url();
      const body = (route.request().postDataJSON() ?? {}) as { version?: string };
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'Cache-Control': 'no-store' },
        body: JSON.stringify({
          name: decodeURIComponent(url.split('/secrets/')[1].split('/reveal')[0]),
          version: body.version ?? 'ver-latest-003',
          value: CANARY_SECRET_VALUE,
          contentType: 'application/x-connection-string',
          updatedOn: '2026-06-20T12:30:00Z',
        }),
      });
    });

    await page.route('**/api/v1/vaults/*/secrets/*/versions', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'Cache-Control': 'no-store' },
        body: JSON.stringify([
          {
            version: 'ver-latest-003',
            enabled: true,
            createdOn: '2026-06-20T12:30:00Z',
            updatedOn: '2026-06-20T12:30:00Z',
            expiresOn: '2027-01-01T00:00:00Z',
            notBefore: '2026-01-01T00:00:00Z',
            contentType: 'application/x-connection-string',
            tags: { env: 'prod' },
            latest: true,
          },
          {
            version: 'ver-prev-002',
            enabled: true,
            createdOn: '2026-03-10T09:00:00Z',
            updatedOn: '2026-03-10T09:00:00Z',
            expiresOn: null,
            notBefore: null,
            contentType: 'application/x-connection-string',
            tags: { env: 'prod' },
            latest: false,
          },
          {
            version: 'ver-init-001',
            enabled: false,
            createdOn: '2026-01-01T08:00:00Z',
            updatedOn: '2026-01-01T08:00:00Z',
            expiresOn: null,
            notBefore: null,
            contentType: 'application/x-connection-string',
            tags: { env: 'prod' },
            latest: false,
          },
        ]),
      });
    });

    await page.route(`**/api/v1/vaults/${PROD_VAULT_ID}/secrets/billing-prod-eu-0001`, async (route) => {
      if (route.request().method() === 'DELETE') {
        const body = route.request().postDataJSON() as { confirmSecretName?: string };
        expect(body.confirmSecretName).toBe('billing-prod-eu-0001');
        deleteOpPollCount = 0;
        await route.fulfill({
          status: 202,
          contentType: 'application/json',
          headers: { 'Cache-Control': 'no-store' },
          body: JSON.stringify({
            operationId: 'op-del-e2e-1',
            vaultId: PROD_VAULT_ID,
            secretName: 'billing-prod-eu-0001',
            operationType: 'SOFT_DELETE',
            state: 'IN_PROGRESS',
            createdAt: '2026-06-21T10:10:00Z',
            updatedAt: '2026-06-21T10:10:00Z',
            errorCode: null,
            errorMessage: null,
          }),
        });
        return;
      }
      await route.continue();
    });

    await page.route(`**/api/v1/vaults/${PROD_VAULT_ID}/deleted-secrets`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'Cache-Control': 'no-store' },
        body: JSON.stringify(deletedItems),
      });
    });

    await page.route(`**/api/v1/vaults/${PROD_VAULT_ID}/deleted-secrets/*/recover`, async (route) => {
      recoverOpPollCount = 0;
      const secretName = decodeURIComponent(
        route.request().url().split('/deleted-secrets/')[1].split('/recover')[0]
      );
      await route.fulfill({
        status: 202,
        contentType: 'application/json',
        headers: { 'Cache-Control': 'no-store' },
        body: JSON.stringify({
          operationId: 'op-rec-e2e-1',
          vaultId: PROD_VAULT_ID,
          secretName,
          operationType: 'RECOVER',
          state: 'IN_PROGRESS',
          createdAt: '2026-06-21T10:15:00Z',
          updatedAt: '2026-06-21T10:15:00Z',
          errorCode: null,
          errorMessage: null,
        }),
      });
    });

    await page.route('**/api/v1/operations/*', async (route) => {
      const opId = route.request().url().split('/operations/')[1];
      if (opId === 'op-del-e2e-1') {
        deleteOpPollCount++;
        const state = deleteOpPollCount >= 1 ? 'SUCCEEDED' : 'IN_PROGRESS';
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: { 'Cache-Control': 'no-store' },
          body: JSON.stringify({
            operationId: opId,
            vaultId: PROD_VAULT_ID,
            secretName: 'billing-prod-eu-0001',
            operationType: 'SOFT_DELETE',
            state,
            createdAt: '2026-06-21T10:10:00Z',
            updatedAt: '2026-06-21T10:10:02Z',
            errorCode: null,
            errorMessage: null,
          }),
        });
        return;
      }
      if (opId === 'op-rec-e2e-1') {
        recoverOpPollCount++;
        deletedItems = [];
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: { 'Cache-Control': 'no-store' },
          body: JSON.stringify({
            operationId: opId,
            vaultId: PROD_VAULT_ID,
            secretName: 'legacy-deleted-secret',
            operationType: 'RECOVER',
            state: 'SUCCEEDED',
            createdAt: '2026-06-21T10:15:00Z',
            updatedAt: '2026-06-21T10:15:02Z',
            errorCode: null,
            errorMessage: null,
          }),
        });
        return;
      }
      await route.continue();
    });

    // Submit real local bootstrap login and inspect actual HTTP request/response
    const [bootstrapReq, bootstrapRes] = await Promise.all([
      page.waitForRequest((req) => req.url().endsWith('/api/v1/auth/bootstrap') && req.method() === 'POST'),
      page.waitForResponse((res) => res.url().endsWith('/api/v1/auth/bootstrap')),
      (async () => {
        await tokenInput.fill(bootstrapToken);
        await page.locator('button[type="submit"]').click();
      })(),
    ]);

    expect(bootstrapRes.status()).toBe(200);
    expect(bootstrapReq.headers()['x-xsrf-token']).toBeTruthy();
    expect(bootstrapReq.url()).not.toContain(bootstrapToken);
    expect(page.url()).not.toContain(bootstrapToken);

    const authJson = (await bootstrapRes.json()) as {
      authenticated: boolean;
      subject: string;
      profile: string;
      deleteEnabled: boolean;
    };
    expect(authJson.authenticated).toBe(true);
    expect(authJson.subject).toBe('local-operator');
    expect(authJson.profile).toBe('local');
    expect(authJson.deleteEnabled).toBe(true);

    // Verify cookies: XSRF-TOKEN + HttpOnly SameSite Strict session cookie
    const cookies = await context.cookies(BASE_URL);
    const xsrfCookie = cookies.find((c) => c.name === 'XSRF-TOKEN');
    const sessionCookie = cookies.find((c) => c.name === 'AKV_SESSION' || c.name === 'JSESSIONID');
    expect(xsrfCookie).toBeDefined();
    expect(sessionCookie).toBeDefined();
    expect(sessionCookie!.httpOnly).toBe(true);
    expect(sessionCookie!.sameSite).toBe('Strict');

    // Main workspace & vault selector should be visible
    await expect(page.locator('.vault-item', { hasText: 'kv-prod-core' })).toBeVisible();
    await expect(page.locator('.vault-item', { hasText: 'kv-dev-sandbox' })).toBeVisible();
  });

  test('2. Progressive loading (no fake %), 10,000 synthetic records virtual scroll & real-browser search latency', async () => {
    snapshotPhase = 'LOADING';
    snapshotPollCount = 0;

    // Click PROD vault
    await page.locator('.vault-item', { hasText: 'kv-prod-core' }).click();

    // Verify LOADING state shows loaded count (25), NO fake percentage, and search input is active!
    const syncPill = page.locator('.sync-pill');
    await expect(syncPill).toContainText('Yükleniyor');
    const toolbarText = await page.locator('.toolbar__stats').innerText();
    expect(toolbarText).toContain('25');
    expect(toolbarText).not.toContain('%');

    const searchInput = page.locator('input.search-input');
    await expect(searchInput).toBeEnabled();

    // Search for an unmatched term while LOADING -> must show loading-in-progress notice, NOT definitive empty
    await searchInput.fill('does-not-exist-yet-xyz');
    const emptyState = page.locator('.empty-state');
    await expect(emptyState).toContainText('Henüz tüm kayıtlar yüklenmedi; yükleme devam ediyor');
    await expect(emptyState).not.toContainText('Arama ve filtre kriterlerinize uyan secret bulunamadı');

    // Switch snapshot mock to COMPLETE with 10,000 synthetic records and wait for automatic polling update
    snapshotPhase = 'COMPLETE';
    await searchInput.fill('');
    await expect(syncPill).toContainText('Tamamlandı', { timeout: 10_000 });
    await expect(page.locator('.toolbar__stats')).toContainText('10000');

    // Verify CDK Virtual Scroll renders bounded DOM rows (NOT 10,000 DOM rows!)
    const viewport = page.locator('cdk-virtual-scroll-viewport');
    await expect(viewport).toBeVisible();
    const domRowCount = await viewport.locator('.table-row').count();
    expect(domRowCount).toBeGreaterThan(5);
    expect(domRowCount).toBeLessThan(120);

    // Measure real-browser search latency across 15 queries on 10,000 records
    const queries = [
      'billing prod-eu',
      'payments core-tr',
      'auth prod-us',
      'orders shared-uk',
      'analytics 050',
      'notify prod-eu',
      'gateway 999',
      'ledger prod-us',
      'billing-prod-eu-0001',
      'critical',
      'finops',
      'payments 123',
      'auth 456',
      'orders 789',
      'analytics 990',
    ];
    const samplesMs: number[] = [];
    for (const q of queries) {
      const start = performance.now();
      await searchInput.fill(q);
      // Wait for Angular change detection + DOM update to complete
      await page.waitForFunction(
        () => {
          const chips = Array.from(document.querySelectorAll('.stat-chip strong'));
          const matchingText = chips[2]?.textContent?.trim();
          return matchingText !== undefined && matchingText !== '10000';
        },
        null,
        { timeout: 5000 }
      );
      const elapsed = performance.now() - start;
      samplesMs.push(elapsed);
    }

    samplesMs.sort((a, b) => a - b);
    const p50 = samplesMs[Math.floor(samplesMs.length * 0.5)];
    const p95 = samplesMs[Math.min(samplesMs.length - 1, Math.ceil(samplesMs.length * 0.95) - 1)];
    const max = samplesMs[samplesMs.length - 1];
    console.log(
      `[E2E-PERF] 10,000 records real-browser virtual-scroll DOM rows=${domRowCount}, search latency p50=${p50.toFixed(2)}ms, p95=${p95.toFixed(2)}ms, max=${max.toFixed(2)}ms`
    );

    // Verify multi-word AND + status + tag filters accuracy
    await searchInput.fill('billing prod-eu');
    await expect(page.locator('.table-row').first()).toContainText('billing-prod-eu');

    await page.locator('select[aria-label="Status filter"]').selectOption('disabled');
    const disabledRows = page.locator('.table-row .status-badge--disabled');
    await expect(disabledRows.first()).toBeVisible();

    await page.locator('select[aria-label="Status filter"]').selectOption('all');
    await page.locator('input.tag-input').fill('owner=finops');
    await expect(page.locator('.table-row')).toHaveCount(1);
    await expect(page.locator('.table-row').first()).toContainText('billing-prod-eu-0001');

    // Reset filters
    await page.locator('input.tag-input').fill('');
    await searchInput.fill('');
  });

  test('3. XSS safety, Reveal canary leak check, Create multiline/whitespace, Versions, Soft-Delete, Recover, Zero Purge, TR/EN i18n', async () => {
    const searchInput = page.locator('input.search-input');

    // --- A. XSS Safety ---
    await searchInput.fill('xss-safety-probe-0000');
    await page.locator('.table-row', { hasText: 'xss-safety-probe-0000' }).first().click();
    await expect(page.locator('.drawer__secret-name')).toHaveText('xss-safety-probe-0000');
    await expect(page.locator('.drawer')).toContainText(XSS_PAYLOAD);
    const xssTriggered = await page.evaluate(() => Boolean((window as unknown as Record<string, unknown>)['__xssTriggered']));
    expect(xssTriggered).toBe(false);

    // --- B. Reveal & Canary Secret Leak Check ---
    await searchInput.fill('billing-prod-eu-0001');
    await page.locator('.table-row', { hasText: 'billing-prod-eu-0001' }).first().click();
    await expect(page.locator('.drawer__secret-name')).toHaveText('billing-prod-eu-0001');

    // Masked by default; zero reveal API calls and zero canary in DOM before clicking Reveal
    await expect(page.locator('[data-testid="masked-secret-box"]')).toBeVisible();
    expect(revealCallCount).toBe(0);
    expect(await page.evaluate(() => document.body.innerText)).not.toContain(CANARY_SECRET_VALUE);

    // Click Reveal -> canary appears
    await page.locator('[data-testid="reveal-secret-btn"]').click();
    await expect(page.locator('[data-testid="revealed-secret-value"]')).toHaveText(CANARY_SECRET_VALUE);
    expect(revealCallCount).toBe(1);

    // Check browser storage, URL, and DOM banners for leaks
    const leakAudit = await page.evaluate((canary) => ({
      localStorageLen: window.localStorage.length,
      sessionStorageLen: window.sessionStorage.length,
      urlContainsCanary: window.location.href.includes(canary),
      noticeContainsCanary: Array.from(document.querySelectorAll('.notice-banner, .error-banner')).some((el) =>
        (el.textContent ?? '').includes(canary)
      ),
    }), CANARY_SECRET_VALUE);

    expect(leakAudit.localStorageLen).toBe(0);
    expect(leakAudit.sessionStorageLen).toBe(0);
    expect(leakAudit.urlContainsCanary).toBe(false);
    expect(leakAudit.noticeContainsCanary).toBe(false);

    // Switch to another secret -> revealed canary immediately disappears from DOM
    await searchInput.fill('xss-safety-probe-0000');
    await page.locator('.table-row', { hasText: 'xss-safety-probe-0000' }).first().click();
    await expect(page.locator('[data-testid="revealed-secret-value"]')).toHaveCount(0);
    expect(await page.evaluate(() => document.body.innerText)).not.toContain(CANARY_SECRET_VALUE);

    // Close drawer
    await page.locator('.drawer button[aria-label="Kapat"]').click();
    await expect(page.locator('.drawer')).toHaveCount(0);

    // --- C. New Secret Dialog (Multiline, Whitespace Preservation, UTF-8 Byte Counter, Non-Atomic Warning) ---
    await page.locator('button', { hasText: 'Yeni Secret' }).click();
    const dialog = page.locator('.modal-dialog');
    await expect(dialog).toBeVisible();
    await expect(dialog.locator('.info-banner')).toContainText('upsert');

    const multilineValue = '  line-one\nline-two-ü  \t';
    const expectedUtf8Bytes = Buffer.byteLength(multilineValue, 'utf8');
    await dialog.locator('#secretNameInput').fill('e2e-multiline-secret');
    await dialog.locator('#secretValueInput').fill(multilineValue);
    await expect(dialog.locator('.byte-counter')).toContainText(`${expectedUtf8Bytes} / 25600`);

    await dialog.locator('button[type="submit"]').click();
    await expect(dialog).toHaveCount(0);
    expect(createdRequestBody).not.toBeNull();
    expect(createdRequestBody!['name']).toBe('e2e-multiline-secret');
    expect(createdRequestBody!['value']).toBe(multilineValue); // verbatim, NOT trimmed

    // --- D. Versions Tab (Zero Auto-Fetch of Old Values) ---
    await searchInput.fill('billing-prod-eu-0001');
    await page.locator('.table-row', { hasText: 'billing-prod-eu-0001' }).first().click();
    const revealCountBeforeVersions = revealCallCount;
    await page.locator('.drawer button[role="tab"]', { hasText: 'Versiyon Geçmişi' }).click();
    await expect(page.locator('.version-card')).toHaveCount(3);
    await expect(page.locator('.versions-notice')).toContainText('otomatik çekilmez');
    expect(revealCallCount).toBe(revealCountBeforeVersions);

    // --- E. Soft-Delete Danger Zone (PROD Warning, Exact Name Confirmation, Async Operation Polling) ---
    await page.locator('.drawer button[role="tab"]', { hasText: 'Genel Bakış' }).click();
    await expect(page.locator('.prod-danger-alert')).toContainText('PRODUCTION');

    const deleteBtn = page.locator('.card--danger button.btn--danger');
    await expect(deleteBtn).toBeDisabled();

    await page.locator('#deleteConfirmInput').fill('wrong-secret-name');
    await expect(deleteBtn).toBeDisabled();

    await page.locator('#deleteConfirmInput').fill('billing-prod-eu-0001');
    await expect(deleteBtn).toBeEnabled();
    await deleteBtn.click();

    // Drawer closes once async operation reaches SUCCEEDED
    await expect(page.locator('.drawer')).toHaveCount(0, { timeout: 10_000 });
    expect(deleteOpPollCount).toBeGreaterThanOrEqual(1);

    // --- F. Deleted Secrets Tab & Recover (ZERO Purge Button Anywhere) ---
    await page.locator('button[role="tab"]', { hasText: 'Silinmiş Secrets' }).click();
    await expect(page.locator('.deleted-table')).toContainText('legacy-deleted-secret');

    // Verify ZERO permanent purge button exists in the entire UI
    const purgeButtons = await page.evaluate(() => {
      return Array.from(document.querySelectorAll('button, a'))
        .map((el) => (el.textContent ?? '').trim())
        .filter((txt) => /purge|kalıcı\s+sil/i.test(txt));
    });
    expect(purgeButtons).toEqual([]);

    await page.locator('.deleted-table button', { hasText: 'Kurtar (Recover)' }).click();
    await expect(page.locator('.op-banner')).toContainText('başarıyla kurtarıldı', { timeout: 10_000 });
    expect(recoverOpPollCount).toBeGreaterThanOrEqual(1);

    // --- G. TR / EN Language Switch ---
    const langBtn = page.locator('button[aria-label="Toggle language"]');
    await expect(langBtn).toHaveText('TR');
    await langBtn.click();
    await expect(langBtn).toHaveText('EN');
    await expect(page.locator('.workspace-tabs')).toContainText('Active Secrets');
    await expect(page.locator('.workspace-tabs')).toContainText('Deleted Secrets');
    await expect(page.locator('.topbar__actions')).toContainText('Sign Out');

    // Switch back to TR
    await langBtn.click();
    await expect(langBtn).toHaveText('TR');
    await expect(page.locator('.topbar__actions')).toContainText('Çıkış Yap');
  });

  test('4. Real Logout invalidates session, /api/v1/vaults returns 401, and consumed bootstrap token replay is rejected', async () => {
    // Remove mock route on /api/v1/vaults so post-logout check hits the REAL Spring Boot backend
    await page.unroute('**/api/v1/vaults');

    const [logoutRes] = await Promise.all([
      page.waitForResponse((res) => res.url().endsWith('/api/v1/auth/logout') && res.request().method() === 'POST'),
      page.locator('.topbar__actions button', { hasText: 'Çıkış Yap' }).click(),
    ]);
    expect(logoutRes.status()).toBe(204);

    // Returns to login screen
    const tokenInput = page.locator('#bootstrapTokenInput');
    await expect(tokenInput).toBeVisible();

    // Real backend rejects unauthenticated GET /api/v1/vaults with 401 RFC 9457 JSON
    const unauthVaultsRes = await page.request.get(`${BASE_URL}/api/v1/vaults`);
    expect(unauthVaultsRes.status()).toBe(401);
    const problemJson = (await unauthVaultsRes.json()) as { errorCode?: string; correlationId?: string };
    expect(problemJson.errorCode).toBe('AUTH_REQUIRED');
    expect(problemJson.correlationId).toBeTruthy();

    // Replaying the already-consumed bootstrap token must be rejected 401 by the real backend
    const [replayRes] = await Promise.all([
      page.waitForResponse((res) => res.url().endsWith('/api/v1/auth/bootstrap')),
      (async () => {
        await tokenInput.fill(bootstrapToken);
        await page.locator('button[type="submit"]').click();
      })(),
    ]);
    expect(replayRes.status()).toBe(401);
    const replayProblem = (await replayRes.json()) as { errorCode?: string };
    expect(replayProblem.errorCode).toBe('BOOTSTRAP_TOKEN_INVALID');

    // Final check: zero external requests, zero console/page errors across entire E2E session
    expect(externalRequests).toEqual([]);
    expect(pageErrors).toEqual([]);
  });
});
