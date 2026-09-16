import { createHash } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { chromium, type Browser } from 'playwright';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { config } from '../src/config.js';
import { signConsentRequest } from '../src/auth/jwt.js';
import { startTestServer, type TestServer } from './helpers.js';

const RUN = process.env.RUN_E2E === '1' || process.env.RUN_E2E === 'true';

describe.skipIf(!RUN)('e2e: consent browser security', () => {
  let browser: Browser;
  let server: TestServer;
  let callbackServer: Server;
  let callback: string;
  const originalIssuer = config.issuerUrl;
  const callbackRequests: Array<{ url: string; method: string; body: string; referer?: string }> = [];
  beforeAll(async () => {
    server = await startTestServer();
    // Exercise the actual browser Origin header against an actual HTTP server.
    // The different loopback callback port is a separate origin, not a mock 302.
    config.issuerUrl = new URL(server.base);
    callbackServer = createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => { body += String(chunk); });
      req.on('end', () => {
        if (req.url?.startsWith('/callback?')) {
          callbackRequests.push({ url: new URL(req.url, callback).href, method: req.method!, body, referer: req.headers.referer });
        }
        res.setHeader('content-type', 'text/html');
        res.end('<h1>Callback received</h1>');
      });
    });
    await new Promise<void>((resolve) => callbackServer.listen(0, '127.0.0.1', resolve));
    const address = callbackServer.address();
    if (!address || typeof address === 'string') throw new Error('Callback fixture did not bind TCP');
    callback = `http://127.0.0.1:${address.port}/callback`;
    browser = await chromium.launch({
      headless: true,
      chromiumSandbox: false, // isolated test container, not a production default
      // Allow only our loopback fixtures. Any background/external traffic fails.
      proxy: { server: 'http://127.0.0.1:9', bypass: '127.0.0.1' },
      args: ['--disable-dev-shm-usage', '--disable-background-networking', '--disable-quic'],
    });
  });
  afterAll(async () => {
    config.issuerUrl = originalIssuer;
    await browser?.close();
    await server?.close();
    if (callbackServer) await new Promise<void>((resolve) => callbackServer.close(() => resolve()));
  });

  it('follows the approved cross-origin callback without sending login credentials or referrer', async () => {
    const token = await signConsentRequest({
      clientId: 'browser-consent-test', redirectUri: callback,
      codeChallenge: createHash('sha256').update('browser-test-verifier'.repeat(3)).digest('base64url'),
      scopes: ['mcp:fetch'], state: 'browser-roundtrip',
    });
    const context = await browser.newContext();
    try {
      const page = await context.newPage();
      await page.goto(`${server.base}/consent?req=${encodeURIComponent(token)}`);
      await page.locator('[name=username]').fill(config.AUTH_USERNAME);
      await page.locator('[name=password]').fill(config.AUTH_PASSWORD);
      await Promise.all([
        page.waitForURL((url) => url.origin === new URL(callback).origin, { timeout: 10_000 }),
        page.locator('button[value=approve]').click(),
      ]);
      expect(callbackRequests).toHaveLength(1);
      expect(callbackRequests[0]!.method).toBe('GET');
      expect(callbackRequests[0]!.body).toBe('');
      expect(callbackRequests[0]!.referer).toBeUndefined();
      const result = new URL(callbackRequests[0]!.url);
      expect(result.searchParams.get('code')).toBeTruthy();
      expect(result.searchParams.get('state')).toBe('browser-roundtrip');
      expect(result.href).not.toContain(config.AUTH_PASSWORD);
    } finally { await context.close(); }
  });
});
