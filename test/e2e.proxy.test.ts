import { createServer, type Server } from 'node:http';
import type { Socket } from 'node:net';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { startEgressProxy, type EgressProxy } from '../src/fetch/proxy.js';

// Opt-in real Chromium regression tests. Every response is either fulfilled by
// Playwright or served by our loopback fixture: no external service is needed.
const RUN = process.env.RUN_E2E === '1' || process.env.RUN_E2E === 'true';

describe.skipIf(!RUN)('e2e: connection-level Chromium SSRF boundary', () => {
  let browser: Browser;
  let destination: Server;
  let port: number;
  let destinationConnections = 0;
  const destinationSockets = new Set<Socket>();
  let gateway: EgressProxy;
  let context: BrowserContext;

  beforeAll(async () => {
    destination = createServer((_req, res) => {
      res.setHeader('content-type', 'text/plain');
      res.end('forbidden destination reached');
    });
    destination.on('connection', (socket) => {
      destinationConnections++;
      destinationSockets.add(socket);
      socket.on('error', () => {});
      socket.once('close', () => destinationSockets.delete(socket));
    });
    await new Promise<void>((resolve, reject) => {
      destination.once('error', reject);
      destination.listen(0, '127.0.0.1', () => {
        destination.off('error', reject);
        resolve();
      });
    });
    const address = destination.address();
    if (!address || typeof address === 'string') throw new Error('Fixture did not bind a TCP port');
    port = address.port;
    browser = await chromium.launch({
      headless: true,
      // Tests run in the existing isolated container; this is not a production default.
      chromiumSandbox: false,
      // Prevent browser-global background traffic from escaping to the network.
      proxy: { server: 'http://127.0.0.1:9', bypass: '<-loopback>' },
      args: ['--disable-dev-shm-usage', '--disable-background-networking', '--disable-quic'],
    });
  });

  beforeEach(async () => {
    destinationConnections = 0;
    gateway = await startEgressProxy({
      allowPrivate: false,
      // The fixture port is deliberately allowed: address policy, not port
      // rejection, must prevent the connection.
      allowedPorts: [80, 443, port],
      timeoutMs: 15000,
      // Every legitimate network destination in this test is a literal IP.
      // Unexpected favicon/background requests must not query external DNS.
      lookup: async () => { throw new Error('External DNS is disabled in this fixture'); },
    });
    context = await browser.newContext({
      proxy: { server: gateway.url, bypass: '<-loopback>' },
      serviceWorkers: 'block',
      acceptDownloads: false,
    });
  });

  afterEach(async () => {
    await context?.close();
    await gateway?.close();
  });

  afterAll(async () => {
    await browser?.close();
    for (const socket of destinationSockets) socket.destroy();
    if (destination) await new Promise<void>((resolve) => destination.close(() => resolve()));
  });

  it('blocks a public-to-loopback redirect even when Playwright omits the redirected route', async () => {
    const initial = 'http://initial.test/redirect';
    const forbidden = `http://127.0.0.1:${port}/private`;
    const page = await context.newPage();
    const routed: string[] = [];
    const requested: string[] = [];
    page.on('request', (req) => requested.push(req.url()));
    await page.route('**/*', async (route) => {
      routed.push(route.request().url());
      if (route.request().url() === initial) {
        await route.fulfill({ status: 302, headers: { location: forbidden }, body: '' });
      } else {
        // No route-level security check: the socket boundary must protect a
        // redirect whether or not Playwright happens to expose it here.
        await route.continue();
      }
    });
    const response = await page.goto(initial, { waitUntil: 'load', timeout: 10000 });
    expect(requested).toContain(forbidden);
    expect(routed).toEqual([initial]);
    expect(response?.status()).toBe(403);
    expect(destinationConnections).toBe(0);
    expect(gateway.failure).toBeUndefined();
  });

  it('blocks direct and redirected loopback subresources without destination connections', async () => {
    const initial = 'http://initial.test/page';
    const redirectImage = 'http://initial.test/redirect-image';
    const forbiddenDirect = `http://127.0.0.1:${port}/direct.png`;
    const forbiddenRedirect = `http://127.0.0.1:${port}/redirected.png`;
    const page = await context.newPage();
    const denied: string[] = [];
    page.on('response', (response) => {
      if (response.status() === 403) denied.push(response.url());
    });
    await page.route('**/*', async (route) => {
      const url = route.request().url();
      if (url === initial) {
        await route.fulfill({
          contentType: 'text/html',
          body: `<!doctype html><html><body>
            <img src="${forbiddenDirect}" onerror="this.dataset.failed='yes'">
            <img src="${redirectImage}" onerror="this.dataset.failed='yes'">
          </body></html>`,
        });
      } else if (url === redirectImage) {
        await route.fulfill({ status: 302, headers: { location: forbiddenRedirect }, body: '' });
      } else {
        await route.continue();
      }
    });
    await page.goto(initial, { waitUntil: 'load', timeout: 10000 });
    await page.waitForFunction(() => [...document.images].every((image) => image.dataset.failed === 'yes'));
    expect(denied).toEqual(expect.arrayContaining([forbiddenDirect, forbiddenRedirect]));
    expect(destinationConnections).toBe(0);
    expect(gateway.failure).toBeUndefined();
  });
});
