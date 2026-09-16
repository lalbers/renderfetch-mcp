import { afterEach, describe, expect, it, vi } from 'vitest';
import { config } from '../src/config.js';

const mocks = vi.hoisted(() => {
  const page = {
    on: vi.fn(), goto: vi.fn(async () => ({ status: () => 200 })),
    waitForLoadState: vi.fn(async () => {}), waitForSelector: vi.fn(async () => {}),
    waitForTimeout: vi.fn(async () => {}), url: () => 'https://example.com/',
    evaluate: vi.fn(async () => '<html><head><title>Example</title></head><body>ok</body></html>'),
    title: vi.fn(async () => 'Example'), screenshot: vi.fn(async () => Buffer.from('png')),
  };
  const context = {
    setDefaultNavigationTimeout: vi.fn(), setDefaultTimeout: vi.fn(),
    route: vi.fn(async () => {}), routeWebSocket: vi.fn(async () => {}),
    on: vi.fn(), newPage: vi.fn(async () => page), close: vi.fn(async () => {}),
  };
  const browser = { isConnected: () => true, newContext: vi.fn(async () => context), on: vi.fn(), close: vi.fn(async () => {}) };
  const proxy = { url: 'http://127.0.0.1:12345', failure: undefined, close: vi.fn(async () => {}) };
  return { page, context, browser, proxy, launch: vi.fn(async () => browser), startProxy: vi.fn(async () => proxy) };
});
vi.mock('playwright', () => ({ chromium: { launch: mocks.launch } }));
vi.mock('../src/fetch/proxy.js', () => ({ startEgressProxy: mocks.startProxy }));

import { browserEnvironment, closeBrowser, renderPage, screenshotPage } from '../src/fetch/browser.js';
const originals = { maxQueue: config.BROWSER_MAX_QUEUE, timeout: config.FETCH_TIMEOUT_MS, maxHtml: config.FETCH_MAX_HTML_BYTES };

afterEach(async () => {
  config.BROWSER_MAX_QUEUE = originals.maxQueue;
  config.FETCH_TIMEOUT_MS = originals.timeout;
  config.FETCH_MAX_HTML_BYTES = originals.maxHtml;
  await closeBrowser();
  vi.clearAllMocks();
});

describe('isolated browser jobs', () => {
  it('passes only an explicit environment allowlist to Chromium', () => {
    expect(browserEnvironment({ PATH: '/bin', HOME: '/home/browser', JWT_SECRET: 'secret', AUTH_PASSWORD: 'secret', AWS_SESSION_TOKEN: 'secret', NODE_OPTIONS: '--require evil.js', HTTP_PROXY: 'http://evil' }))
      .toEqual({ PATH: '/bin', HOME: '/home/browser' });
  });

  it('enforces per-context proxy, service-worker and download restrictions', async () => {
    await renderPage({ url: 'https://example.com/' });
    expect(mocks.launch).toHaveBeenCalledWith(expect.objectContaining({ chromiumSandbox: !config.CHROMIUM_NO_SANDBOX }));
    expect(mocks.context.routeWebSocket).toHaveBeenCalled();
    expect(mocks.browser.newContext).toHaveBeenCalledWith(expect.objectContaining({
      serviceWorkers: 'block', acceptDownloads: false, permissions: [],
      proxy: { server: mocks.proxy.url, bypass: '<-loopback>' },
    }));
    expect(mocks.browser.newContext.mock.calls[0]?.[0]).not.toHaveProperty('bypassCSP');
    expect(mocks.proxy.close).toHaveBeenCalled();
    expect(mocks.context.close).toHaveBeenCalled();
  });

  it('returns HTML/title for screenshot text preflight', async () => {
    const shot = await screenshotPage({ url: 'https://example.com/' });
    expect(shot.html).toContain('<body>ok</body>');
    expect(shot.title).toBe('Example');
    expect(shot.pngBase64).toBe(Buffer.from('png').toString('base64'));
  });

  it('rejects oversized screenshots before base64 serialization', async () => {
    const maxBytes = Math.min(config.FETCH_MAX_TRANSFER_BYTES, 5_000_000);
    mocks.page.screenshot.mockResolvedValueOnce(Buffer.alloc(maxBytes + 1));
    await expect(screenshotPage({ url: 'https://example.com/' })).rejects.toThrow('output limit');
    expect(mocks.proxy.close).toHaveBeenCalled();
    expect(mocks.context.close).toHaveBeenCalled();
  });

  it('bounds same-tick admission and recovers after timeout', async () => {
    config.BROWSER_MAX_QUEUE = 0;
    config.FETCH_TIMEOUT_MS = 30;
    mocks.page.goto.mockImplementation(() => new Promise(() => {}));
    const accepted = Array.from({ length: config.BROWSER_CONCURRENCY }, () => renderPage({ url: 'https://example.com/' }));
    await expect(renderPage({ url: 'https://example.com/' })).rejects.toThrow('queue is full');
    const outcomes = await Promise.allSettled(accepted);
    expect(outcomes.every((value) => value.status === 'rejected')).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 10));
    mocks.page.goto.mockImplementation(async () => ({ status: () => 200 }));
    config.FETCH_TIMEOUT_MS = originals.timeout;
    await expect(renderPage({ url: 'https://example.com/' })).resolves.toHaveProperty('status', 200);
    expect(mocks.proxy.close).toHaveBeenCalled();
  });

  it('rejects an oversized DOM before extraction', async () => {
    config.FETCH_MAX_HTML_BYTES = 10;
    await expect(renderPage({ url: 'https://example.com/' })).rejects.toThrow('too large');
    expect(mocks.context.close).toHaveBeenCalled();
  });
});
