import { chromium, type Browser, type BrowserContext, type Page, type Response as PWResponse } from 'playwright';
import pLimit from 'p-limit';
import { config } from '../config.js';
import { logger } from '../logger.js';
import { parseFetchUrl } from './guard.js';
import { startEgressProxy, type EgressProxy } from './proxy.js';

let browser: Browser | null = null;
let launching: Promise<Browser> | null = null;
let requestsSinceLaunch = 0;
let active = 0;
let admitted = 0; // Synchronous admission also covers same-tick bursts and expired queued jobs.
const limit = pLimit(config.BROWSER_CONCURRENCY);

// Chromium needs runtime/display/library locations, not OAuth credentials or the
// host's cloud/API tokens. Never inherit process.env wholesale into the browser.
export function browserEnvironment(env: NodeJS.ProcessEnv = process.env): Record<string, string> {
  const allowed = ['PATH', 'HOME', 'TMPDIR', 'TMP', 'TEMP', 'LANG', 'LC_ALL', 'TZ',
    'DISPLAY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR', 'XDG_CACHE_HOME',
    'LD_LIBRARY_PATH', 'FONTCONFIG_PATH', 'FONTCONFIG_FILE', 'SYSTEMROOT'];
  return Object.fromEntries(allowed.flatMap((name) => env[name] === undefined ? [] : [[name, env[name]!]]));
}

async function getBrowser(): Promise<Browser> {
  if (browser?.isConnected()) return browser;
  if (launching) return launching;
  launching = chromium.launch({
    headless: true,
    chromiumSandbox: !config.CHROMIUM_NO_SANDBOX,
    env: browserEnvironment(),
    // A dead launch-level proxy prevents browser background HTTP traffic going
    // direct. Every job supplies its own live, policy-enforcing context proxy.
    proxy: { server: 'http://127.0.0.1:9', bypass: '<-loopback>' },
    args: [
      '--disable-dev-shm-usage', '--disable-quic',
      '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
      '--proxy-bypass-list=<-loopback>',
    ],
    timeout: 30_000,
  }).then((b) => {
    browser = b;
    requestsSinceLaunch = 0;
    b.on('disconnected', () => { if (browser === b) browser = null; });
    logger.info('chromium launched');
    return b;
  }).finally(() => { launching = null; });
  return launching;
}

export async function warmupBrowser(): Promise<void> { await getBrowser(); }
export async function closeBrowser(): Promise<void> {
  const b = browser ?? await launching?.catch(() => null);
  browser = null;
  if (b) await b.close().catch(() => {});
}

async function maybeRecycleIfIdle(): Promise<void> {
  if (active === 0 && config.BROWSER_RECYCLE_AFTER > 0 && requestsSinceLaunch >= config.BROWSER_RECYCLE_AFTER) {
    await closeBrowser();
  }
}

export interface RenderOptions {
  url: string;
  waitMs?: number;
  waitForSelector?: string;
  navTimeoutMs?: number;
}
export interface RenderResult {
  finalUrl: string;
  status: number | null;
  html: string;
  title: string;
}
export interface ScreenshotResult extends RenderResult { pngBase64: string; }

/** Per-job context, connection-level egress policy, bounded queue and deadline. */
async function withPage<T>(opts: RenderOptions, fn: (page: Page, response: PWResponse | null) => Promise<T>): Promise<T> {
  parseFetchUrl(opts.url, { allowedPorts: config.FETCH_ALLOWED_PORTS, allowPrivate: config.FETCH_ALLOW_PRIVATE });
  if (admitted >= config.BROWSER_CONCURRENCY + config.BROWSER_MAX_QUEUE) {
    throw new Error('Browser queue is full; retry later');
  }
  admitted++;
  let context: BrowserContext | undefined;
  let proxy: EgressProxy | undefined;
  let stopped = false;
  let expire: (error: Error) => void = () => {};
  const expired = new Promise<never>((_resolve, reject) => { expire = reject; });
  const stop = (error: Error) => {
    if (stopped) return;
    stopped = true;
    void context?.close().catch(() => {});
    void proxy?.close();
    expire(error);
  };
  const timer = setTimeout(() => stop(new Error('Browser request deadline exceeded')), config.FETCH_TIMEOUT_MS);
  timer.unref();
  const check = () => { if (stopped) throw new Error('Browser request expired'); };

  const work = limit(async () => {
    if (stopped) { admitted--; check(); }
    active++;
    try {
      const operation = async (): Promise<T> => {
        const b = await getBrowser();
        check();
        proxy = await startEgressProxy();
        if (stopped) { await proxy.close(); check(); }
        context = await b.newContext({
          userAgent: config.FETCH_USER_AGENT,
          serviceWorkers: 'block', acceptDownloads: false,
          permissions: [],
          proxy: { server: proxy.url, bypass: '<-loopback>' },
        });
        if (stopped) { await context.close(); check(); }
        const navTimeout = Math.min(opts.navTimeoutMs ?? config.NAV_TIMEOUT_MS, config.FETCH_TIMEOUT_MS);
        context.setDefaultNavigationTimeout(navTimeout);
        context.setDefaultTimeout(navTimeout);
        let requestCount = 0;
        context.on('request', () => {
          if (++requestCount > config.FETCH_MAX_REQUESTS) stop(new Error('Browser request limit exceeded'));
        });
        await context.route('**/*', async (route) => {
          try {
            check();
            if (!['GET', 'HEAD', 'OPTIONS'].includes(route.request().method())) throw new Error('Browser writes are disabled');
            // Syntax/port check only. DNS/IP checks belong to the proxy's pinned
            // connection, not a second resolver call with a TOCTOU window.
            parseFetchUrl(route.request().url(), { allowedPorts: config.FETCH_ALLOWED_PORTS, allowPrivate: config.FETCH_ALLOW_PRIVATE });
            await route.continue();
          } catch { await route.abort('blockedbyclient').catch(() => {}); }
        });
        await context.routeWebSocket('**/*', (socket) => socket.close());
        const page = await context.newPage();
        context.on('page', (extra) => { if (extra !== page) void extra.close().catch(() => {}); });
        page.on('download', (download) => { void download.cancel().catch(() => {}); });
        page.on('dialog', (dialog) => { void dialog.dismiss().catch(() => {}); });
        const response = await page.goto(opts.url, { waitUntil: 'domcontentloaded', timeout: navTimeout });
        await page.waitForLoadState('networkidle', { timeout: 2_000 }).catch(() => {});
        check();
        if (opts.waitForSelector) await page.waitForSelector(opts.waitForSelector, { timeout: navTimeout });
        if (opts.waitMs && opts.waitMs > 0) await page.waitForTimeout(Math.min(opts.waitMs, 60_000));
        check();
        if (proxy.failure) throw proxy.failure;
        const value = await fn(page, response);
        check();
        if (proxy.failure) throw proxy.failure;
        return value;
      };
      return await Promise.race([operation(), expired]);
    } finally {
      // Proxy first: even a Chromium shutdown stall must not retain egress.
      await proxy?.close();
      await context?.close().catch(() => {});
      requestsSinceLaunch++;
      active--;
      admitted--;
      await maybeRecycleIfIdle().catch(() => {});
    }
  });
  try { return await Promise.race([work, expired]); }
  finally { clearTimeout(timer); }
}

async function snapshot(page: Page, response: PWResponse | null): Promise<RenderResult> {
  // Bound serialized UTF-8 in the renderer before transferring the DOM to Node.
  // Check code units first to avoid encoding an already-overlarge string.
  const html = await page.evaluate((maxBytes) => {
    const document = (globalThis as unknown as { document: { documentElement: { outerHTML: string } } }).document;
    const value = document.documentElement.outerHTML;
    if (value.length > maxBytes) throw new Error('Rendered page is too large');
    if (new TextEncoder().encode(value).byteLength > maxBytes) throw new Error('Rendered UTF-8 page is too large');
    return value;
  }, config.FETCH_MAX_HTML_BYTES);
  if (Buffer.byteLength(html, 'utf8') > config.FETCH_MAX_HTML_BYTES) throw new Error('Rendered page is too large');
  const finalUrl = page.url();
  // data:/blob: navigations can avoid ordinary HTTP routing. Do not return them.
  parseFetchUrl(finalUrl, { allowedPorts: config.FETCH_ALLOWED_PORTS, allowPrivate: config.FETCH_ALLOW_PRIVATE });
  return { finalUrl, status: response?.status() ?? null, html, title: (await page.title()).slice(0, 2_000) };
}

export function renderPage(opts: RenderOptions): Promise<RenderResult> {
  return withPage(opts, snapshot);
}
export function screenshotPage(opts: RenderOptions): Promise<ScreenshotResult> {
  return withPage(opts, async (page, response) => {
    const captured = await snapshot(page, response);
    const image = await page.screenshot({ type: 'png', fullPage: false, timeout: config.NAV_TIMEOUT_MS });
    if (image.byteLength > Math.min(config.FETCH_MAX_TRANSFER_BYTES, 5_000_000)) {
      throw new Error('Screenshot exceeds the output limit');
    }
    return { ...captured, pngBase64: image.toString('base64') };
  });
}
