import { chromium, type Browser, type Page, type Response as PWResponse } from 'playwright';
import pLimit from 'p-limit';
import { config } from '../config.js';
import { logger } from '../logger.js';
import { isTargetBlocked } from './guard.js';

let browser: Browser | null = null;
let launching: Promise<Browser> | null = null;
let requestsSinceLaunch = 0;
let active = 0; // in-flight requests holding the shared browser

const limit = pLimit(Math.max(1, config.BROWSER_CONCURRENCY));

const launchArgs: string[] = ['--disable-dev-shm-usage'];
if (config.CHROMIUM_NO_SANDBOX) {
  // The rootless container is the isolation boundary; Chromium's own sandbox
  // requires user-namespace privileges we don't grant.
  launchArgs.push('--no-sandbox', '--disable-setuid-sandbox');
}

async function getBrowser(): Promise<Browser> {
  if (browser && browser.isConnected()) return browser;
  if (launching) return launching;
  launching = chromium
    .launch({ headless: true, args: launchArgs })
    .then((b) => {
      browser = b;
      requestsSinceLaunch = 0;
      launching = null;
      b.on('disconnected', () => {
        browser = null;
      });
      logger.info('chromium launched');
      return b;
    })
    .catch((err) => {
      launching = null;
      throw err;
    });
  return launching;
}

export async function warmupBrowser(): Promise<void> {
  await getBrowser();
}

export async function closeBrowser(): Promise<void> {
  const b = browser;
  browser = null;
  if (b) {
    try {
      await b.close();
    } catch {
      /* ignore */
    }
  }
}

// Recycle only when idle, so we never tear down a browser other concurrent
// requests are still using.
async function maybeRecycleIfIdle(): Promise<void> {
  if (active === 0 && config.BROWSER_RECYCLE_AFTER > 0 && requestsSinceLaunch >= config.BROWSER_RECYCLE_AFTER) {
    logger.info({ requestsSinceLaunch }, 'recycling chromium');
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

export interface ScreenshotResult {
  finalUrl: string;
  status: number | null;
  pngBase64: string;
}

/**
 * Run `fn` against a freshly-created, isolated browser context for one request,
 * then tear it down. A single Browser is shared; concurrency is bounded by a
 * semaphore. An SSRF request router (DNS-resolving, cached) aborts internal
 * targets on every request including redirects/subresources.
 */
async function withPage<T>(
  opts: RenderOptions,
  fn: (page: Page, response: PWResponse | null) => Promise<T>,
): Promise<T> {
  return limit(async () => {
    active++;
    const navTimeout = opts.navTimeoutMs ?? config.NAV_TIMEOUT_MS;
    let context: Awaited<ReturnType<Browser['newContext']>> | null = null;
    try {
      const b = await getBrowser();
      context = await b.newContext({ userAgent: config.FETCH_USER_AGENT, bypassCSP: true });
      context.setDefaultNavigationTimeout(navTimeout);
      context.setDefaultTimeout(navTimeout);
      await context.route('**/*', async (route) => {
        if (await isTargetBlocked(route.request().url())) {
          await route.abort('blockedbyclient');
          return;
        }
        await route.continue();
      });
      const page = await context.newPage();
      const response = await page.goto(opts.url, { waitUntil: 'domcontentloaded', timeout: navTimeout });
      // Best-effort settle for JS-rendered pages; never let this fail the fetch.
      await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
      if (opts.waitForSelector) {
        await page.waitForSelector(opts.waitForSelector, { timeout: navTimeout });
      }
      if (opts.waitMs && opts.waitMs > 0) {
        await page.waitForTimeout(Math.min(opts.waitMs, 60000));
      }
      const out = await fn(page, response);
      requestsSinceLaunch++;
      return out;
    } finally {
      if (context) await context.close().catch(() => {});
      active--;
      await maybeRecycleIfIdle().catch(() => {});
    }
  });
}

export function renderPage(opts: RenderOptions): Promise<RenderResult> {
  return withPage(opts, async (page, response) => ({
    finalUrl: page.url(),
    status: response?.status() ?? null,
    html: await page.content(),
    title: await page.title(),
  }));
}

export function screenshotPage(opts: RenderOptions): Promise<ScreenshotResult> {
  return withPage(opts, async (page, response) => {
    const buf = await page.screenshot({ type: 'png', fullPage: false });
    return {
      finalUrl: page.url(),
      status: response?.status() ?? null,
      pngBase64: buf.toString('base64'),
    };
  });
}
