import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';

// Real-Chromium test. Opt in with RUN_E2E=1 (requires Playwright browsers
// installed). Fetches a local server that fills the page via JavaScript, so it
// proves JS rendering, not just static HTML parsing.
const RUN = process.env.RUN_E2E === '1' || process.env.RUN_E2E === 'true';

describe.skipIf(!RUN)('e2e: fetch_url renders JavaScript', () => {
  let server: Server;
  let port = 0;

  beforeAll(async () => {
    // Allow fetching the loopback test server past the SSRF guard.
    process.env.FETCH_ALLOW_PRIVATE = 'true';
    server = createServer((_req, res) => {
      res.setHeader('content-type', 'text/html');
      res.end(
        `<!doctype html><html><head><title>JS Page</title></head><body>` +
          `<div id="app">loading…</div>` +
          `<script>document.getElementById('app').innerHTML =` +
          ` '<h1>Rendered Heading</h1><p>Injected by JavaScript.</p>';</script>` +
          `</body></html>`,
      );
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const addr = server.address();
    port = addr && typeof addr === 'object' ? addr.port : 0;
  });

  afterAll(async () => {
    await new Promise<void>((r) => server.close(() => r()));
    const { closeBrowser } = await import('../src/fetch/browser.js');
    await closeBrowser();
  });

  it('returns markdown containing JS-injected content', async () => {
    const { renderPage } = await import('../src/fetch/browser.js');
    const { extract } = await import('../src/fetch/extract.js');
    const rendered = await renderPage({ url: `http://127.0.0.1:${port}/`, waitMs: 300 });
    const ex = extract({
      html: rendered.html,
      url: rendered.finalUrl,
      format: 'markdown',
      maxChars: 50000,
    });
    expect(ex.content).toContain('Rendered Heading');
    expect(ex.content).toContain('Injected by JavaScript');
  }, 60000);
});
