import { createServer, type Server } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const RUN = process.env.RUN_E2E === '1' || process.env.RUN_E2E === 'true';
describe.skipIf(!RUN)('e2e: detached cookie cleanup', () => {
  let server: Server;
  let url: string;
  let consentRequests = 0;
  beforeAll(async () => {
    server = createServer((req, res) => {
      if (req.url === '/consent') consentRequests++;
      res.setHeader('content-type', 'text/html');
      res.end(`<!doctype html><html><head><title>Cookie fixture</title></head><body>
        <article><h1>Article stays visible</h1><p>Ordinary page content.</p></article>
        <script>setTimeout(() => {
          const banner = document.createElement('div');
          banner.id = 'onetrust-banner-sdk';
          banner.innerHTML = '<p>We use cookies.</p><button>Accept all</button>';
          banner.querySelector('button').onclick = () => fetch('/consent');
          document.body.append(banner);
        }, 50);</script></body></html>`);
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Missing fixture port');
    process.env.FETCH_ALLOW_PRIVATE = 'true';
    process.env.FETCH_ALLOWED_PORTS = String(address.port);
    url = `http://127.0.0.1:${address.port}/`;
  });
  afterAll(async () => {
    const { closeBrowser } = await import('../src/fetch/browser.js');
    await closeBrowser();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  it('hides a delayed banner in output without clicking or modifying the captured page', async () => {
    const { renderPage } = await import('../src/fetch/browser.js');
    const { extract } = await import('../src/fetch/extract.js');
    const rendered = await renderPage({ url, waitForSelector: '#onetrust-banner-sdk' });
    expect(rendered.html).toContain('Accept all');
    const output = extract({ html: rendered.html, url, format: 'text', cssSelector: 'body', maxChars: 5000 });
    expect(output.cookieBanner).toMatchObject({ mode: 'hide', hidden: 1 });
    expect(output.content).toContain('Article stays visible');
    expect(output.content).not.toContain('We use cookies');
    expect(rendered.html).toContain('Accept all');
    expect(consentRequests).toBe(0);
  });
});
