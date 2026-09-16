import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import { createServer as createTcpServer, type Server as TcpServer } from 'node:net';
import { createSocket, type Socket as UdpSocket } from 'node:dgram';

// Real-Chromium test. Opt in with RUN_E2E=1 (requires Playwright browsers
// installed). Fetches a local server that fills the page via JavaScript, so it
// proves JS rendering, not just static HTML parsing.
const RUN = process.env.RUN_E2E === '1' || process.env.RUN_E2E === 'true';

describe.skipIf(!RUN)('e2e: fetch_url renders JavaScript', () => {
  let server: Server;
  let port = 0;
  let workerRequests = 0;
  let writeRequests = 0;
  let webSocketUpgrades = 0;
  let turnServer: TcpServer;
  let stunSocket: UdpSocket;
  let turnPort = 0;
  let stunPort = 0;
  let turnConnections = 0;
  let stunPackets = 0;

  beforeAll(async () => {
    // Allow fetching the loopback test server past the SSRF guard.
    process.env.FETCH_ALLOW_PRIVATE = 'true';
    turnServer = createTcpServer((socket) => { turnConnections++; socket.destroy(); });
    await new Promise<void>((resolve) => turnServer.listen(0, '127.0.0.1', resolve));
    turnPort = (turnServer.address() as { port: number }).port;
    stunSocket = createSocket('udp4');
    stunSocket.on('message', () => { stunPackets++; });
    await new Promise<void>((resolve) => stunSocket.bind(0, '127.0.0.1', resolve));
    stunPort = stunSocket.address().port;
    server = createServer((req, res) => {
      if (req.url === '/blocked-sw.js') workerRequests++;
      if (req.url === '/write') writeRequests++;
      res.setHeader('content-type', 'text/html; charset=utf-8');
      if (req.url === '/peer-network') {
        res.end(`<!doctype html><html><head><title>Peer-network probe</title></head><body>
          <p id="state">starting</p><script>
          const peers = [
            new RTCPeerConnection({ iceServers: [{ urls: 'stun:127.0.0.1:${stunPort}' }] }),
            new RTCPeerConnection({ iceTransportPolicy: 'relay', iceServers: [{
              urls: 'turn:127.0.0.1:${turnPort}?transport=tcp', username: 'probe', credential: 'probe'
            }] })
          ];
          Promise.all(peers.map(async (peer) => {
            peer.createDataChannel('probe');
            await peer.setLocalDescription(await peer.createOffer());
          })).then(() => {
            document.querySelector('#state').id = 'started';
            document.querySelector('#started').textContent = 'STUN and TURN gathering started';
          }).catch(() => { document.querySelector('#state').textContent = 'probe setup failed'; });
          </script></body></html>`);
        return;
      }
      if (req.url === '/multibyte') {
        res.end('<html><body>' + '€'.repeat(400) + '</body></html>');
        return;
      }
      if (req.url === '/restrictions') {
        res.end(`<!doctype html><html><head><title>Restricted browser</title></head><body>
          <p id="state">starting</p><script>
          fetch('/write', { method: 'POST', body: 'must not leave the browser' }).catch(() => {});
          try { navigator.serviceWorker.register('/blocked-sw.js').catch(() => {}); } catch {}
          try { new WebSocket('ws://' + location.host + '/socket'); } catch {}
          document.querySelector('#state').textContent = 'attempted blocked browser capabilities';
          </script></body></html>`);
        return;
      }
      res.end(
        `<!doctype html><html><head><title>JS Page</title></head><body>` +
          `<div id="app">loading…</div>` +
          `<script>document.getElementById('app').innerHTML =` +
          ` '<h1>Rendered Heading</h1><p>Injected by JavaScript.</p>';</script>` +
          `</body></html>`,
      );
    });
    server.on('upgrade', (_req, socket) => { webSocketUpgrades++; socket.destroy(); });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    const addr = server.address();
    port = addr && typeof addr === 'object' ? addr.port : 0;
    process.env.FETCH_ALLOWED_PORTS = String(port);
  });

  afterAll(async () => {
    const { closeBrowser } = await import('../src/fetch/browser.js');
    await closeBrowser();
    if (server) await new Promise<void>((resolve) => server.close(() => resolve()));
    if (turnServer) await new Promise<void>((resolve) => turnServer.close(() => resolve()));
    if (stunSocket) await new Promise<void>((resolve) => stunSocket.close(() => resolve()));
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

  it('blocks service workers, WebSockets and state-changing requests in the real browser', async () => {
    const { renderPage } = await import('../src/fetch/browser.js');
    const rendered = await renderPage({ url: `http://127.0.0.1:${port}/restrictions`, waitMs: 300 });
    expect(rendered.html).toContain('attempted blocked browser capabilities');
    expect(workerRequests).toBe(0);
    expect(writeRequests).toBe(0);
    expect(webSocketUpgrades).toBe(0);
  }, 60000);

  it('does not contact controlled STUN UDP or TURN TCP destinations outside the HTTP port policy', async () => {
    const { renderPage } = await import('../src/fetch/browser.js');
    // Only the HTTP fixture port is approved. A direct socket bypass would
    // contact these distinct sinks despite the connection-level proxy policy.
    expect(turnPort).not.toBe(port);
    const rendered = await renderPage({
      url: `http://127.0.0.1:${port}/peer-network`,
      waitForSelector: '#started', waitMs: 2_000,
    });
    expect(rendered.html).toContain('STUN and TURN gathering started');
    expect(stunPackets).toBe(0);
    expect(turnConnections).toBe(0);
  }, 60000);
  it('enforces UTF-8 byte size inside Chromium before IPC', async () => {
    const { renderPage } = await import('../src/fetch/browser.js');
    const { config } = await import('../src/config.js');
    const previous = config.FETCH_MAX_HTML_BYTES;
    config.FETCH_MAX_HTML_BYTES = 1000;
    try {
      await expect(renderPage({ url: `http://127.0.0.1:${port}/multibyte` }))
        .rejects.toThrow('Rendered UTF-8 page is too large');
    } finally { config.FETCH_MAX_HTML_BYTES = previous; }
  });

});
