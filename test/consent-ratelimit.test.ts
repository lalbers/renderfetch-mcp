import { createHash } from 'node:crypto';
import { connect } from 'node:net';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { startTestServer, type TestServer } from './helpers.js';
import { config } from '../src/config.js';

// Own file: the consent limiter is module state and would leak into other suites.
const callback = 'https://claude.ai/api/mcp/auth_callback';
const challenge = createHash('sha256').update('test-verifier-'.repeat(4)).digest('base64url');

describe('consent rate limit', () => {
  let srv: TestServer;
  let clientId: string;
  beforeAll(async () => {
    srv = await startTestServer();
    const response = await fetch(`${srv.base}/register`, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ redirect_uris: [callback], token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code'], response_types: ['code'] }) });
    clientId = (await response.json() as OAuthClientInformationFull).client_id;
  });
  afterAll(async () => { await srv.close(); });

  async function consentRequest(): Promise<string> {
    const params = new URLSearchParams({ client_id: clientId, redirect_uri: callback, response_type: 'code',
      code_challenge: challenge, code_challenge_method: 'S256' });
    const response = await fetch(`${srv.base}/authorize?${params}`, { redirect: 'manual' });
    return new URL(response.headers.get('location')!, srv.base).searchParams.get('req')!;
  }
  function post(req: string, password: string, origin = config.issuerUrl.origin): Promise<Response> {
    return fetch(`${srv.base}/consent`, { method: 'POST', redirect: 'manual', headers: { origin },
      body: new URLSearchParams({ req, username: config.AUTH_USERNAME, password, action: 'approve' }) });
  }

  // Headers arrive, the body never does: the parser aborts without a response.
  function abortedPost(): Promise<void> {
    const { hostname, port } = new URL(srv.base);
    return new Promise((resolve) => {
      const socket = connect(Number(port), hostname, () => {
        socket.write(`POST /consent HTTP/1.1\r\nHost: ${hostname}\r\nOrigin: ${config.issuerUrl.origin}\r\n` +
          'Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 1000\r\n\r\nreq=partial');
        setTimeout(() => { socket.destroy(); resolve(); }, 20);
      });
    });
  }

  it('ignores junk posts but locks out after repeated wrong credentials', async () => {
    // Anonymous junk shares the proxy's bucket in default deployments; it must not count.
    for (let i = 0; i < 15; i++) {
      expect((await post('forged', config.AUTH_PASSWORD)).status).toBe(400);
      expect((await post('forged', config.AUTH_PASSWORD, 'https://evil.example')).status).toBe(403);
      await abortedPost();
    }
    expect((await post(await consentRequest(), config.AUTH_PASSWORD)).status).toBe(302);

    const req = await consentRequest();
    for (let i = 0; i < 10; i++) expect((await post(req, 'wrong-password')).status).toBe(401);
    expect((await post(req, config.AUTH_PASSWORD)).status).toBe(429);
  });
});
