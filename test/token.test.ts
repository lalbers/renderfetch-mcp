import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { startTestServer, type TestServer } from './helpers.js';

describe('DCR + token endpoint', () => {
  let srv: TestServer;
  let clientId = '';

  beforeAll(async () => {
    srv = await startTestServer();
    const reg = await fetch(`${srv.base}/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        client_name: 'test client',
      }),
    });
    expect(reg.status).toBe(201);
    const body = (await reg.json()) as { client_id: string };
    clientId = body.client_id;
    expect(clientId).toBeTruthy();
  });

  afterAll(async () => {
    await srv.close();
  });

  it('rejects a disallowed redirect_uri at registration', async () => {
    const reg = await fetch(`${srv.base}/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ redirect_uris: ['https://evil.example/cb'] }),
    });
    expect(reg.status).toBe(400);
  });

  it('/token accepts application/x-www-form-urlencoded (not 415) and runs grant logic', async () => {
    const form = new URLSearchParams({
      grant_type: 'authorization_code',
      code: 'bogus-code',
      code_verifier: 'bogus-verifier',
      redirect_uri: 'https://claude.ai/api/mcp/auth_callback',
      client_id: clientId,
      resource: 'https://mcp.test.example/mcp',
    });
    const r = await fetch(`${srv.base}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    // The decisive assertion: the form body was parsed (no 415), and the grant
    // logic ran and rejected the bogus code with a standard OAuth error.
    expect(r.status).not.toBe(415);
    expect([400, 401]).toContain(r.status);
    const body = (await r.json()) as { error?: string };
    expect(body.error).toBeTruthy();
  });
});
