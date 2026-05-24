import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { startTestServer, type TestServer } from './helpers.js';

describe('discovery + health', () => {
  let srv: TestServer;
  beforeAll(async () => {
    srv = await startTestServer();
  });
  afterAll(async () => {
    await srv.close();
  });

  it('serves /healthz unauthenticated', async () => {
    const r = await fetch(`${srv.base}/healthz`);
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ status: 'ok' });
  });

  it('authorization-server metadata is spec-correct (RFC 8414)', async () => {
    const r = await fetch(`${srv.base}/.well-known/oauth-authorization-server`);
    expect(r.status).toBe(200);
    const m = (await r.json()) as Record<string, unknown>;
    expect(m.issuer).toBe('https://mcp.test.example/');
    expect(String(m.authorization_endpoint)).toContain('/authorize');
    expect(String(m.token_endpoint)).toContain('/token');
    expect(String(m.registration_endpoint)).toContain('/register');
    expect(m.code_challenge_methods_supported).toContain('S256');
    expect(m.grant_types_supported).toContain('refresh_token');
    expect(m.scopes_supported).toContain('offline_access');
  });

  it('protected-resource metadata lists the AS (RFC 9728)', async () => {
    const r = await fetch(`${srv.base}/.well-known/oauth-protected-resource/mcp`);
    expect(r.status).toBe(200);
    const m = (await r.json()) as Record<string, unknown>;
    expect(m.resource).toBe('https://mcp.test.example/mcp');
    expect(Array.isArray(m.authorization_servers)).toBe(true);
    expect((m.authorization_servers as unknown[]).length).toBeGreaterThan(0);
  });

  it('GET /mcp without a token returns 401 + WWW-Authenticate(resource_metadata)', async () => {
    const r = await fetch(`${srv.base}/mcp`);
    expect(r.status).toBe(401);
    const wa = (r.headers.get('www-authenticate') ?? '').toLowerCase();
    expect(wa).toContain('bearer');
    expect(wa).toContain('resource_metadata');
  });
});
