import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { request as httpRequest } from 'node:http';
import { config } from '../src/config.js';
import { signAccessToken } from '../src/auth/jwt.js';
import { closeAllTransports } from '../src/mcp/transport.js';
import * as mcpServerModule from '../src/mcp/server.js';
import { createApp } from '../src/http.js';
import { startTestServer, type TestServer } from './helpers.js';

const original = {
  ALLOWED_ORIGINS: config.ALLOWED_ORIGINS,
  TRUST_PROXY: config.TRUST_PROXY,
  MCP_SESSION_TTL_MS: config.MCP_SESSION_TTL_MS,
  MCP_MAX_SESSIONS: config.MCP_MAX_SESSIONS,
  MCP_MAX_SESSIONS_PER_CLIENT: config.MCP_MAX_SESSIONS_PER_CLIENT,
  RATE_LIMIT_MAX: config.RATE_LIMIT_MAX,
  STATIC_BEARER_TOKEN: config.STATIC_BEARER_TOKEN,
  OAUTH_ONLY: config.OAUTH_ONLY,
};
const staticToken = 'test-static-bearer-for-session-tests';
const initializeBody = {
  jsonrpc: '2.0', id: 1, method: 'initialize',
  params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'security-test', version: '1' } },
};

describe('MCP transport security (real HTTP + SDK)', () => {
  let srv: TestServer;
  let tokenA: string;
  let tokenB: string;

  beforeEach(async () => {
    await closeAllTransports();
    Object.assign(config, {
      ...original,
      ALLOWED_ORIGINS: ['https://inspector.example'],
      TRUST_PROXY: [],
      MCP_SESSION_TTL_MS: 60_000,
      MCP_MAX_SESSIONS: 8,
      MCP_MAX_SESSIONS_PER_CLIENT: 4,
      RATE_LIMIT_MAX: 1000,
      STATIC_BEARER_TOKEN: staticToken,
      OAUTH_ONLY: false,
    });
    tokenA = (await signAccessToken({ clientId: 'client-a', scopes: ['mcp:fetch'] })).token;
    tokenB = (await signAccessToken({ clientId: 'client-b', scopes: ['mcp:fetch'] })).token;
    srv = await startTestServer();
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await closeAllTransports();
    await srv?.close();
    Object.assign(config, original);
  });

  async function request(token: string, method: string, session?: string, body?: unknown, origin?: string) {
    const response = await fetch(`${srv.base}/mcp`, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        accept: 'application/json, text/event-stream',
        ...(method === 'POST' ? { 'content-type': 'application/json' } : {}),
        ...(session ? { 'mcp-session-id': session } : {}),
        ...(origin !== undefined ? { origin } : {}),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    // Drain finite SSE responses as well as JSON so test shutdown is deterministic.
    const text = await response.text();
    return { status: response.status, headers: response.headers, text };
  }

  const initialize = (token: string, origin?: string) => request(token, 'POST', undefined, initializeBody, origin);
  const ping = (token: string, session: string) => request(token, 'POST', session, { jsonrpc: '2.0', id: 2, method: 'ping' });

  it('binds GET, POST and DELETE to client + subject without revealing foreign sessions', async () => {
    const started = await initialize(tokenA);
    expect(started.status).toBe(200);
    const id = started.headers.get('mcp-session-id')!;
    expect(id).toBeTruthy();
    expect((await ping(tokenB, id)).status).toBe(404);
    expect((await request(tokenB, 'GET', id)).status).toBe(404);
    expect((await request(tokenB, 'DELETE', id)).status).toBe(404);
    const otherSubject = (await signAccessToken({ clientId: 'client-a', userId: 'different-user', scopes: ['mcp:fetch'] })).token;
    expect((await ping(otherSubject, id)).status).toBe(404);
    expect((await ping(tokenA, id)).status).toBe(200);
  });

  it('keeps the same session across refreshed access tokens', async () => {
    const started = await initialize(tokenA);
    const refreshed = (await signAccessToken({ clientId: 'client-a', scopes: ['mcp:fetch'] })).token;
    expect(refreshed).not.toBe(tokenA);
    expect((await ping(refreshed, started.headers.get('mcp-session-id')!)).status).toBe(200);
  });

  it('separates static and OAuth identities even when client and subject strings match', async () => {
    const started = await initialize(staticToken);
    expect(started.status).toBe(200);
    const oauth = (await signAccessToken({ clientId: 'static-bearer', scopes: ['mcp:fetch'] })).token;
    expect((await ping(oauth, started.headers.get('mcp-session-id')!)).status).toBe(404);
  });

  it('returns 400 for missing and 404 for unknown or deleted session IDs', async () => {
    expect((await request(tokenA, 'GET')).status).toBe(400);
    expect((await request(tokenA, 'DELETE')).status).toBe(400);
    expect((await request(tokenA, 'POST', undefined, { jsonrpc: '2.0', id: 2, method: 'ping' })).status).toBe(400);
    expect((await ping(tokenA, 'unknown-session')).status).toBe(404);
    const started = await initialize(tokenA);
    const id = started.headers.get('mcp-session-id')!;
    expect((await request(tokenA, 'DELETE', id)).status).toBe(200);
    expect((await ping(tokenA, id)).status).toBe(404);
  });

  it('rejects duplicate and oversized session headers without selecting a valid ID', async () => {
    const started = await initialize(tokenA);
    const id = started.headers.get('mcp-session-id')!;
    config.MCP_MAX_SESSIONS = 1;
    for (const method of ['GET', 'POST']) {
      const duplicateStatus = await new Promise<number | undefined>((resolve, reject) => {
        const req = httpRequest(`${srv.base}/mcp`, {
          method,
          headers: { authorization: `Bearer ${tokenA}`, 'mcp-session-id': [id, id], accept: 'application/json, text/event-stream', 'content-type': 'application/json' },
        }, (res) => {
          res.resume();
          res.on('end', () => resolve(res.statusCode));
        });
        req.on('error', reject);
        req.end(method === 'POST' ? JSON.stringify(initializeBody) : undefined);
      });
      expect(duplicateStatus).toBe(404);
    }
    expect((await ping(tokenA, 'x'.repeat(1024))).status).toBe(404);
    expect((await request(tokenA, 'POST', 'x'.repeat(1024), initializeBody)).status).toBe(404);
    expect((await ping(tokenA, id)).status).toBe(200);
    await request(tokenA, 'DELETE', id);
    expect((await initialize(tokenB)).status).toBe(200);
  });

  it('accepts absent Origin and reflects only exact canonical/configured origins', async () => {
    expect((await initialize(tokenA)).status).toBe(200);
    for (const origin of [config.issuerUrl.origin, 'https://inspector.example']) {
      const response = await initialize(tokenA, origin);
      expect(response.status).toBe(200);
      expect(response.headers.get('access-control-allow-origin')).toBe(origin);
    }
  });

  it.each(['https://attacker.example', 'null', 'not-an-origin', 'https://mcp.test.example/', 'https://mcp.test.example.evil'])('rejects present disallowed Origin %s before authentication', async (origin) => {
    const response = await request('invalid', 'POST', undefined, initializeBody, origin);
    expect(response.status).toBe(403);
    expect(response.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('applies the Origin policy to unauthenticated preflight requests', async () => {
    const allowed = await fetch(`${srv.base}/mcp`, { method: 'OPTIONS', headers: { origin: 'https://inspector.example', 'access-control-request-method': 'POST' } });
    expect(allowed.status).toBe(204);
    expect(allowed.headers.get('access-control-allow-origin')).toBe('https://inspector.example');
    const denied = await fetch(`${srv.base}/mcp`, { method: 'OPTIONS', headers: { origin: 'https://attacker.example', 'access-control-request-method': 'POST' } });
    expect(denied.status).toBe(403);
    expect(denied.headers.get('access-control-allow-origin')).toBeNull();
    await denied.text();
  });

  it('enforces per-identity and global caps and releases deleted sessions', async () => {
    config.MCP_MAX_SESSIONS = 2;
    config.MCP_MAX_SESSIONS_PER_CLIENT = 1;
    const first = await initialize(tokenA);
    expect(first.status).toBe(200);
    expect((await initialize(tokenA)).status).toBe(429);
    expect((await initialize(tokenB)).status).toBe(200);
    const tokenC = (await signAccessToken({ clientId: 'client-c', scopes: ['mcp:fetch'] })).token;
    expect((await initialize(tokenC)).status).toBe(429);
    await request(tokenA, 'DELETE', first.headers.get('mcp-session-id')!);
    expect((await initialize(tokenC)).status).toBe(200);
  });

  it('rejects initialize notifications without consuming unreachable session capacity', async () => {
    config.MCP_MAX_SESSIONS = 1;
    const { id: _id, ...notification } = initializeBody;
    expect((await request(tokenA, 'POST', undefined, notification)).status).toBe(400);
    expect((await initialize(tokenA)).status).toBe(200);
  });

  it('reserves capacity before simultaneous initializations complete', async () => {
    config.MCP_MAX_SESSIONS_PER_CLIENT = 1;
    const responses = await Promise.all(Array.from({ length: 8 }, () => initialize(tokenA)));
    expect(responses.filter((response) => response.status === 200)).toHaveLength(1);
    expect(responses.filter((response) => response.status === 429)).toHaveLength(7);
  });

  it('expires idle sessions before lookup and releases capacity', async () => {
    config.MCP_MAX_SESSIONS = 1;
    const started = await initialize(tokenA);
    const now = Date.now();
    vi.spyOn(Date, 'now').mockReturnValue(now + config.MCP_SESSION_TTL_MS + 1);
    expect((await ping(tokenA, started.headers.get('mcp-session-id')!)).status).toBe(404);
    expect((await initialize(tokenB)).status).toBe(200);
  });

  it('sweeps idle sessions without incoming traffic and closes the associated server', async () => {
    config.MCP_SESSION_TTL_MS = 25;
    const build = mcpServerModule.buildMcpServer;
    const closed = vi.fn();
    vi.spyOn(mcpServerModule, 'buildMcpServer').mockImplementation(() => {
      const server = build();
      const close = server.close.bind(server);
      vi.spyOn(server, 'close').mockImplementation(async () => { closed(); await close(); });
      return server;
    });
    expect((await initialize(tokenA)).status).toBe(200);
    await new Promise((resolve) => setTimeout(resolve, 75));
    expect(closed).toHaveBeenCalledOnce();
  });

  it('cleans up failed initialization and closes all session IDs deterministically', async () => {
    config.MCP_MAX_SESSIONS = 1;
    const bad = await request(tokenA, 'POST', undefined, { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
    expect(bad.status).toBeGreaterThanOrEqual(400);
    // Valid initialize body but invalid Accept: reservation happens before the
    // SDK rejects it, so the finally-path must reclaim the unpublished session.
    const rejected = await fetch(`${srv.base}/mcp`, {
      method: 'POST',
      headers: { authorization: `Bearer ${tokenA}`, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(initializeBody),
    });
    expect(rejected.status).toBe(406);
    await rejected.text();
    const started = await initialize(tokenA);
    expect(started.status).toBe(200);
    await closeAllTransports();
    expect((await ping(tokenA, started.headers.get('mcp-session-id')!)).status).toBe(404);
    expect((await initialize(tokenB)).status).toBe(200);
  });

  it('rate-limits stable identities, not refreshed token values', async () => {
    // Each app has a fresh in-memory rate-limit store; configure it before creation.
    await srv.close();
    config.RATE_LIMIT_MAX = 1;
    srv = await startTestServer();
    expect((await request(tokenA, 'GET')).status).toBe(400);
    const refreshed = (await signAccessToken({ clientId: 'client-a', scopes: ['mcp:fetch'] })).token;
    expect((await request(refreshed, 'GET')).status).toBe(429);
    expect((await request(tokenB, 'GET')).status).toBe(400);
  });

  it('does not trust arbitrary forwarded IP headers by default', () => {
    expect(createApp().get('trust proxy')).toBe(false);
    config.TRUST_PROXY = ['127.0.0.1/32'];
    expect(createApp().get('trust proxy')).toEqual(['127.0.0.1/32']);
  });

  it('rejects unsupported encodings and malformed compressed bodies as client errors', async () => {
    for (const [extraHeaders, body, status] of [
      [{ 'content-type': 'application/json; charset=iso-8859-1' }, '{}', 415],
      [{ 'content-encoding': 'unsupported' }, '{}', 415],
      [{ 'content-encoding': 'gzip' }, 'not-a-gzip-stream', 400],
    ] as const) {
      const response = await fetch(`${srv.base}/mcp`, {
        method: 'POST',
        headers: { authorization: `Bearer ${tokenA}`, 'content-type': 'application/json', ...extraHeaders },
        body,
      });
      expect(response.status).toBe(status);
      expect(await response.text()).not.toContain(body);
    }
  });

  it('maps malformed and oversized JSON to 400 and 413 without echoing bodies', async () => {
    const headers = { authorization: `Bearer ${tokenA}`, 'content-type': 'application/json' };
    const malformed = await fetch(`${srv.base}/mcp`, { method: 'POST', headers, body: '{"private-payload"' });
    expect(malformed.status).toBe(400);
    expect(await malformed.text()).not.toContain('private-payload');
    const oversized = await fetch(`${srv.base}/mcp`, { method: 'POST', headers, body: JSON.stringify({ value: 'x'.repeat(4 * 1024 * 1024) }) });
    expect(oversized.status).toBe(413);
    await oversized.text();
  });
});
