import { createHash, randomUUID } from 'node:crypto';
import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from 'vitest';
import { SignJWT } from 'jose';
import Database from 'better-sqlite3';
import type { OAuthClientInformationFull, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import { startTestServer, type TestServer } from './helpers.js';
import { config, OWNER_USER_ID } from '../src/config.js';
import { signAccessToken, signConsentRequest, verifyAccessTokenJwt, verifyConsentRequest } from '../src/auth/jwt.js';
import { RenderfetchOAuthProvider } from '../src/auth/provider.js';
import { createAuthCode, createAuthCodeForConsent, getAuthCode, consumeAuthCode } from '../src/store/codes.js';
import { createRefreshToken, getRefreshTokenRow, rotateRefreshToken } from '../src/store/tokens.js';
import { isAllowedRedirect, SqliteClientsStore } from '../src/store/clients.js';
import { db, pruneExpired, migrate } from '../src/store/db.js';
import { nowSec } from '../src/util.js';

const callback = 'https://claude.ai/api/mcp/auth_callback';
const verifier = 'test-verifier-'.repeat(4);
const challenge = createHash('sha256').update(verifier).digest('base64url');
const client = (id = randomUUID()): OAuthClientInformationFull => ({
  client_id: id,
  redirect_uris: [callback],
  token_endpoint_auth_method: 'none',
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
});

function tokenForm(clientId: string, code: string, codeVerifier = verifier): URLSearchParams {
  return new URLSearchParams({ grant_type: 'authorization_code', client_id: clientId, code,
    code_verifier: codeVerifier, redirect_uri: callback, resource: config.resourceUrl.href });
}

describe('OAuth HTTP security', () => {
  let srv: TestServer;
  let registered: OAuthClientInformationFull;
  beforeAll(async () => {
    srv = await startTestServer();
    const response = await fetch(`${srv.base}/register`, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(client('ignored-by-dcr')) });
    expect(response.status).toBe(201);
    registered = await response.json() as OAuthClientInformationFull;
  });
  afterAll(async () => { await srv.close(); });

  it('issues a client secret that outlives the SDK default of 30 days', async () => {
    // Only CONFIDENTIAL clients get a secret — the shared test client above
    // registers as `none`. That asymmetry is the whole point: a connector that
    // registers confidentially (claude.ai does) silently stops refreshing once
    // the secret expires, with "Client secret has expired" visible only in the
    // server log. Without clientRegistrationOptions the SDK hands out 30 days;
    // observed in production as a monthly manual re-link across four months.
    const response = await fetch(`${srv.base}/register`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...client(), token_endpoint_auth_method: 'client_secret_post' }),
    });
    expect(response.status).toBe(201);
    const confidential = await response.json() as OAuthClientInformationFull;
    expect(confidential.client_secret).toBeTruthy();
    const issued = confidential.client_id_issued_at!;
    expect(confidential.client_secret_expires_at).toBe(issued + config.CLIENT_SECRET_TTL);
    expect(confidential.client_secret_expires_at! - issued).toBeGreaterThan(30 * 86400);
  });

  async function authorization(scope?: string): Promise<Response> {
    const params = new URLSearchParams({ client_id: registered.client_id, redirect_uri: callback,
      response_type: 'code', code_challenge: challenge, code_challenge_method: 'S256', state: 'roundtrip-state' });
    if (scope !== undefined) params.set('scope', scope);
    return fetch(`${srv.base}/authorize?${params}`, { redirect: 'manual' });
  }
  async function consentRequest(scope?: string): Promise<string> {
    const response = await authorization(scope);
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get('location')!, srv.base);
    expect(location.pathname).toBe('/consent');
    return location.searchParams.get('req')!;
  }
  function approve(req: string, origin: string | undefined = config.issuerUrl.origin, action = 'approve'): Promise<Response> {
    return fetch(`${srv.base}/consent`, { method: 'POST', redirect: 'manual',
      headers: origin === undefined ? {} : { origin },
      body: new URLSearchParams({ req, username: config.AUTH_USERNAME, password: config.AUTH_PASSWORD, action }) });
  }

  it('rejects unsupported scopes before consent', async () => {
    for (const scope of ['mcp:fetch admin', 'offline_access']) {
      const response = await authorization(scope);
      expect(response.status).toBe(302);
      expect(new URL(response.headers.get('location')!).searchParams.get('error')).toBe('invalid_scope');
    }
  });

  it('completes a PKCE grant, rejects wrong verifier/reuse, and exposes protected consent headers', async () => {
    const req = await consentRequest('mcp:fetch offline_access');
    const page = await fetch(`${srv.base}/consent?req=${encodeURIComponent(req)}`);
    expect(page.status).toBe(200);
    expect(page.headers.get('cache-control')).toBe('no-store');
    expect(page.headers.get('referrer-policy')).toBe('same-origin');
    expect(page.headers.get('x-frame-options')).toBe('DENY');
    expect(page.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    expect(page.headers.get('content-security-policy')).toContain("form-action 'self' https://claude.ai");
    const approval = await approve(req);
    expect(approval.status).toBe(302);
    const redirect = new URL(approval.headers.get('location')!);
    expect(redirect.searchParams.get('state')).toBe('roundtrip-state');
    const code = redirect.searchParams.get('code')!;
    expect((await approve(req)).status).toBe(400);
    const wrong = await fetch(`${srv.base}/token`, { method: 'POST', body: tokenForm(registered.client_id, code, 'wrong-verifier') });
    expect(wrong.status).toBe(400);
    const exchanged = await fetch(`${srv.base}/token`, { method: 'POST', body: tokenForm(registered.client_id, code) });
    expect(exchanged.status).toBe(200);
    const tokens = await exchanged.json() as OAuthTokens;
    expect(tokens.refresh_token).toBeTruthy();
    expect((await verifyAccessTokenJwt(tokens.access_token)).scopes).toEqual(['mcp:fetch', 'offline_access']);
    expect((await fetch(`${srv.base}/token`, { method: 'POST', body: tokenForm(registered.client_id, code) })).status).toBe(400);
  });

  it('defaults omitted scope to fetch without granting offline access', async () => {
    const req = await consentRequest();
    expect((await verifyConsentRequest(req)).scopes).toEqual(['mcp:fetch']);
    const approval = await approve(req);
    const code = new URL(approval.headers.get('location')!).searchParams.get('code')!;
    const response = await fetch(`${srv.base}/token`, { method: 'POST', body: tokenForm(registered.client_id, code) });
    expect(response.status).toBe(200);
    const tokens = await response.json() as OAuthTokens;
    expect(tokens.scope).toBe('mcp:fetch');
    expect(tokens.refresh_token).toBeUndefined();
  });

  it('rejects cross-origin consent and consumes denials permanently', async () => {
    const req = await consentRequest();
    expect((await approve(req, 'https://evil.example')).status).toBe(403);
    expect((await approve(req, 'null')).status).toBe(403);
    const denied = await approve(req, config.issuerUrl.origin, 'deny');
    expect(new URL(denied.headers.get('location')!).searchParams.get('error')).toBe('access_denied');
    expect((await approve(req)).status).toBe(400);
  });

  it('rejects bearer tokens without mcp:fetch scope', async () => {
    const { token } = await signAccessToken({ clientId: registered.client_id, scopes: ['offline_access'] });
    const response = await fetch(`${srv.base}/mcp`, { headers: { authorization: `Bearer ${token}` } });
    expect(response.status).toBe(403);
    expect(response.headers.get('www-authenticate')).toContain('mcp:fetch');
  });
});

describe('OAuth store and claim invariants', () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it('keeps rotated tombstones after pruning and never slides the family expiry', async () => {
    const provider = new RenderfetchOAuthProvider();
    const owner = client();
    const original = createRefreshToken({ clientId: owner.client_id, scopes: ['mcp:fetch', 'offline_access'],
      resource: config.resourceUrl.href, userId: OWNER_USER_ID, ttlSeconds: 120 });
    const separateGrant = createRefreshToken({ clientId: owner.client_id, scopes: ['mcp:fetch', 'offline_access'],
      resource: config.resourceUrl.href, userId: OWNER_USER_ID, ttlSeconds: 120 });
    const initialExpiry = getRefreshTokenRow(original)!.expiresAt;
    const clock = Date.now();
    vi.spyOn(Date, 'now').mockReturnValue(clock + 30_000);
    const rotated = await provider.exchangeRefreshToken(owner, original);
    expect(getRefreshTokenRow(rotated.refresh_token!)!.expiresAt).toBe(initialExpiry);
    pruneExpired();
    expect(getRefreshTokenRow(original)?.revoked).toBe(true);
    await expect(provider.exchangeRefreshToken(owner, original)).rejects.toThrow('revoked');
    await expect(provider.exchangeRefreshToken(owner, rotated.refresh_token!)).rejects.toThrow('revoked');
    expect(getRefreshTokenRow(separateGrant)?.revoked).toBe(false);
    vi.spyOn(Date, 'now').mockReturnValue(clock + 121_000);
    pruneExpired();
    expect(getRefreshTokenRow(original)).toBeUndefined();
    expect(getRefreshTokenRow(rotated.refresh_token!)).toBeUndefined();
  });

  it('migrates surviving legacy rotation chains to a fixed family expiry', () => {
    const legacy = new Database(':memory:');
    try {
      legacy.exec(`CREATE TABLE refresh_tokens (
        token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, scopes TEXT NOT NULL, resource TEXT,
        user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, rotated_to TEXT,
        revoked INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL
      )`);
      const insert = legacy.prepare('INSERT INTO refresh_tokens VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?)');
      insert.run('old', 'client', 'mcp:fetch offline_access', OWNER_USER_ID, 100, 'new', 1, 1);
      insert.run('new', 'client', 'mcp:fetch offline_access', OWNER_USER_ID, 200, null, 0, 2);
      insert.run('separate', 'client', 'mcp:fetch offline_access', OWNER_USER_ID, 300, null, 0, 3);
      migrate(legacy);
      expect(legacy.prepare('SELECT family_id, expires_at FROM refresh_tokens WHERE token_hash = ?').get('old'))
        .toEqual({ family_id: 'new', expires_at: 200 });
      expect(legacy.prepare('SELECT family_id, expires_at FROM refresh_tokens WHERE token_hash = ?').get('new'))
        .toEqual({ family_id: 'new', expires_at: 200 });
      expect(legacy.prepare('SELECT family_id FROM refresh_tokens WHERE token_hash = ?').get('separate'))
        .toEqual({ family_id: 'separate' });
      migrate(legacy); // restart is idempotent
    } finally { legacy.close(); }
  });

  it('uses compare-and-set rotation so a consumed token cannot produce another successor', () => {
    const data = { clientId: randomUUID(), scopes: ['mcp:fetch', 'offline_access'], userId: OWNER_USER_ID, ttlSeconds: 60 };
    const original = createRefreshToken(data);
    expect(rotateRefreshToken(original, data)).toBeTruthy();
    expect(rotateRefreshToken(original, data)).toBeUndefined();
  });

  it('binds revocation and exchange to the client', async () => {
    const provider = new RenderfetchOAuthProvider();
    const owner = client();
    const stranger = client();
    const token = createRefreshToken({ clientId: owner.client_id, scopes: ['mcp:fetch', 'offline_access'],
      resource: config.resourceUrl.href, userId: OWNER_USER_ID, ttlSeconds: 120 });
    await provider.revokeToken(stranger, { token });
    expect(getRefreshTokenRow(token)?.revoked).toBe(false);
    await expect(provider.exchangeRefreshToken(stranger, token)).rejects.toThrow('not issued');
    await provider.revokeToken(owner, { token });
    expect(getRefreshTokenRow(token)?.revoked).toBe(true);
  });

  it('binds authorization codes to the client, redirect, and resource without consuming failed attempts', async () => {
    const provider = new RenderfetchOAuthProvider();
    const owner = client();
    const code = createAuthCode({ clientId: owner.client_id, redirectUri: callback, codeChallenge: challenge,
      scopes: ['mcp:fetch'], resource: config.resourceUrl.href, userId: OWNER_USER_ID, ttlSeconds: 60 });
    await expect(provider.challengeForAuthorizationCode(client(), code)).rejects.toThrow();
    await expect(provider.exchangeAuthorizationCode(client(), code)).rejects.toThrow('not issued');
    await expect(provider.exchangeAuthorizationCode(owner, code, undefined, 'http://localhost/other')).rejects.toThrow('redirect_uri');
    await expect(provider.exchangeAuthorizationCode(owner, code, undefined, callback, new URL('https://other.example/mcp'))).rejects.toThrow('resource');
    expect(getAuthCode(code)).toBeDefined();
    const issued = await provider.exchangeAuthorizationCode(owner, code, undefined, callback, config.resourceUrl);
    expect((await verifyAccessTokenJwt(issued.access_token)).clientId).toBe(owner.client_id);
    expect(getAuthCode(code)).toBeUndefined();
  });

  it('rejects legacy invalid scopes and refresh grants issued for a different resource', async () => {
    const provider = new RenderfetchOAuthProvider();
    const owner = client();
    for (const scopes of [[], ['offline_access'], ['mcp:fetch', 'offline_access', 'admin'], ['mcp:fetch', 'offline_access', 'offline_access']]) {
      const legacy = createRefreshToken({ clientId: owner.client_id, scopes, resource: config.resourceUrl.href,
        userId: OWNER_USER_ID, ttlSeconds: 60 });
      await expect(provider.exchangeRefreshToken(owner, legacy)).rejects.toThrow('authorize again');
    }
    const oldResource = createRefreshToken({ clientId: owner.client_id, scopes: ['mcp:fetch', 'offline_access'],
      resource: 'https://previous-server.example/mcp', userId: OWNER_USER_ID, ttlSeconds: 60 });
    await expect(provider.exchangeRefreshToken(owner, oldResource)).rejects.toThrow('authorize again');
    expect(getRefreshTokenRow(oldResource)?.rotatedTo).toBeNull();
  });

  it('removes refresh permission when explicitly downscoped', async () => {
    const provider = new RenderfetchOAuthProvider();
    const owner = client();
    const original = createRefreshToken({ clientId: owner.client_id, scopes: ['mcp:fetch', 'offline_access'],
      resource: config.resourceUrl.href, userId: OWNER_USER_ID, ttlSeconds: 120 });
    await expect(provider.exchangeRefreshToken(owner, original, ['offline_access'])).rejects.toThrow('mcp:fetch');
    const downscoped = await provider.exchangeRefreshToken(owner, original, ['mcp:fetch']);
    expect(downscoped.refresh_token).toBeUndefined();
    expect(getRefreshTokenRow(original)?.revoked).toBe(true);
  });

  it('atomically persists consent use and code consumption', () => {
    const jti = randomUUID();
    const data = { clientId: randomUUID(), redirectUri: callback, codeChallenge: challenge,
      scopes: ['mcp:fetch'], userId: OWNER_USER_ID, ttlSeconds: 60 };
    const code = createAuthCodeForConsent(jti, nowSec() + 60, data)!;
    expect(code).toBeTruthy();
    expect(createAuthCodeForConsent(jti, nowSec() + 60, data)).toBeUndefined();
    expect(db.prepare('SELECT COUNT(*) AS count FROM consumed_consents').get()).toMatchObject({ count: expect.any(Number) });
    expect(consumeAuthCode(code)).toBe(true);
    expect(consumeAuthCode(code)).toBe(false);
    expect(getAuthCode(code)).toBeUndefined();
  });

  it('enforces exact safe callbacks, including configured extras', () => {
    for (const uri of [callback, 'http://127.0.0.1:48123/callback', 'http://[::1]:5123/cb']) expect(isAllowedRedirect(uri)).toBe(true);
    for (const uri of [`${callback}?forward=evil`, `${callback}#x`, 'https://claude.ai:444/api/mcp/auth_callback',
      'https://user@claude.ai/api/mcp/auth_callback', 'http://public.example/cb', 'javascript:alert(1)',
      'http://localhost/cb#fragment', 'http://user@localhost/cb']) expect(isAllowedRedirect(uri)).toBe(false);
    const previous = config.EXTRA_REDIRECT_URIS;
    try {
      config.EXTRA_REDIRECT_URIS = ['javascript:alert(1)', 'https://trusted.example/cb'];
      expect(isAllowedRedirect('javascript:alert(1)')).toBe(false);
      expect(isAllowedRedirect('https://trusted.example/cb')).toBe(true);
    } finally { config.EXTRA_REDIRECT_URIS = previous; }
  });

  it('caps dynamic client registration without replacing existing clients', () => {
    const previous = config.OAUTH_MAX_CLIENTS;
    try {
      const { count } = db.prepare('SELECT COUNT(*) AS count FROM clients').get() as { count: number };
      config.OAUTH_MAX_CLIENTS = count + 1;
      const store = new SqliteClientsStore();
      const allowed = client();
      store.registerClient(allowed);
      expect(() => store.registerClient(client())).toThrow('capacity');
      expect(store.getClient(allowed.client_id)?.redirect_uris).toEqual([callback]);
    } finally { config.OAUTH_MAX_CLIENTS = previous; }
  });

  it('rejects malformed claims, missing expiry, wrong type, and wrong audience', async () => {
    const secret = new TextEncoder().encode(config.JWT_SECRET);
    const baseline = { sub: OWNER_USER_ID, client_id: 'test-client', scope: 'mcp:fetch', iat: nowSec(),
      exp: nowSec() + 60, jti: randomUUID(), iss: config.issuerUrl.href, aud: config.resourceUrl.href };
    const cases: Array<{ payload: Record<string, unknown>; typ?: string }> = [
      { payload: { ...baseline, sub: undefined } },
      { payload: { ...baseline, client_id: undefined } },
      { payload: { ...baseline, exp: undefined } },
      { payload: { ...baseline, exp: nowSec() - 1 } },
      { payload: { ...baseline, iat: nowSec() + 60, exp: nowSec() + 120 } },
      { payload: { ...baseline, aud: 'https://other.example/mcp' } },
      { payload: { ...baseline, scope: 'admin' } },
      { payload: baseline, typ: 'consent+jwt' },
    ];
    for (const invalid of cases) {
      const token = await new SignJWT(invalid.payload).setProtectedHeader({ alg: 'HS256', typ: invalid.typ ?? 'at+jwt' }).sign(secret);
      await expect(verifyAccessTokenJwt(token)).rejects.toThrow();
    }
    const consent = await signConsentRequest({ clientId: 'test-client', redirectUri: callback,
      codeChallenge: challenge, scopes: ['mcp:fetch'] });
    await expect(verifyAccessTokenJwt(consent)).rejects.toThrow();
  });
});
