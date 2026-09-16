import { db } from './db.js';
import { nowSec, randomToken, sha256hex } from '../util.js';

export interface NewAuthCode {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  resource?: string;
  userId: string;
  ttlSeconds: number;
}

export interface StoredAuthCode {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  resource?: string;
  userId: string;
}

interface Row {
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  scopes: string;
  resource: string | null;
  user_id: string;
  expires_at: number;
  consumed: number;
}

const insertStmt = db.prepare(
  `INSERT INTO auth_codes
     (code_hash, client_id, redirect_uri, code_challenge, scopes, resource, user_id, expires_at, consumed, created_at)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
);
const getStmt = db.prepare('SELECT * FROM auth_codes WHERE code_hash = ?');
const consumeStmt = db.prepare(
  'UPDATE auth_codes SET consumed = 1 WHERE code_hash = ? AND consumed = 0 AND expires_at > ?',
);
const consumeConsentStmt = db.prepare('INSERT OR IGNORE INTO consumed_consents (jti_hash, expires_at) VALUES (?, ?)');

/** Create a single-use authorization code; returns the plaintext code. */
export function createAuthCode(data: NewAuthCode): string {
  const code = randomToken(32);
  insertStmt.run(
    sha256hex(code),
    data.clientId,
    data.redirectUri,
    data.codeChallenge,
    data.scopes.join(' '),
    data.resource ?? null,
    data.userId,
    nowSec() + data.ttlSeconds,
    nowSec(),
  );
  return code;
}

function toStored(row: Row): StoredAuthCode {
  return {
    clientId: row.client_id,
    redirectUri: row.redirect_uri,
    codeChallenge: row.code_challenge,
    scopes: row.scopes ? row.scopes.split(' ') : [],
    resource: row.resource ?? undefined,
    userId: row.user_id,
  };
}

/** Look up a valid (unexpired, unconsumed) code without consuming it. */
export function getAuthCode(code: string): StoredAuthCode | undefined {
  const row = getStmt.get(sha256hex(code)) as Row | undefined;
  if (!row) return undefined;
  if (row.consumed === 1 || row.expires_at <= nowSec()) return undefined;
  return toStored(row);
}

/** Mark a code consumed (one-time use). */
export function consumeAuthCode(code: string): boolean {
  return consumeStmt.run(sha256hex(code), nowSec()).changes === 1;
}

/** A consent token mints at most one code, including across processes/restarts. */
export function createAuthCodeForConsent(jti: string, expiresAt: number, data: NewAuthCode): string | undefined {
  return db.transaction(() => {
    if (expiresAt <= nowSec()) return undefined;
    if (consumeConsentStmt.run(sha256hex(jti), expiresAt).changes !== 1) return undefined;
    return createAuthCode(data);
  }).immediate();
}

/** Denial consumes the request too; approval cannot subsequently replay it. */
export function consumeConsent(jti: string, expiresAt: number): boolean {
  if (expiresAt <= nowSec()) return false;
  return consumeConsentStmt.run(sha256hex(jti), expiresAt).changes === 1;
}
