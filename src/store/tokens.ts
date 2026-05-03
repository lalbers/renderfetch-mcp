import { db } from './db.js';
import { nowSec, randomToken, sha256hex } from '../util.js';

export interface NewRefreshToken {
  clientId: string;
  scopes: string[];
  resource?: string;
  userId: string;
  ttlSeconds: number;
}

export interface StoredRefreshToken {
  clientId: string;
  scopes: string[];
  resource?: string;
  userId: string;
}

interface Row {
  token_hash: string;
  client_id: string;
  scopes: string;
  resource: string | null;
  user_id: string;
  expires_at: number;
  rotated_to: string | null;
  revoked: number;
}

const insertStmt = db.prepare(
  `INSERT INTO refresh_tokens
     (token_hash, client_id, scopes, resource, user_id, expires_at, rotated_to, revoked, created_at)
   VALUES (?, ?, ?, ?, ?, ?, NULL, 0, ?)`,
);
const getStmt = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?');
const revokeStmt = db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?');
const rotateStmt = db.prepare(
  'UPDATE refresh_tokens SET revoked = 1, rotated_to = ? WHERE token_hash = ?',
);
const revokeByClientStmt = db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE client_id = ?');

/** Issue a new refresh token; returns the plaintext token. */
export function createRefreshToken(data: NewRefreshToken): string {
  const token = randomToken(32);
  insertStmt.run(
    sha256hex(token),
    data.clientId,
    data.scopes.join(' '),
    data.resource ?? null,
    data.userId,
    nowSec() + data.ttlSeconds,
    nowSec(),
  );
  return token;
}

/** Look up a valid (active, unexpired, unrevoked) refresh token. */
export function getRefreshToken(token: string): StoredRefreshToken | undefined {
  const row = getStmt.get(sha256hex(token)) as Row | undefined;
  if (!row) return undefined;
  if (row.revoked === 1 || row.expires_at < nowSec()) return undefined;
  return {
    clientId: row.client_id,
    scopes: row.scopes ? row.scopes.split(' ') : [],
    resource: row.resource ?? undefined,
    userId: row.user_id,
  };
}

export interface RefreshTokenRow extends StoredRefreshToken {
  expiresAt: number;
  revoked: boolean;
  rotatedTo: string | null;
}

/** Look up a refresh token regardless of state — for reuse/theft detection. */
export function getRefreshTokenRow(token: string): RefreshTokenRow | undefined {
  const row = getStmt.get(sha256hex(token)) as Row | undefined;
  if (!row) return undefined;
  return {
    clientId: row.client_id,
    scopes: row.scopes ? row.scopes.split(' ') : [],
    resource: row.resource ?? undefined,
    userId: row.user_id,
    expiresAt: row.expires_at,
    revoked: row.revoked === 1,
    rotatedTo: row.rotated_to,
  };
}

/**
 * Rotate a refresh token: revoke the old one (linking it to its successor) and
 * issue a new one in a single transaction. Required for public clients.
 */
export function rotateRefreshToken(oldToken: string, data: NewRefreshToken): string {
  const txn = db.transaction((): string => {
    const newToken = createRefreshToken(data);
    rotateStmt.run(sha256hex(newToken), sha256hex(oldToken));
    return newToken;
  });
  return txn();
}

export function revokeRefreshToken(token: string): void {
  revokeStmt.run(sha256hex(token));
}

export function revokeRefreshTokensForClient(clientId: string): void {
  revokeByClientStmt.run(clientId);
}
