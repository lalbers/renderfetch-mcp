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
  family_id: string;
  scopes: string;
  resource: string | null;
  user_id: string;
  expires_at: number;
  rotated_to: string | null;
  revoked: number;
}

const insertStmt = db.prepare(
  `INSERT INTO refresh_tokens
     (token_hash, client_id, family_id, scopes, resource, user_id, expires_at, rotated_to, revoked, created_at)
   VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0, ?)`,
);
const getStmt = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?');
const revokeStmt = db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ? AND client_id = ? AND revoked = 0 AND expires_at > ?');
const rotateStmt = db.prepare(
  'UPDATE refresh_tokens SET revoked = 1, rotated_to = ? WHERE token_hash = ? AND revoked = 0 AND expires_at > ?',
);
const revokeFamilyStmt = db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ? AND client_id = ?');

function insertRefreshToken(data: NewRefreshToken, expiresAt: number, familyId: string): string {
  const token = randomToken(32);
  insertStmt.run(
    sha256hex(token), data.clientId, familyId, data.scopes.join(' '), data.resource ?? null,
    data.userId, expiresAt, nowSec(),
  );
  return token;
}

/** Start a grant with an absolute expiry shared by all subsequent rotations. */
export function createRefreshToken(data: NewRefreshToken): string {
  return insertRefreshToken(data, nowSec() + data.ttlSeconds, randomToken(16));
}

export interface RefreshTokenRow extends StoredRefreshToken {
  familyId: string;
  expiresAt: number;
  revoked: boolean;
  rotatedTo: string | null;
}

/** Includes tombstones: a replay must remain observable after housekeeping. */
export function getRefreshTokenRow(token: string): RefreshTokenRow | undefined {
  const row = getStmt.get(sha256hex(token)) as Row | undefined;
  if (!row) return undefined;
  return {
    clientId: row.client_id,
    familyId: row.family_id,
    scopes: row.scopes ? row.scopes.split(' ') : [],
    resource: row.resource ?? undefined,
    userId: row.user_id,
    expiresAt: row.expires_at,
    revoked: row.revoked === 1,
    rotatedTo: row.rotated_to,
  };
}

export function getRefreshToken(token: string): StoredRefreshToken | undefined {
  const row = getRefreshTokenRow(token);
  return row && !row.revoked && row.expiresAt > nowSec() ? row : undefined;
}

/** Atomic, one-use rotation. Expiry never slides beyond the original grant. */
export function rotateRefreshToken(oldToken: string, data: NewRefreshToken): string | undefined {
  return db.transaction(() => {
    const old = getRefreshTokenRow(oldToken);
    if (!old || old.revoked || old.expiresAt <= nowSec() || old.clientId !== data.clientId || old.userId !== data.userId) {
      return undefined;
    }
    const newToken = insertRefreshToken(data, old.expiresAt, old.familyId);
    if (rotateStmt.run(sha256hex(newToken), sha256hex(oldToken), nowSec()).changes !== 1) {
      throw new Error('Refresh token rotation conflict'); // transaction rolls back the new token
    }
    return newToken;
  }).immediate();
}

export function revokeRefreshToken(token: string, clientId: string): boolean {
  return revokeStmt.run(sha256hex(token), clientId, nowSec()).changes === 1;
}

export function revokeRefreshTokenFamily(familyId: string, clientId: string): void {
  revokeFamilyStmt.run(familyId, clientId);
}
