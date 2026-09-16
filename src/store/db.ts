import { dirname } from 'node:path';
import { mkdirSync, chmodSync } from 'node:fs';
import Database from 'better-sqlite3';
import { config } from '../config.js';
import { logger } from '../logger.js';

export function migrate(database: Database.Database): void {
  database.exec(`
    CREATE TABLE IF NOT EXISTS clients (
      client_id                TEXT PRIMARY KEY,
      metadata                 TEXT NOT NULL,   -- full OAuthClientInformationFull JSON
      client_id_issued_at      INTEGER,
      created_at               INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS auth_codes (
      code_hash       TEXT PRIMARY KEY,         -- sha256(code)
      client_id       TEXT NOT NULL,
      redirect_uri    TEXT NOT NULL,
      code_challenge  TEXT NOT NULL,            -- PKCE S256 challenge
      scopes          TEXT NOT NULL,            -- space-joined
      resource        TEXT,                     -- RFC 8707 canonical resource
      user_id         TEXT NOT NULL,
      expires_at      INTEGER NOT NULL,         -- epoch seconds
      consumed        INTEGER NOT NULL DEFAULT 0,
      created_at      INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS refresh_tokens (
      token_hash   TEXT PRIMARY KEY,            -- sha256(token)
      client_id    TEXT NOT NULL,
      family_id    TEXT NOT NULL,
      scopes       TEXT NOT NULL,               -- space-joined
      resource     TEXT,
      user_id      TEXT NOT NULL,
      expires_at   INTEGER NOT NULL,            -- epoch seconds
      rotated_to   TEXT,                         -- successor token_hash (null = current)
      revoked      INTEGER NOT NULL DEFAULT 0,
      created_at   INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS consumed_consents (
      jti_hash   TEXT PRIMARY KEY,
      expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_consents_expires ON consumed_consents(expires_at);

    CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON auth_codes(expires_at);
    CREATE INDEX IF NOT EXISTS idx_refresh_client ON refresh_tokens(client_id);
    CREATE INDEX IF NOT EXISTS idx_refresh_expires ON refresh_tokens(expires_at);
  `);
  const columns = database.prepare('PRAGMA table_info(refresh_tokens)').all() as Array<{ name: string }>;
  if (!columns.some((column) => column.name === 'family_id')) {
    database.transaction(() => {
      database.exec('ALTER TABLE refresh_tokens ADD COLUMN family_id TEXT');
      // Preserve existing grants during upgrade. Surviving rotation chains share
      // their latest existing expiry, fixed from this point onward. Tombstones
      // deleted by an older version cannot be reconstructed.
      const rows = database.prepare('SELECT token_hash, client_id, user_id, expires_at, rotated_to FROM refresh_tokens').all() as Array<{
        token_hash: string; client_id: string; user_id: string; expires_at: number; rotated_to: string | null;
      }>;
      const byHash = new Map(rows.map((row) => [row.token_hash, row]));
      const families = new Map<string, string>();
      for (const row of rows) {
        if (families.has(row.token_hash)) continue;
        const chain: string[] = [];
        const seen = new Set<string>();
        let cursor = row;
        while (!families.has(cursor.token_hash) && !seen.has(cursor.token_hash)) {
          chain.push(cursor.token_hash);
          seen.add(cursor.token_hash);
          const next = cursor.rotated_to ? byHash.get(cursor.rotated_to) : undefined;
          if (!next || next.client_id !== row.client_id || next.user_id !== row.user_id) break;
          cursor = next;
        }
        const family = families.get(cursor.token_hash) ?? cursor.token_hash;
        for (const hash of chain) families.set(hash, family);
      }
      const expiries = new Map<string, number>();
      for (const row of rows) {
        const family = families.get(row.token_hash)!;
        expiries.set(family, Math.max(expiries.get(family) ?? 0, row.expires_at));
      }
      const update = database.prepare('UPDATE refresh_tokens SET family_id = ?, expires_at = ? WHERE token_hash = ?');
      for (const row of rows) {
        const family = families.get(row.token_hash)!;
        update.run(family, expiries.get(family), row.token_hash);
      }
    })();
  }
  database.exec('CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id)');
}

function open(): Database.Database {
  try {
    if (config.DB_PATH !== ':memory:') mkdirSync(dirname(config.DB_PATH), { recursive: true, mode: 0o700 });
    const database = new Database(config.DB_PATH);
    if (config.DB_PATH !== ':memory:') chmodSync(config.DB_PATH, 0o600);
    database.pragma('journal_mode = WAL');
    if (config.DB_PATH !== ':memory:') {
      // SQLite sidecars can contain the same sensitive material as the main DB.
      for (const suffix of ['-wal', '-shm']) {
        try { chmodSync(config.DB_PATH + suffix, 0o600); } catch (err) {
          if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
        }
      }
    }
    database.pragma('foreign_keys = ON');
    database.pragma('busy_timeout = 5000');
    migrate(database);
    logger.info({ path: config.DB_PATH }, 'sqlite store ready');
    return database;
  } catch (err) {
    logger.fatal({ err }, 'failed to open sqlite store');
    process.exit(1);
  }
}

// Opened + migrated once on first import.
export const db = open();

/** Best-effort cleanup of expired/consumed rows. Safe to call periodically. */
export function pruneExpired(): void {
  const now = Math.floor(Date.now() / 1000);
  db.prepare('DELETE FROM auth_codes WHERE expires_at <= ? OR consumed = 1').run(now);
  db.prepare('DELETE FROM consumed_consents WHERE expires_at <= ?').run(now);
  // Keep revoked predecessors until the absolute family expiry for replay detection.
  db.prepare('DELETE FROM refresh_tokens WHERE expires_at <= ?').run(now);
}
