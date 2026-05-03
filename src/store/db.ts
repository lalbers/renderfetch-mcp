import { dirname } from 'node:path';
import { mkdirSync } from 'node:fs';
import Database from 'better-sqlite3';
import { config } from '../config.js';
import { logger } from '../logger.js';

function migrate(database: Database.Database): void {
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
      scopes       TEXT NOT NULL,               -- space-joined
      resource     TEXT,
      user_id      TEXT NOT NULL,
      expires_at   INTEGER NOT NULL,            -- epoch seconds
      rotated_to   TEXT,                         -- successor token_hash (null = current)
      revoked      INTEGER NOT NULL DEFAULT 0,
      created_at   INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON auth_codes(expires_at);
    CREATE INDEX IF NOT EXISTS idx_refresh_client ON refresh_tokens(client_id);
    CREATE INDEX IF NOT EXISTS idx_refresh_expires ON refresh_tokens(expires_at);
  `);
}

function open(): Database.Database {
  try {
    mkdirSync(dirname(config.DB_PATH), { recursive: true });
    const database = new Database(config.DB_PATH);
    database.pragma('journal_mode = WAL');
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
  db.prepare('DELETE FROM auth_codes WHERE expires_at < ? OR consumed = 1').run(now);
  db.prepare('DELETE FROM refresh_tokens WHERE expires_at < ? OR revoked = 1').run(now);
}
