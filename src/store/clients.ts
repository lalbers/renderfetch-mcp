import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { InvalidClientMetadataError, TooManyRequestsError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { db } from './db.js';
import { config, SUPPORTED_SCOPES } from '../config.js';
import { logger } from '../logger.js';
import { nowSec } from '../util.js';

const CLAUDE_AI_CALLBACK = 'https://claude.ai/api/mcp/auth_callback';
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/** Validate URI structure before applying the exact allowlist/loopback exception. */
export function isAllowedRedirect(uri: string): boolean {
  if (uri.length > 2048 || /[\s\u0000-\u001f\u007f\\]/.test(uri)) return false;
  let u: URL;
  try { u = new URL(uri); } catch { return false; }
  if (u.username || u.password || u.hash || uri.includes('#')) return false;
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && LOOPBACK_HOSTS.has(u.hostname))) return false;
  if (uri === CLAUDE_AI_CALLBACK || config.EXTRA_REDIRECT_URIS.includes(uri)) return true;
  return LOOPBACK_HOSTS.has(u.hostname);
}

const getStmt = db.prepare('SELECT metadata FROM clients WHERE client_id = ?');
const countStmt = db.prepare('SELECT COUNT(*) AS count FROM clients');
const insertStmt = db.prepare(
  'INSERT INTO clients (client_id, metadata, client_id_issued_at, created_at) VALUES (?, ?, ?, ?)',
);

export class SqliteClientsStore implements OAuthRegisteredClientsStore {
  getClient(clientId: string): OAuthClientInformationFull | undefined {
    const row = getStmt.get(clientId) as { metadata: string } | undefined;
    return row ? JSON.parse(row.metadata) as OAuthClientInformationFull : undefined;
  }

  registerClient(client: OAuthClientInformationFull): OAuthClientInformationFull {
    if (!client.redirect_uris.length || client.redirect_uris.length > 10 ||
        (client.client_name?.length ?? 0) > 256 || client.client_id.length > 256) {
      throw new InvalidClientMetadataError('Client metadata exceeds the supported limits');
    }
    for (const uri of client.redirect_uris) {
      if (!isAllowedRedirect(uri)) throw new InvalidClientMetadataError('redirect_uri not allowed');
    }
    if (client.scope?.split(' ').some((scope) => !SUPPORTED_SCOPES.includes(scope))) {
      throw new InvalidClientMetadataError('Unsupported scope');
    }
    db.transaction(() => {
      const { count } = countStmt.get() as { count: number };
      if (count >= config.OAUTH_MAX_CLIENTS) throw new TooManyRequestsError('Client registration capacity reached');
      insertStmt.run(client.client_id, JSON.stringify(client), client.client_id_issued_at ?? nowSec(), nowSec());
    }).immediate();
    // Avoid reflecting arbitrary client names or redirect query strings into logs.
    logger.info({ client_id: client.client_id }, 'registered oauth client');
    return client;
  }
}
