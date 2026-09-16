import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import { InvalidClientMetadataError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { db } from './db.js';
import { config } from '../config.js';
import { logger } from '../logger.js';
import { nowSec } from '../util.js';

const CLAUDE_AI_CALLBACK = 'https://claude.ai/api/mcp/auth_callback';
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

/**
 * Redirect-URI allowlist for Dynamic Client Registration. DCR is open by spec
 * (any client may register), but we still constrain *where* a client may be
 * redirected to limit abuse — the real user-facing control is the consent
 * credential. Allowed:
 *   - claude.ai's exact connector callback,
 *   - loopback (Claude Code / MCP Inspector, any port/path),
 *   - any exact URI listed in EXTRA_REDIRECT_URIS.
 */
export function isAllowedRedirect(uri: string): boolean {
  if (config.EXTRA_REDIRECT_URIS.includes(uri)) return true;
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return false;
  }
  if (u.protocol === 'https:' && u.hostname === 'claude.ai' && u.pathname === '/api/mcp/auth_callback') {
    return true;
  }
  if ((u.protocol === 'http:' || u.protocol === 'https:') && LOOPBACK_HOSTS.has(u.hostname)) {
    return true;
  }
  return false;
}

const getStmt = db.prepare('SELECT metadata FROM clients WHERE client_id = ?');
const insertStmt = db.prepare(
  'INSERT OR REPLACE INTO clients (client_id, metadata, client_id_issued_at, created_at) VALUES (?, ?, ?, ?)',
);

export class SqliteClientsStore implements OAuthRegisteredClientsStore {
  getClient(clientId: string): OAuthClientInformationFull | undefined {
    const row = getStmt.get(clientId) as { metadata: string } | undefined;
    if (!row) return undefined;
    return JSON.parse(row.metadata) as OAuthClientInformationFull;
  }

  // The SDK's registration handler generates client_id/issued_at and passes the
  // full client object; we persist it verbatim after validating redirect URIs.
  registerClient(client: OAuthClientInformationFull): OAuthClientInformationFull {
    // Log every DCR attempt (incl. the requested redirect_uris) so a rejected
    // client — e.g. a new connector whose callback isn't yet allow-listed — is
    // observable and its exact redirect_uri can be added to EXTRA_REDIRECT_URIS.
    logger.info(
      { client_name: client.client_name, redirect_uris: client.redirect_uris },
      'DCR attempt',
    );
    for (const uri of client.redirect_uris) {
      if (!isAllowedRedirect(uri)) {
        logger.warn(
          { client_name: client.client_name, redirect_uri: uri },
          'DCR rejected: redirect_uri not allowed',
        );
        throw new InvalidClientMetadataError(`redirect_uri not allowed: ${uri}`);
      }
    }
    insertStmt.run(
      client.client_id,
      JSON.stringify(client),
      client.client_id_issued_at ?? nowSec(),
      nowSec(),
    );
    logger.info(
      { client_id: client.client_id, client_name: client.client_name, redirect_uris: client.redirect_uris },
      'registered oauth client (DCR)',
    );
    return client;
  }
}
