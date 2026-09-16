import type { RequestHandler } from 'express';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/sdk/server/auth/router.js';
import type { OAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import { config, OWNER_USER_ID, SUPPORTED_SCOPES } from '../config.js';
import { logger } from '../logger.js';
import { timingSafeEqualStr } from '../util.js';

/**
 * Dual auth for /mcp:
 *   1. Static bearer token (env) for headless/systemd Claude Code — checked
 *      first, constant-time. Disabled when OAUTH_ONLY=true or no token is set.
 *   2. OAuth 2.1 bearer (claude.ai + interactive Claude Code) via the SDK's
 *      requireBearerAuth, which validates the JWT and emits the proper
 *      401 + WWW-Authenticate(resource_metadata=...) challenge.
 */
export function buildAuthMiddleware(provider: OAuthServerProvider): RequestHandler {
  const oauth = requireBearerAuth({
    verifier: provider,
    requiredScopes: ['mcp:fetch'],
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(config.resourceUrl),
  });

  const staticEnabled = !config.OAUTH_ONLY && !!config.STATIC_BEARER_TOKEN;

  return (req, res, next) => {
    if (staticEnabled) {
      const header = req.headers.authorization;
      const match = header ? /^Bearer\s+(.+)$/i.exec(header) : null;
      const presented = match?.[1];
      if (presented && timingSafeEqualStr(presented, config.STATIC_BEARER_TOKEN as string)) {
        req.auth = {
          token: presented,
          clientId: 'static-bearer',
          scopes: SUPPORTED_SCOPES.filter((s) => s !== 'offline_access'),
          expiresAt: Math.floor(Date.now() / 1000) + 3600,
          resource: config.resourceUrl,
          extra: { auth: 'static', sub: OWNER_USER_ID },
        };
        logger.debug('authenticated via static bearer token');
        return next();
      }
    }
    return oauth(req, res, next);
  };
}
