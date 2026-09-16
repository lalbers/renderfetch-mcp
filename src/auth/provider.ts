import type { Response } from 'express';
import type {
  OAuthServerProvider,
  AuthorizationParams,
} from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type {
  OAuthClientInformationFull,
  OAuthTokens,
  OAuthTokenRevocationRequest,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import {
  InvalidRequestError,
  InvalidScopeError,
  InvalidGrantError,
  InvalidTokenError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { config, SUPPORTED_SCOPES } from '../config.js';
import { logger } from '../logger.js';
import { SqliteClientsStore } from '../store/clients.js';
import { getAuthCode, consumeAuthCode } from '../store/codes.js';
import {
  createRefreshToken,
  getRefreshTokenRow,
  rotateRefreshToken,
  revokeRefreshToken,
  revokeRefreshTokenFamily,
} from '../store/tokens.js';
import { signAccessToken, verifyAccessTokenJwt } from './jwt.js';
import { signConsentRequest } from './jwt.js';
import { nowSec } from '../util.js';

const stripSlash = (s: string) => s.replace(/\/$/, '');

/** A requested resource is acceptable if absent or equal to our canonical one. */
function resourceMatches(resource?: URL): boolean {
  if (!resource) return true;
  return stripSlash(resource.href) === stripSlash(config.resourceUrl.href);
}

export class RenderfetchOAuthProvider implements OAuthServerProvider {
  readonly clientsStore = new SqliteClientsStore();

  // skipLocalPkceValidation left undefined => the SDK token handler validates
  // PKCE locally using challengeForAuthorizationCode(), and passes us no verifier.

  /**
   * Called by the SDK /authorize handler after it has validated the client and
   * redirect_uri. We do NOT mint a code here — instead we hand off to our own
   * login + consent page (req parameters travel in a signed token).
   */
  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response,
  ): Promise<void> {
    // The SDK's /authorize handler already validated redirect_uri against the
    // registered set (including RFC 8252 loopback port flexibility), so we do
    // NOT re-check it exactly here — that would reject legitimate loopback
    // clients (Claude Code / MCP Inspector) that use an ephemeral port.
    if (!resourceMatches(params.resource)) {
      throw new InvalidRequestError(`Unsupported resource: ${params.resource?.href ?? ''}`);
    }
    const requestedScopes = params.scopes?.length ? params.scopes : ['mcp:fetch'];
    if (!requestedScopes.includes('mcp:fetch') || requestedScopes.some((scope) => !SUPPORTED_SCOPES.includes(scope))) {
      throw new InvalidScopeError('mcp:fetch is required; unsupported scopes are not allowed');
    }
    if (!/^[A-Za-z0-9_-]{43}$/.test(params.codeChallenge)) {
      throw new InvalidRequestError('A valid S256 code challenge is required');
    }
    if ((params.state?.length ?? 0) > 2048) throw new InvalidRequestError('state is too long');
    const reqToken = await signConsentRequest({
      clientId: client.client_id,
      clientName: client.client_name,
      redirectUri: params.redirectUri,
      codeChallenge: params.codeChallenge,
      scopes: [...new Set(requestedScopes)],
      state: params.state,
      resource: config.resourceUrl.href,
    });
    res.redirect(302, `/consent?req=${encodeURIComponent(reqToken)}`);
  }

  async challengeForAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
  ): Promise<string> {
    const code = getAuthCode(authorizationCode);
    if (!code || code.clientId !== client.client_id) throw new InvalidGrantError('Invalid or expired authorization code');
    return code.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string, // PKCE already verified by the SDK token handler
    redirectUri?: string,
    resource?: URL,
  ): Promise<OAuthTokens> {
    const code = getAuthCode(authorizationCode);
    if (!code) throw new InvalidGrantError('Invalid or expired authorization code');
    if (code.clientId !== client.client_id) {
      throw new InvalidGrantError('Authorization code was not issued to this client');
    }
    if (redirectUri !== undefined && redirectUri !== code.redirectUri) {
      throw new InvalidGrantError('redirect_uri does not match the authorization request');
    }
    if (!resourceMatches(resource)) {
      throw new InvalidRequestError('resource does not match the authorization request');
    }
    // An old grant must not silently migrate to a different server/resource.
    if (code.resource !== config.resourceUrl.href || !code.scopes.includes('mcp:fetch') ||
        new Set(code.scopes).size !== code.scopes.length || code.scopes.some((scope) => !SUPPORTED_SCOPES.includes(scope))) {
      throw new InvalidGrantError('Authorization grant is no longer valid; authorize again');
    }
    if (!consumeAuthCode(authorizationCode)) throw new InvalidGrantError('Authorization code was already consumed');
    return this.issueTokens(client.client_id, code.scopes, code.userId);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL,
  ): Promise<OAuthTokens> {
    const row = getRefreshTokenRow(refreshToken);
    if (!row) throw new InvalidGrantError('Invalid refresh token');
    if (row.clientId !== client.client_id) {
      throw new InvalidGrantError('Refresh token was not issued to this client');
    }
    if (row.revoked) {
      // Replay of an already-rotated/revoked refresh token => possible theft.
      // Revoke only this authorization grant (RFC 9700 reuse detection).
      revokeRefreshTokenFamily(row.familyId, row.clientId);
      logger.warn(
        { client_id: row.clientId },
        'refresh token reuse detected; revoked grant family',
      );
      throw new InvalidGrantError('Refresh token has been revoked');
    }
    if (row.expiresAt <= nowSec()) throw new InvalidGrantError('Refresh token expired');
    if (!resourceMatches(resource)) {
      throw new InvalidRequestError('resource does not match the original grant');
    }
    if (row.resource !== config.resourceUrl.href || !row.scopes.includes('mcp:fetch') ||
        !row.scopes.includes('offline_access') || new Set(row.scopes).size !== row.scopes.length || row.scopes.some((scope) => !SUPPORTED_SCOPES.includes(scope))) {
      throw new InvalidGrantError('Refresh grant is no longer valid; authorize again');
    }
    // Down-scope only (requested scopes must be a subset of the original grant).
    let grantScopes = row.scopes;
    if (scopes !== undefined) {
      if (!scopes.includes('mcp:fetch')) throw new InvalidScopeError('mcp:fetch is required');
      for (const s of scopes) {
        if (!row.scopes.includes(s)) {
          throw new InvalidGrantError(`scope was not originally granted: ${s}`);
        }
      }
      grantScopes = [...new Set(scopes)];
    }
    // Rotate the refresh token (mandatory for public clients): the new token is
    // returned and the old one is revoked + linked in the same transaction.
    let newRefresh: string | undefined;
    if (grantScopes.includes('offline_access')) {
      newRefresh = rotateRefreshToken(refreshToken, {
        clientId: client.client_id,
        scopes: grantScopes,
        resource: config.resourceUrl.href,
        userId: row.userId,
        ttlSeconds: config.REFRESH_TOKEN_TTL, // rotation retains the original absolute expiry
      });
      if (!newRefresh) {
        revokeRefreshTokenFamily(row.familyId, client.client_id);
        throw new InvalidGrantError('Refresh token was already consumed');
      }
    } else if (!revokeRefreshToken(refreshToken, client.client_id)) {
      revokeRefreshTokenFamily(row.familyId, client.client_id);
      throw new InvalidGrantError('Refresh token was already consumed');
    }
    const at = await signAccessToken({
      clientId: client.client_id,
      scopes: grantScopes,
      userId: row.userId,
    });
    logger.info({ client_id: client.client_id }, 'refresh token rotated');
    return {
      access_token: at.token,
      token_type: 'bearer',
      expires_in: at.expiresIn,
      scope: grantScopes.join(' '),
      refresh_token: newRefresh,
    };
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    try {
      const v = await verifyAccessTokenJwt(token);
      return {
        token,
        clientId: v.clientId,
        scopes: v.scopes,
        expiresAt: v.expSec,
        resource: new URL(v.resource),
        extra: { auth: 'oauth', sub: v.sub },
      };
    } catch {
      // Surface as a 401 with WWW-Authenticate (handled by requireBearerAuth).
      throw new InvalidTokenError('Token is invalid or expired');
    }
  }

  // Advertising this method makes mcpAuthRouter mount /revoke and the
  // revocation_endpoint in metadata.
  async revokeToken(
    client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest,
  ): Promise<void> {
    if (!request.token) return;
    const row = getRefreshTokenRow(request.token);
    if (row?.clientId === client.client_id) revokeRefreshTokenFamily(row.familyId, client.client_id);
  }

  private async issueTokens(
    clientId: string,
    scopes: string[],
    userId: string,
  ): Promise<OAuthTokens> {
    const refresh = scopes.includes('offline_access') ? createRefreshToken({
      clientId,
      scopes,
      resource: config.resourceUrl.href,
      userId,
      ttlSeconds: config.REFRESH_TOKEN_TTL,
    }) : undefined;
    const at = await signAccessToken({ clientId, scopes, userId });
    return {
      access_token: at.token,
      token_type: 'bearer',
      expires_in: at.expiresIn,
      scope: scopes.join(' '),
      refresh_token: refresh,
    };
  }
}
