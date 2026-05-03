import { SignJWT, jwtVerify } from 'jose';
import { config, OWNER_USER_ID } from '../config.js';
import { randomToken } from '../util.js';

const secret = new TextEncoder().encode(config.JWT_SECRET);
const ALG = 'HS256';
const CONSENT_AUDIENCE = 'urn:renderfetch-mcp:consent';

// --- Access tokens (stateless, audience-bound JWTs) -------------------------

export interface AccessTokenClaims {
  clientId: string;
  scopes: string[];
  userId?: string;
}

export interface IssuedAccessToken {
  token: string;
  expiresIn: number;
  jti: string;
}

export async function signAccessToken(claims: AccessTokenClaims): Promise<IssuedAccessToken> {
  const jti = randomToken(16);
  const expiresIn = config.ACCESS_TOKEN_TTL;
  const token = await new SignJWT({
    scope: claims.scopes.join(' '),
    client_id: claims.clientId,
  })
    .setProtectedHeader({ alg: ALG, typ: 'at+jwt' })
    .setSubject(claims.userId ?? OWNER_USER_ID)
    .setIssuer(config.issuerUrl.href)
    // Audience is ALWAYS our canonical resource (RFC 8707). verifyAccessTokenJwt
    // enforces it, so a token minted for another resource cannot be replayed here.
    .setAudience(config.resourceUrl.href)
    .setIssuedAt()
    .setJti(jti)
    .setExpirationTime(`${expiresIn}s`)
    .sign(secret);
  return { token, expiresIn, jti };
}

export interface VerifiedAccessToken {
  sub: string;
  clientId: string;
  scopes: string[];
  expSec: number;
  resource: string;
}

export async function verifyAccessTokenJwt(token: string): Promise<VerifiedAccessToken> {
  const { payload } = await jwtVerify(token, secret, {
    issuer: config.issuerUrl.href,
    audience: config.resourceUrl.href,
    algorithms: [ALG],
  });
  const scope = typeof payload.scope === 'string' ? payload.scope : '';
  const aud = Array.isArray(payload.aud) ? payload.aud[0] : payload.aud;
  return {
    sub: typeof payload.sub === 'string' ? payload.sub : OWNER_USER_ID,
    clientId: typeof payload.client_id === 'string' ? payload.client_id : 'unknown',
    scopes: scope ? scope.split(' ') : [],
    expSec: typeof payload.exp === 'number' ? payload.exp : 0,
    resource: typeof aud === 'string' ? aud : config.resourceUrl.href,
  };
}

// --- Consent-request tokens (short-lived, signed authorization request) -----
// Carries the validated authorization request across the login/consent page so
// the parameters cannot be tampered with between /authorize and /consent.

export interface ConsentRequest {
  clientId: string;
  clientName?: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  state?: string;
  resource?: string;
  jti?: string; // populated on verify; used for one-time-use enforcement
}

export async function signConsentRequest(req: ConsentRequest): Promise<string> {
  return new SignJWT({
    clientId: req.clientId,
    clientName: req.clientName,
    redirectUri: req.redirectUri,
    codeChallenge: req.codeChallenge,
    scopes: req.scopes,
    state: req.state,
    resource: req.resource,
  })
    .setProtectedHeader({ alg: ALG, typ: 'consent+jwt' })
    .setIssuer(config.issuerUrl.href)
    .setAudience(CONSENT_AUDIENCE)
    .setIssuedAt()
    .setJti(randomToken(12))
    .setExpirationTime(`${config.CONSENT_REQUEST_TTL}s`)
    .sign(secret);
}

export async function verifyConsentRequest(token: string): Promise<ConsentRequest> {
  const { payload } = await jwtVerify(token, secret, {
    issuer: config.issuerUrl.href,
    audience: CONSENT_AUDIENCE,
    algorithms: [ALG],
  });
  return {
    clientId: String(payload.clientId),
    clientName: payload.clientName ? String(payload.clientName) : undefined,
    redirectUri: String(payload.redirectUri),
    codeChallenge: String(payload.codeChallenge),
    scopes: Array.isArray(payload.scopes) ? payload.scopes.map(String) : [],
    state: payload.state ? String(payload.state) : undefined,
    resource: payload.resource ? String(payload.resource) : undefined,
    jti: typeof payload.jti === 'string' ? payload.jti : undefined,
  };
}
