import { SignJWT, jwtVerify } from 'jose';
import { z } from 'zod';
import { config, OWNER_USER_ID, SUPPORTED_SCOPES } from '../config.js';
import { randomToken } from '../util.js';

const secret = new TextEncoder().encode(config.JWT_SECRET);
const ALG = 'HS256';
const CONSENT_AUDIENCE = 'urn:renderfetch-mcp:consent';
const identifier = z.string().min(1).max(256);
const scopeList = z.array(z.enum(['mcp:fetch', 'offline_access'])).max(SUPPORTED_SCOPES.length);
const commonClaims = z.object({
  iat: z.number().int().nonnegative(),
  exp: z.number().int().positive(),
  jti: identifier,
});

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
  const token = await new SignJWT({ scope: claims.scopes.join(' '), client_id: claims.clientId })
    .setProtectedHeader({ alg: ALG, typ: 'at+jwt' })
    .setSubject(claims.userId ?? OWNER_USER_ID)
    .setIssuer(config.issuerUrl.href)
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
    typ: 'at+jwt',
    requiredClaims: ['sub', 'client_id', 'scope', 'iat', 'exp', 'jti'],
  });
  const claims = commonClaims.extend({
    sub: identifier,
    client_id: identifier,
    scope: z.string().max(256),
    aud: z.literal(config.resourceUrl.href),
  }).parse(payload);
  if (claims.exp <= claims.iat || claims.iat > Math.floor(Date.now() / 1000)) {
    throw new Error('Invalid access token timestamps');
  }
  const scopes = scopeList.parse(claims.scope ? claims.scope.split(' ') : []);
  return {
    sub: claims.sub,
    clientId: claims.client_id,
    scopes,
    expSec: claims.exp,
    resource: config.resourceUrl.href,
  };
}

// Signed authorization-request state, distinct from access tokens by audience/type.
export interface ConsentRequest {
  clientId: string;
  clientName?: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  state?: string;
  resource?: string;
}

export interface VerifiedConsentRequest extends ConsentRequest {
  jti: string;
  expiresAt: number;
}

export async function signConsentRequest(req: ConsentRequest): Promise<string> {
  return new SignJWT({ ...req })
    .setProtectedHeader({ alg: ALG, typ: 'consent+jwt' })
    .setIssuer(config.issuerUrl.href)
    .setAudience(CONSENT_AUDIENCE)
    .setIssuedAt()
    .setJti(randomToken(16))
    .setExpirationTime(`${config.CONSENT_REQUEST_TTL}s`)
    .sign(secret);
}

export async function verifyConsentRequest(token: string): Promise<VerifiedConsentRequest> {
  const { payload } = await jwtVerify(token, secret, {
    issuer: config.issuerUrl.href,
    audience: CONSENT_AUDIENCE,
    algorithms: [ALG],
    typ: 'consent+jwt',
    requiredClaims: ['iat', 'exp', 'jti', 'clientId', 'redirectUri', 'codeChallenge', 'scopes'],
  });
  const claims = commonClaims.extend({
    clientId: identifier,
    clientName: z.string().max(256).optional(),
    redirectUri: z.string().url().max(2048),
    codeChallenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    scopes: scopeList,
    state: z.string().max(2048).optional(),
    resource: z.literal(config.resourceUrl.href).optional(),
  }).parse(payload);
  if (claims.exp <= claims.iat || claims.iat > Math.floor(Date.now() / 1000)) {
    throw new Error('Invalid consent token timestamps');
  }
  return {
    clientId: claims.clientId,
    clientName: claims.clientName,
    redirectUri: claims.redirectUri,
    codeChallenge: claims.codeChallenge,
    scopes: claims.scopes,
    state: claims.state,
    resource: claims.resource,
    jti: claims.jti,
    expiresAt: claims.exp,
  };
}
