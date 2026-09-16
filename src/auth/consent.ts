import express, { Router, type Response } from 'express';
import { rateLimit } from 'express-rate-limit';
import { config, OWNER_USER_ID } from '../config.js';
import { logger } from '../logger.js';
import { verifyConsentRequest, type VerifiedConsentRequest } from './jwt.js';
import { createAuthCodeForConsent, consumeConsent } from '../store/codes.js';
import { isAllowedRedirect } from '../store/clients.js';
import { htmlEscape, timingSafeEqualStr } from '../util.js';

export const consentRouter = Router();

// Online-guessing protection: the whole model rests on one credential, so cap
// login attempts (the SDK rate-limits /authorize|/token|/register, not /consent).
const consentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many attempts. Please try again later.',
});

// Consent carries credentials and a signed authorization request: never cache,
// embed, or leak its query string to another origin.
consentRouter.use('/consent', (_req, res, next) => {
  res.set({
    'Cache-Control': 'no-store',
    Pragma: 'no-cache',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  });
  next();
});

function allowConsentCallback(res: Response, redirectUri: string): void {
  // no-referrer makes Chromium send Origin:null for form POSTs. same-origin
  // preserves the CSRF origin check while still hiding the consent URL from
  // every external callback (including its signed request query parameter).
  res.set('Referrer-Policy', 'same-origin');
  // Chromium applies form-action to POST redirects too. Permit only this signed,
  // validated callback origin, not arbitrary external form destinations.
  res.set('Content-Security-Policy', `default-src 'none'; style-src 'unsafe-inline'; form-action 'self' ${new URL(redirectUri).origin}; base-uri 'none'; frame-ancestors 'none'`);
}

function layout(title: string, body: string): string {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${htmlEscape(title)}</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; max-width: 28rem; margin: 3rem auto; padding: 0 1rem; line-height: 1.5; }
  .card { border: 1px solid #8884; border-radius: 12px; padding: 1.25rem 1.5rem; }
  h1 { font-size: 1.25rem; margin-top: 0; }
  .host { font-weight: 600; word-break: break-all; }
  .scopes { font-size: .9rem; color: #888; }
  label { display: block; margin: .75rem 0 .25rem; font-size: .9rem; }
  input[type=text], input[type=password] { width: 100%; padding: .55rem; border: 1px solid #8886; border-radius: 8px; box-sizing: border-box; }
  .row { display: flex; gap: .75rem; margin-top: 1.25rem; }
  button { flex: 1; padding: .6rem; border-radius: 8px; border: 0; font-size: 1rem; cursor: pointer; }
  .approve { background: #2563eb; color: #fff; }
  .deny { background: #8883; }
  .err { color: #dc2626; font-size: .9rem; margin-top: .5rem; }
  .muted { color: #888; font-size: .8rem; }
</style>
</head><body><div class="card">${body}</div></body></html>`;
}

function errorPage(message: string): string {
  return layout('Authorization error', `<h1>Authorization error</h1><p>${htmlEscape(message)}</p>`);
}

function consentPage(reqToken: string, cr: VerifiedConsentRequest, error: string | null): string {
  let redirectHost = '(unknown)';
  try {
    redirectHost = new URL(cr.redirectUri).host;
  } catch {
    /* validated elsewhere */
  }
  const client = cr.clientName || cr.clientId;
  const scopeList = cr.scopes.length ? cr.scopes.join(', ') : '(none requested)';
  return layout(
    'Authorize connection',
    `
    <h1>Authorize connection</h1>
    <p><strong>${htmlEscape(client)}</strong> wants to connect to your web-fetch MCP server.</p>
    <p class="muted">After approval you will be returned to:<br><span class="host">${htmlEscape(redirectHost)}</span></p>
    <p class="scopes">Requested access: ${htmlEscape(scopeList)}</p>
    ${error ? `<p class="err">${htmlEscape(error)}</p>` : ''}
    <form method="post" action="/consent" autocomplete="off">
      <input type="hidden" name="req" value="${htmlEscape(reqToken)}">
      <label for="u">Username</label>
      <input id="u" type="text" name="username" autocomplete="username" required>
      <label for="p">Password</label>
      <input id="p" type="password" name="password" autocomplete="current-password" required>
      <div class="row">
        <button class="approve" type="submit" name="action" value="approve">Approve</button>
        <button class="deny" type="submit" name="action" value="deny">Deny</button>
      </div>
    </form>
    <p class="muted">Only approve if you started this connection.</p>
    `,
  );
}

consentRouter.get('/consent', async (req, res) => {
  const reqToken = typeof req.query.req === 'string' ? req.query.req : '';
  try {
    const cr = await verifyConsentRequest(reqToken);
    if (!isAllowedRedirect(cr.redirectUri)) throw new Error('Invalid redirect target');
    allowConsentCallback(res, cr.redirectUri);
    res.type('html').send(consentPage(reqToken, cr, null));
  } catch {
    res
      .status(400)
      .type('html')
      .send(errorPage('This authorization request is invalid or has expired. Start the connection again from your client.'));
  }
});

consentRouter.post('/consent', consentLimiter, express.urlencoded({ extended: false, limit: '16kb', parameterLimit: 8 }), async (req, res) => {
  // Form submissions must originate from this consent UI, not another website.
  let origin = req.headers.origin;
  if (origin === undefined && req.headers.referer) {
    try { origin = new URL(req.headers.referer).origin; } catch { /* rejected below */ }
  }
  if (origin !== config.issuerUrl.origin) {
    res.status(403).type('html').send(errorPage('Invalid consent origin.'));
    return;
  }
  const reqToken = typeof req.body?.req === 'string' ? req.body?.req : '';
  let cr: VerifiedConsentRequest;
  try {
    cr = await verifyConsentRequest(reqToken);
  } catch {
    res.status(400).type('html').send(errorPage('This authorization request is invalid or has expired.'));
    return;
  }

  // Defensive re-check (the redirect_uri was validated at registration + /authorize).
  if (!isAllowedRedirect(cr.redirectUri)) {
    res.status(400).type('html').send(errorPage('Invalid redirect target.'));
    return;
  }

  allowConsentCallback(res, cr.redirectUri);
  const action = String(req.body?.action ?? '');
  if (action !== 'approve') {
    if (action !== 'deny' || !consumeConsent(cr.jti, cr.expiresAt)) {
      res.status(400).type('html').send(errorPage('This authorization request is invalid or already completed.'));
      return;
    }
    const url = new URL(cr.redirectUri);
    url.searchParams.set('error', 'access_denied');
    if (cr.state) url.searchParams.set('state', cr.state);
    logger.info({ client_id: cr.clientId }, 'consent denied');
    res.redirect(302, url.toString());
    return;
  }

  const username = String(req.body?.username ?? '');
  const password = String(req.body?.password ?? '');
  const userOk = timingSafeEqualStr(username, config.AUTH_USERNAME);
  const passOk = timingSafeEqualStr(password, config.AUTH_PASSWORD);
  if (!(userOk && passOk)) {
    logger.warn({ client_id: cr.clientId }, 'consent login failed');
    res.status(401).type('html').send(consentPage(reqToken, cr, 'Incorrect username or password.'));
    return;
  }

  const code = createAuthCodeForConsent(cr.jti, cr.expiresAt, {
    clientId: cr.clientId,
    redirectUri: cr.redirectUri,
    codeChallenge: cr.codeChallenge,
    scopes: cr.scopes,
    resource: cr.resource,
    userId: OWNER_USER_ID,
    ttlSeconds: config.AUTH_CODE_TTL,
  });
  if (!code) {
    res.status(400).type('html').send(errorPage('This authorization request has already been completed. Start the connection again from your client.'));
    return;
  }
  const url = new URL(cr.redirectUri);
  url.searchParams.set('code', code);
  if (cr.state) url.searchParams.set('state', cr.state);
  logger.info(
    { client_id: cr.clientId, redirect_host: new URL(cr.redirectUri).host },
    'consent approved, authorization code issued',
  );
  res.redirect(302, url.toString());
});
