import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import cors from 'cors';
import { rateLimit } from 'express-rate-limit';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { config, SUPPORTED_SCOPES } from './config.js';
import { logger } from './logger.js';
import { sha256hex } from './util.js';
import { RenderfetchOAuthProvider } from './auth/provider.js';
import { consentRouter } from './auth/consent.js';
import { buildAuthMiddleware } from './auth/bearer.js';
import { authenticatedIdentity, handleMcpPost, handleMcpSessionRequest } from './mcp/transport.js';

// Forward async handler rejections to the Express error handler.
const wrap =
  (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction) =>
    fn(req, res).catch(next);

export function createApp(): Express {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.TRUST_PROXY.length ? config.TRUST_PROXY : false);

  // Unauthenticated health endpoint.
  app.get('/healthz', (_req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  const provider = new RenderfetchOAuthProvider();

  // Our login + consent UI — the front-end of /authorize.
  app.use(consentRouter);

  // OAuth 2.1 Authorization Server: /authorize, /token, /register (DCR),
  // /revoke, and RFC 8414 + RFC 9728 metadata at /.well-known/*.
  app.use(
    mcpAuthRouter({
      provider,
      issuerUrl: config.issuerUrl,
      baseUrl: config.issuerUrl,
      resourceServerUrl: config.resourceUrl,
      scopesSupported: SUPPORTED_SCOPES,
      resourceName: 'renderfetch-mcp',
      // Without this the SDK hands out 30-day client secrets; see
      // CLIENT_SECRET_TTL in config-schema.ts for why that is a trap.
      clientRegistrationOptions: { clientSecretExpirySeconds: config.CLIENT_SECRET_TTL },
    }),
  );

  // Validate before auth and preflight. An absent Origin is valid for server
  // clients, but a present Origin must exactly match a configured browser origin.
  const allowedOrigins = new Set([config.issuerUrl.origin, ...config.ALLOWED_ORIGINS]);
  app.use('/mcp', (req, res, next) => {
    const origin = req.headers.origin;
    if (origin !== undefined && (typeof origin !== 'string' || !allowedOrigins.has(origin))) {
      res.status(403).json({ jsonrpc: '2.0', error: { code: -32000, message: 'Origin not allowed' }, id: null });
      return;
    }
    next();
  });
  const corsMw = cors({
    origin: (origin, callback) => callback(null, origin !== undefined && allowedOrigins.has(origin)),
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'mcp-session-id',
      'mcp-protocol-version',
      'last-event-id',
    ],
    exposedHeaders: ['Mcp-Session-Id'],
    maxAge: 86400,
  });

  const auth = buildAuthMiddleware(provider);

  // Stable principal limit: refreshing an access token must not reset the bucket.
  const perIdentity = rateLimit({
    windowMs: config.RATE_LIMIT_WINDOW_MS,
    limit: config.RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    // Hash the authenticated tuple, never a token or an untrusted forwarding header.
    keyGenerator: (req: Request) => sha256hex(authenticatedIdentity(req) ?? 'unauthenticated'),
    message: { jsonrpc: '2.0', error: { code: -32000, message: 'Rate limit exceeded' }, id: null },
  });

  app.options('/mcp', corsMw, (_req, res) => {
    res.sendStatus(204);
  });
  app.post('/mcp', corsMw, auth, perIdentity, express.json({ limit: '4mb' }), wrap(handleMcpPost));
  app.get('/mcp', corsMw, auth, perIdentity, wrap(handleMcpSessionRequest));
  app.delete('/mcp', corsMw, auth, perIdentity, wrap(handleMcpSessionRequest));

  // 404 fallback.
  app.use((_req, res) => {
    res.status(404).json({ error: 'not_found' });
  });

  // Error handler.
  app.use((err: unknown, _req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) return next(err);
    const failure = typeof err === 'object' && err !== null
      ? err as { type?: unknown; status?: unknown; expose?: unknown } : {};
    const type = failure.type;
    // Body-parser can forward decoder errors without a `type` (e.g. bad gzip).
    const clientStatus = failure.expose === true ? failure.status : undefined;
    if (type === 'entity.too.large' || clientStatus === 413) {
      res.status(413).json({ jsonrpc: '2.0', error: { code: -32600, message: 'Request body too large' }, id: null });
      return;
    }
    if (type === 'entity.parse.failed' || type === 'request.size.invalid' || type === 'request.aborted' || clientStatus === 400) {
      res.status(400).json({ jsonrpc: '2.0', error: { code: -32700, message: 'Invalid request body' }, id: null });
      return;
    }
    if (type === 'encoding.unsupported' || type === 'charset.unsupported' || clientStatus === 415) {
      res.status(415).json({ jsonrpc: '2.0', error: { code: -32600, message: 'Unsupported request encoding' }, id: null });
      return;
    }
    logger.error({ err }, 'unhandled request error');
    res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal error' }, id: null });
  });

  return app;
}
