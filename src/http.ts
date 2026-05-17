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
import { handleMcpPost, handleMcpSessionRequest } from './mcp/transport.js';

// Forward async handler rejections to the Express error handler.
const wrap =
  (fn: (req: Request, res: Response) => Promise<void>) =>
  (req: Request, res: Response, next: NextFunction) =>
    fn(req, res).catch(next);

export function createApp(): Express {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1); // exactly one hop in front: Traefik (X-Forwarded-*)

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
    }),
  );

  // CORS for browser-based MCP clients / the MCP Inspector. claude.ai calls the
  // server from its cloud (no CORS needed), but exposing Mcp-Session-Id is
  // mandatory for any browser client to read the session id.
  const corsMw = cors({
    origin: true,
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

  // Per-token rate limit (auth runs first, so req.auth is always set here).
  const perToken = rateLimit({
    windowMs: config.RATE_LIMIT_WINDOW_MS,
    limit: config.RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    // Key strictly on the token (auth runs first, so req.auth is always set);
    // never touch req.ip, so the library's IP/proxy validations don't apply.
    keyGenerator: (req: Request) => (req.auth ? sha256hex(req.auth.token) : 'anon'),
    message: { jsonrpc: '2.0', error: { code: -32000, message: 'Rate limit exceeded' }, id: null },
  });

  app.options('/mcp', corsMw, (_req, res) => {
    res.sendStatus(204);
  });
  app.post('/mcp', corsMw, auth, perToken, express.json({ limit: '4mb' }), wrap(handleMcpPost));
  app.get('/mcp', corsMw, auth, perToken, wrap(handleMcpSessionRequest));
  app.delete('/mcp', corsMw, auth, perToken, wrap(handleMcpSessionRequest));

  // 404 fallback.
  app.use((_req, res) => {
    res.status(404).json({ error: 'not_found' });
  });

  // Error handler.
  app.use((err: unknown, _req: Request, res: Response, next: NextFunction) => {
    logger.error({ err }, 'unhandled request error');
    if (res.headersSent) return next(err);
    res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal error' }, id: null });
  });

  return app;
}
