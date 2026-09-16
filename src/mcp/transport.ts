import { randomUUID } from 'node:crypto';
import type { Request, Response } from 'express';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest, isJSONRPCRequest } from '@modelcontextprotocol/sdk/types.js';
import { buildMcpServer } from './server.js';
import { config } from '../config.js';
import { logger } from '../logger.js';

interface Session {
  owner: string;
  lastUsed: number;
  id?: string;
  server: McpServer;
  transport: StreamableHTTPServerTransport;
  closed: boolean;
  transportClosed: boolean;
  closePromise?: Promise<void>;
}

// Include pending initializations in the capacity limit, not just published IDs.
const sessions = new Set<Session>();
const sessionsById = new Map<string, Session>();
const closing = new Set<Promise<void>>();
let sweepTimer: ReturnType<typeof setInterval> | undefined;

/** Stable across access-token refresh; separate static and OAuth namespaces. */
export function authenticatedIdentity(req: Request): string | undefined {
  const auth = req.auth;
  const kind = auth?.extra?.auth;
  const subject = auth?.extra?.sub;
  if (
    (kind !== 'oauth' && kind !== 'static') ||
    typeof subject !== 'string' || !subject ||
    typeof auth?.clientId !== 'string' || !auth.clientId
  ) return undefined;
  return JSON.stringify([kind, subject, auth.clientId]);
}

function headerSessionId(req: Request): string | undefined {
  const sid = req.headers['mcp-session-id'];
  // Node joins duplicate headers with commas. Reject duplicates, arrays and
  // oversized values instead of accidentally selecting the first valid ID.
  return typeof sid === 'string' && sid.length <= 128 && /^[A-Za-z0-9_-]+$/.test(sid)
    ? sid : undefined;
}

function reject(res: Response, status: number, message: string): void {
  res.status(status).json({ jsonrpc: '2.0', error: { code: -32000, message }, id: null });
}

function release(session: Session): void {
  session.closed = true;
  sessions.delete(session);
  if (session.id && sessionsById.get(session.id) === session) sessionsById.delete(session.id);
  if (!sessions.size && sweepTimer) {
    clearInterval(sweepTimer);
    sweepTimer = undefined;
  }
}

function closeSession(session: Session): Promise<void> {
  if (session.closePromise) return session.closePromise;
  // Stop accepting requests and release capacity before any asynchronous cleanup.
  release(session);
  const promise = Promise.resolve().then(async () => {
    try {
      await session.server.close();
    } catch {
      logger.warn('MCP server close failed');
    } finally {
      // Also cover connect() failures before the SDK took transport ownership.
      if (!session.transportClosed) {
        try {
          await session.transport.close();
        } catch {
          logger.warn('MCP transport close failed');
        }
      }
    }
  });
  session.closePromise = promise;
  closing.add(promise);
  void promise.finally(() => closing.delete(promise));
  return promise;
}

function expireSessions(): void {
  const now = Date.now();
  for (const session of sessions) {
    if (now - session.lastUsed >= config.MCP_SESSION_TTL_MS) void closeSession(session);
  }
}

function startSweeper(): void {
  if (sweepTimer) return;
  sweepTimer = setInterval(expireSessions, Math.min(config.MCP_SESSION_TTL_MS, 60_000));
  sweepTimer.unref();
}

function existingSession(req: Request, res: Response, owner: string): Session | undefined {
  if (req.headers['mcp-session-id'] === undefined) {
    reject(res, 400, 'Missing session ID');
    return undefined;
  }
  const id = headerSessionId(req);
  const session = id ? sessionsById.get(id) : undefined;
  // Do not disclose whether a session exists for a different principal.
  if (!session || session.closed || session.owner !== owner) {
    reject(res, 404, 'Session not found');
    return undefined;
  }
  session.lastUsed = Date.now();
  return session;
}

/** POST /mcp — client->server JSON-RPC, including the initialize handshake. */
export async function handleMcpPost(req: Request, res: Response): Promise<void> {
  const owner = authenticatedIdentity(req);
  if (!owner) {
    reject(res, 401, 'Authentication required');
    return;
  }
  expireSessions();
  if (req.headers['mcp-session-id'] !== undefined) {
    const session = existingSession(req, res, owner);
    if (session) await session.transport.handleRequest(req, res, req.body);
    return;
  }
  // The SDK's initialize schema alone also accepts notifications (missing id).
  // Those return 202 without exposing a session ID and would leak capacity.
  if (!isJSONRPCRequest(req.body) || !isInitializeRequest(req.body)) {
    reject(res, 400, 'Missing session ID: initialize a session first');
    return;
  }

  const owned = [...sessions].filter((session) => session.owner === owner).length;
  if (sessions.size >= config.MCP_MAX_SESSIONS || owned >= config.MCP_MAX_SESSIONS_PER_CLIENT) {
    reject(res, 429, 'Session limit exceeded');
    return;
  }

  const server = buildMcpServer();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    onsessioninitialized: (id) => {
      if (session.closed) throw new Error('Session closed during initialization');
      session.id = id;
      sessionsById.set(id, session);
      logger.debug('MCP session initialized');
    },
  });
  const session: Session = {
    owner, lastUsed: Date.now(), server, transport, closed: false, transportClosed: false,
  };
  // Use the protocol-level close callback: connect() owns transport callbacks.
  // SDK close first clears request handlers/aborts in-flight requests, then runs this.
  server.server.onclose = () => {
    session.transportClosed = true;
    release(session);
    logger.debug('MCP session closed');
  };
  // Reserve synchronously before connect/handleRequest can yield to another request.
  sessions.add(session);
  startSweeper();
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    await closeSession(session);
    throw error;
  } finally {
    if (!session.id || res.statusCode >= 400) await closeSession(session);
  }
}

/** GET (SSE stream) and DELETE (teardown) for an existing session. */
export async function handleMcpSessionRequest(req: Request, res: Response): Promise<void> {
  const owner = authenticatedIdentity(req);
  if (!owner) {
    reject(res, 401, 'Authentication required');
    return;
  }
  expireSessions();
  const session = existingSession(req, res, owner);
  if (session) await session.transport.handleRequest(req, res);
}

export async function closeAllTransports(): Promise<void> {
  const pending = [...sessions].map(closeSession);
  await Promise.all([...pending, ...closing]);
}
