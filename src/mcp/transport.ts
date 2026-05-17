import { randomUUID } from 'node:crypto';
import type { Request, Response } from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { buildMcpServer } from './server.js';
import { logger } from '../logger.js';

const transports = new Map<string, StreamableHTTPServerTransport>();

function headerSessionId(req: Request): string | undefined {
  const sid = req.headers['mcp-session-id'];
  return Array.isArray(sid) ? sid[0] : sid;
}

/** POST /mcp — client->server JSON-RPC, including the initialize handshake. */
export async function handleMcpPost(req: Request, res: Response): Promise<void> {
  const sessionId = headerSessionId(req);
  let transport = sessionId ? transports.get(sessionId) : undefined;

  if (!transport) {
    // A new session may only start with an initialize request and no session id.
    if (sessionId || !isInitializeRequest(req.body)) {
      res.status(400).json({
        jsonrpc: '2.0',
        error: { code: -32000, message: 'Bad Request: no valid session ID, and not an initialize request' },
        id: null,
      });
      return;
    }
    const newTransport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (id) => {
        transports.set(id, newTransport);
        logger.info({ session: id }, 'mcp session initialized');
      },
    });
    newTransport.onclose = () => {
      if (newTransport.sessionId) {
        transports.delete(newTransport.sessionId);
        logger.info({ session: newTransport.sessionId }, 'mcp session closed');
      }
    };
    const server = buildMcpServer();
    await server.connect(newTransport); // connect BEFORE handling the request
    transport = newTransport;
  }

  await transport.handleRequest(req, res, req.body);
}

/** GET (SSE stream) and DELETE (teardown) for an existing session. */
export async function handleMcpSessionRequest(req: Request, res: Response): Promise<void> {
  const sessionId = headerSessionId(req);
  const transport = sessionId ? transports.get(sessionId) : undefined;
  if (!transport) {
    res.status(400).send('Invalid or missing session ID');
    return;
  }
  await transport.handleRequest(req, res);
}

export async function closeAllTransports(): Promise<void> {
  for (const t of transports.values()) {
    try {
      await t.close();
    } catch {
      /* ignore */
    }
  }
  transports.clear();
}
