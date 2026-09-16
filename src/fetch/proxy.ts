import { createServer, request as httpRequest, type IncomingHttpHeaders, type IncomingMessage } from 'node:http';
import { connect, type Socket } from 'node:net';
import type { Duplex } from 'node:stream';
import { config } from '../config.js';
import { FetchGuardError, parseFetchUrl, resolveFetchTarget } from './guard.js';

export interface EgressProxyOptions {
  allowPrivate?: boolean;
  allowedPorts?: readonly number[];
  lookup?: (hostname: string) => Promise<Array<{ address: string; family: number }>>;
  dnsTimeoutMs?: number;
  timeoutMs?: number;
  maxRequests?: number;
  maxBytes?: number;
  maxSockets?: number;
}

export interface EgressProxy {
  url: string;
  /** Fatal quota/deadline error, if any. Policy-denied subresources are not fatal. */
  failure: Error | undefined;
  close(): Promise<void>;
}

const HOP_HEADERS = new Set([
  'connection', 'proxy-connection', 'keep-alive', 'proxy-authenticate',
  'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade',
]);

function forwardHeaders(headers: IncomingHttpHeaders): IncomingHttpHeaders {
  const remove = new Set(HOP_HEADERS);
  for (const token of (headers.connection ?? '').split(',')) remove.add(token.trim().toLowerCase());
  return Object.fromEntries(Object.entries(headers).filter(([name]) => !remove.has(name)));
}

/** CONNECT accepts only an explicit host:port authority, never a URL/path/userinfo. */
export function parseConnectAuthority(authority: string, allowedPorts: readonly number[]): URL {
  if (!/^(?:\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+):[0-9]{1,5}$/.test(authority)) {
    throw new FetchGuardError('Invalid CONNECT authority');
  }
  const url = parseFetchUrl(`https://${authority}/`, { allowedPorts, allowPrivate: true });
  // The URL parser must not silently discard/reinterpret any authority component.
  const requestedPort = Number(authority.slice(authority.lastIndexOf(':') + 1));
  if (requestedPort < 1 || requestedPort > 65535 || requestedPort !== Number(url.port || 443)) {
    throw new FetchGuardError('Invalid CONNECT port');
  }
  return url;
}

/**
 * One job, one loopback-only proxy. DNS validation and socket connection share the
 * same numeric address. No pooling survives the job; CONNECT preserves end-to-end
 * TLS, including the browser's original SNI/certificate validation.
 */
export async function startEgressProxy(options: EgressProxyOptions = {}): Promise<EgressProxy> {
  const allowPrivate = options.allowPrivate ?? config.FETCH_ALLOW_PRIVATE;
  const allowedPorts = options.allowedPorts ?? config.FETCH_ALLOWED_PORTS;
  const timeoutMs = options.timeoutMs ?? config.FETCH_TIMEOUT_MS;
  const maxRequests = options.maxRequests ?? config.FETCH_MAX_REQUESTS;
  const maxBytes = options.maxBytes ?? config.FETCH_MAX_TRANSFER_BYTES;
  const maxSockets = options.maxSockets ?? 64;
  const sockets = new Set<Duplex>();
  let closed = false;
  let requests = 0;
  let bytes = 0;
  let closePromise: Promise<void> | undefined;
  let deadline: NodeJS.Timeout | undefined;
  const server = createServer({ maxHeaderSize: 16_384 });
  server.headersTimeout = Math.min(timeoutMs, 10_000);
  server.requestTimeout = timeoutMs;
  server.keepAliveTimeout = 1_000;

  const result: EgressProxy = {
    url: '',
    failure: undefined,
    close() {
      if (closePromise) return closePromise;
      closed = true;
      clearTimeout(deadline);
      for (const socket of sockets) socket.destroy();
      closePromise = new Promise<void>((resolve) => server.close(() => resolve()));
      return closePromise;
    },
  };

  function fail(message: string): void {
    result.failure ??= new Error(message);
    void result.close();
  }
  function track(socket: Duplex): boolean {
    if (closed || sockets.size >= maxSockets) {
      socket.destroy();
      if (!closed) fail('Browser connection limit exceeded');
      return false;
    }
    sockets.add(socket);
    socket.on('error', () => {}); // Deliberately do not echo remote data in errors.
    socket.once('close', () => sockets.delete(socket));
    socket.on('data', (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > maxBytes) fail('Browser transfer limit exceeded');
    });
    if ('setTimeout' in socket) (socket as Socket).setTimeout(Math.min(timeoutMs, 15_000), () => socket.destroy());
    return true;
  }
  function admit(): boolean {
    if (closed) return false;
    if (++requests > maxRequests) {
      fail('Browser request limit exceeded');
      return false;
    }
    return true;
  }
  async function resolve(url: URL) {
    const target = await resolveFetchTarget(url, {
      allowPrivate, allowedPorts,
      lookup: options.lookup,
      dnsTimeoutMs: options.dnsTimeoutMs,
    });
    if (closed) throw new Error('Browser request expired');
    return target;
  }

  server.on('connection', track);
  server.on('clientError', (_error, socket) => socket.destroy());
  server.on('upgrade', (_request, socket) => socket.destroy());
  // Browsers never need to negotiate Expect: 100-continue with this proxy.
  server.on('checkContinue', (_request, response) => { response.writeHead(417); response.end(); });
  server.on('request', (req, res) => {
    if (!admit()) { req.destroy(); return; }
    void (async () => {
      const url = parseFetchUrl(req.url ?? '', { allowedPorts, allowPrivate });
      if (url.protocol !== 'http:') throw new FetchGuardError('Use CONNECT for TLS');
      if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method ?? '')) throw new FetchGuardError('Unsupported HTTP method');
      const hostFields = req.rawHeaders.filter((_value, index) => index % 2 === 0 && req.rawHeaders[index]?.toLowerCase() === 'host');
      if (hostFields.length !== 1 || !req.headers.host || /[/\\?#@\s]/.test(req.headers.host)) {
        throw new FetchGuardError('Invalid Host authority');
      }
      const hostUrl = parseFetchUrl(`http://${req.headers.host}/`, { allowedPorts, allowPrivate });
      if (hostUrl.origin !== url.origin) throw new FetchGuardError('Ambiguous proxy authority');
      const target = await resolve(url);
      const headers = forwardHeaders(req.headers);
      headers.host = url.host;
      headers.connection = 'close';
      // A numeric hostname with agent:false cannot perform a second DNS lookup
      // or reuse a socket approved for a different request/host/job.
      const upstream = httpRequest({
        hostname: target.address, family: target.family, port: target.port,
        method: req.method, path: url.pathname + url.search,
        headers, agent: false, timeout: Math.min(timeoutMs, 15_000),
      });
      upstream.once('socket', track);
      upstream.once('timeout', () => upstream.destroy());
      upstream.once('error', () => {
        if (!res.headersSent) res.writeHead(502, { connection: 'close' });
        res.end();
      });
      req.once('aborted', () => upstream.destroy());
      res.once('close', () => upstream.destroy());
      upstream.once('response', (response: IncomingMessage) => {
        const outgoing = forwardHeaders(response.headers);
        outgoing.connection = 'close';
        res.writeHead(response.statusCode ?? 502, outgoing);
        response.once('error', () => res.destroy());
        response.pipe(res);
      });
      req.pipe(upstream);
    })().catch(() => {
      if (!res.headersSent) res.writeHead(403, { connection: 'close' });
      res.end();
    });
  });
  server.on('connect', (req, client, head) => {
    if (!admit()) { client.destroy(); return; }
    client.pause();
    void (async () => {
      const url = parseConnectAuthority(req.url ?? '', allowedPorts);
      const hostFields = req.rawHeaders.filter((_value, index) => index % 2 === 0 && req.rawHeaders[index]?.toLowerCase() === 'host');
      if (hostFields.length !== 1 || !req.headers.host || parseConnectAuthority(req.headers.host, allowedPorts).href !== url.href) {
        throw new FetchGuardError('Ambiguous CONNECT authority');
      }
      const target = await resolve(url);
      if (client.destroyed) return;
      const upstream = connect({ host: target.address, family: target.family, port: target.port });
      if (!track(upstream)) { client.destroy(); return; }
      upstream.once('error', () => client.destroy());
      client.once('error', () => upstream.destroy());
      client.once('close', () => upstream.destroy());
      upstream.once('close', () => client.destroy());
      upstream.once('connect', () => {
        if (closed || client.destroyed) { upstream.destroy(); return; }
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head.length) upstream.write(head);
        client.pipe(upstream);
        upstream.pipe(client);
        client.resume();
      });
    })().catch(() => {
      if (!client.destroyed) client.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  server.on('error', () => fail('Browser egress proxy unavailable'));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Cannot start browser egress proxy');
  result.url = `http://127.0.0.1:${address.port}`;
  deadline = setTimeout(() => fail('Browser request deadline exceeded'), timeoutMs);
  deadline.unref();
  return result;
}
