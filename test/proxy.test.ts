import { createServer as createHttpServer, request, type RequestListener } from 'node:http';
import { connect, createServer as createTcpServer, type Server, type Socket } from 'node:net';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { parseConnectAuthority, startEgressProxy, type EgressProxy, type EgressProxyOptions } from '../src/fetch/proxy.js';

const cleanups: Array<() => Promise<unknown> | unknown> = [];

afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!();
});

async function fixture(server: Server) {
  let connections = 0;
  const sockets = new Set<Socket>();
  server.on('connection', (socket) => {
    connections++;
    sockets.add(socket);
    socket.on('error', () => {});
    socket.once('close', () => sockets.delete(socket));
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Fixture did not bind a TCP port');
  cleanups.push(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  return { port: address.port, sockets, get connections() { return connections; } };
}

function httpFixture(listener: RequestListener = (_req, res) => res.end('fixture')) {
  return fixture(createHttpServer(listener));
}

async function proxy(options: EgressProxyOptions = {}): Promise<EgressProxy> {
  const result = await startEgressProxy({ timeoutMs: 5000, ...options });
  cleanups.push(() => result.close());
  return result;
}

function getThroughProxy(proxyUrl: string, target: string, headers: Record<string, string> = {}) {
  const proxyAddress = new URL(proxyUrl);
  return new Promise<{ status: number; body: string }>((resolve, reject) => {
    const req = request({
      hostname: proxyAddress.hostname,
      port: proxyAddress.port,
      method: 'GET',
      path: target,
      agent: false,
      headers: { host: new URL(target).host, ...headers },
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.once('end', () => resolve({ status: res.statusCode!, body: Buffer.concat(chunks).toString() }));
      res.once('error', reject);
    });
    req.setTimeout(2000, () => req.destroy(new Error('Proxy test request timed out')));
    req.once('error', reject);
    req.end();
  });
}

async function client(proxyUrl: string): Promise<Socket> {
  const address = new URL(proxyUrl);
  const socket = connect({ host: address.hostname, port: Number(address.port) });
  socket.on('error', () => {});
  cleanups.push(() => socket.destroy());
  await new Promise<void>((resolve, reject) => {
    socket.once('connect', resolve);
    socket.once('error', reject);
  });
  return socket;
}

function exchange(socket: Socket, outgoing: string | Buffer, complete: (data: Buffer) => boolean): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let received = Buffer.alloc(0);
    const timer = setTimeout(() => finish(new Error('Proxy test exchange timed out')), 2000);
    const onData = (chunk: Buffer) => {
      received = Buffer.concat([received, chunk]);
      if (complete(received)) finish();
    };
    const onClose = () => finish(new Error('Proxy closed before the expected response'));
    const finish = (error?: Error) => {
      clearTimeout(timer);
      socket.off('data', onData);
      socket.off('close', onClose);
      socket.off('error', finish);
      if (error) reject(error);
      else resolve(received);
    };
    socket.on('data', onData);
    socket.once('close', onClose);
    socket.once('error', finish);
    socket.write(outgoing);
  });
}

function closed(socket: Socket): Promise<void> {
  if (socket.closed) return Promise.resolve();
  return new Promise((resolve) => socket.once('close', () => resolve()));
}

describe('CONNECT authority parsing', () => {
  it.each([
    ['example.test:443', 'https://example.test/'],
    ['127.0.0.1:8443', 'https://127.0.0.1:8443/'],
    ['[::1]:8443', 'https://[::1]:8443/'],
  ])('accepts an explicit host and approved port: %s', (authority, expected) => {
    expect(parseConnectAuthority(authority, [443, 8443]).href).toBe(expected);
  });

  it.each([
    'example.test', 'example.test:', ':443', 'https://example.test:443',
    'user@example.test:443', 'user:pass@example.test:443',
    'example.test:443/path', 'example.test:443?query', 'example.test:443#fragment',
    ' example.test:443', 'example.test:443 ', 'example.test:443\r\nX-Test: injected',
    'example.test:0', 'example.test:65536', 'example.test:-443',
    'example.test:443.0', 'example.test:0x1bb', 'example.test:000443',
    '::1:443', '[::1:443', '[not-an-ip]:443', 'example%2etest:443',
  ])('rejects ambiguous or malformed authority %j', (authority) => {
    expect(() => parseConnectAuthority(authority, [443, 8443])).toThrow();
  });

  it('requires port approval independently of the target address', () => {
    expect(() => parseConnectAuthority('127.0.0.1:8443', [443])).toThrow();
  });
});

describe('connection-level egress policy', () => {
  it('rejects private HTTP and CONNECT targets before any destination TCP connection', async () => {
    const destination = await httpFixture();
    const gateway = await proxy({ allowPrivate: false, allowedPorts: [destination.port] });
    expect((await getThroughProxy(gateway.url, `http://127.0.0.1:${destination.port}/secret`)).status).toBe(403);

    const socket = await client(gateway.url);
    const response = await exchange(socket, `CONNECT 127.0.0.1:${destination.port} HTTP/1.1\r\nHost: 127.0.0.1:${destination.port}\r\n\r\n`,
      (data) => data.includes('\r\n\r\n'));
    expect(response.toString()).toMatch(/^HTTP\/1\.1 403 /);
    expect(destination.connections).toBe(0);
    expect(gateway.failure).toBeUndefined();
  });

  it('rejects mixed private/public DNS answers without connecting to the private answer', async () => {
    const destination = await httpFixture();
    // Keep the forbidden answer first: even a regression selecting the first
    // record would only touch our fixture, never an external public service.
    const lookup = vi.fn(async () => [
      { address: '127.0.0.1', family: 4 },
      { address: '1.1.1.1', family: 4 },
    ]);
    const gateway = await proxy({ allowPrivate: false, allowedPorts: [destination.port], lookup });
    expect((await getThroughProxy(gateway.url, `http://mixed.test:${destination.port}/`)).status).toBe(403);
    expect(lookup).toHaveBeenCalledExactlyOnceWith('mixed.test');
    expect(destination.connections).toBe(0);
    expect(gateway.failure).toBeUndefined();
  });

  it('pins one DNS answer while preserving the original Host and URL path', async () => {
    const seen: Array<{ host: string | undefined; path: string | undefined; headers: Record<string, unknown> }> = [];
    const destination = await httpFixture((req, res) => {
      seen.push({ host: req.headers.host, path: req.url, headers: req.headers });
      res.setHeader('Connection', 'close, x-response-hop');
      res.setHeader('x-response-hop', 'must-not-leak');
      res.end('pinned destination');
    });
    const lookup = vi.fn(async () => [{ address: '127.0.0.1', family: 4 }]);
    const gateway = await proxy({ allowPrivate: true, allowedPorts: [destination.port], lookup });
    const response = await getThroughProxy(gateway.url,
      `http://origin.test:${destination.port}/a%2Fb?key=value%20here&next=2`, {
        connection: 'close, x-hop',
        'x-hop': 'must-not-forward',
        'proxy-authorization': 'must-not-forward',
        'x-safe': 'preserved',
      });
    expect(response).toEqual({ status: 200, body: 'pinned destination' });
    expect(lookup).toHaveBeenCalledExactlyOnceWith('origin.test');
    expect(destination.connections).toBe(1);
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({
      host: `origin.test:${destination.port}`,
      path: '/a%2Fb?key=value%20here&next=2',
      headers: { 'x-safe': 'preserved' },
    });
    expect(seen[0]!.headers).not.toHaveProperty('x-hop');
    expect(seen[0]!.headers).not.toHaveProperty('proxy-authorization');
  });

  it('enforces approved ports even when private-address access is explicitly enabled', async () => {
    const destination = await httpFixture();
    const gateway = await proxy({ allowPrivate: true, allowedPorts: [443] });
    expect((await getThroughProxy(gateway.url, `http://127.0.0.1:${destination.port}/`)).status).toBe(403);
    const socket = await client(gateway.url);
    const response = await exchange(socket, `CONNECT 127.0.0.1:${destination.port} HTTP/1.1\r\nHost: 127.0.0.1:${destination.port}\r\n\r\n`,
      (data) => data.includes('\r\n\r\n'));
    expect(response.toString()).toMatch(/^HTTP\/1\.1 403 /);
    expect(destination.connections).toBe(0);
  });

  it('rejects mismatched, duplicate, and missing Host headers before connecting', async () => {
    const destination = await httpFixture();
    const gateway = await proxy({ allowPrivate: true, allowedPorts: [destination.port] });
    const authority = `127.0.0.1:${destination.port}`;
    const target = `http://${authority}/`;
    expect((await getThroughProxy(gateway.url, target, { host: `different.test:${destination.port}` })).status).toBe(403);
    for (const headers of [`Host: ${authority}\r\nHost: ${authority}\r\n`, '']) {
      const socket = await client(gateway.url);
      const response = await exchange(socket, `GET ${target} HTTP/1.1\r\n${headers}\r\n`,
        (data) => data.includes('\r\n\r\n'));
      expect(response.toString()).toMatch(/^HTTP\/1\.1 (?:400|403) /);
    }
    expect(destination.connections).toBe(0);
  });

  it('rejects state-changing HTTP methods before connecting', async () => {
    const destination = await httpFixture();
    const gateway = await proxy({ allowPrivate: true, allowedPorts: [destination.port] });
    const authority = `127.0.0.1:${destination.port}`;
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      const socket = await client(gateway.url);
      const response = await exchange(socket,
        `${method} http://${authority}/ HTTP/1.1\r\nHost: ${authority}\r\nContent-Length: 0\r\n\r\n`,
        (data) => data.includes('\r\n\r\n'));
      expect(response.toString()).toMatch(/^HTTP\/1\.1 403 /);
    }
    expect(destination.connections).toBe(0);
  });

  it('rejects missing, mismatched, and duplicate CONNECT Host headers before connecting', async () => {
    const destination = await httpFixture();
    const gateway = await proxy({ allowPrivate: true, allowedPorts: [destination.port] });
    const authority = `127.0.0.1:${destination.port}`;
    for (const headers of [
      '',
      `Host: different.test:${destination.port}\r\n`,
      `Host: ${authority}\r\nHost: ${authority}\r\n`,
      'Host: 127.0.0.1\r\n',
    ]) {
      const socket = await client(gateway.url);
      const response = await exchange(socket, `CONNECT ${authority} HTTP/1.1\r\n${headers}\r\n`,
        (data) => data.includes('\r\n\r\n'));
      expect(response.toString()).toMatch(/^HTTP\/1\.1 403 /);
    }
    expect(destination.connections).toBe(0);
    expect(gateway.failure).toBeUndefined();
  });

  it.each(['https://127.0.0.1:443', 'user@127.0.0.1:443', '127.0.0.1:443/path'])('rejects malformed CONNECT on the wire: %s', async (authority) => {
    const gateway = await proxy({ allowPrivate: true, allowedPorts: [443] });
    const socket = await client(gateway.url);
    const response = await exchange(socket, `CONNECT ${authority} HTTP/1.1\r\n\r\n`,
      (data) => data.includes('\r\n\r\n'));
    expect(response.toString()).toMatch(/^HTTP\/1\.1 403 /);
    expect(gateway.failure).toBeUndefined();
  });

  it('transports opaque CONNECT bytes, including bytes after the CONNECT headers', async () => {
    const destination = await fixture(createTcpServer((socket) => socket.pipe(socket)));
    const lookup = vi.fn(async () => [{ address: '127.0.0.1', family: 4 }]);
    const gateway = await proxy({ allowPrivate: true, allowedPorts: [destination.port], lookup });
    const socket = await client(gateway.url);
    const opaque = Buffer.from([0, 1, 2, 255, 13, 10, 0, 254]);
    const reply = Buffer.from('HTTP/1.1 200 Connection Established\r\n\r\n');
    const response = await exchange(socket, Buffer.concat([
      Buffer.from(`CONNECT tunnel.test:${destination.port} HTTP/1.1\r\nHost: tunnel.test:${destination.port}\r\n\r\n`), opaque,
    ]), (data) => data.length >= reply.length + opaque.length);
    expect(response).toEqual(Buffer.concat([reply, opaque]));
    const second = Buffer.from('second opaque frame');
    expect(await exchange(socket, second, (data) => data.length >= second.length)).toEqual(second);
    expect(lookup).toHaveBeenCalledExactlyOnceWith('tunnel.test');
    expect(destination.connections).toBe(1);
  });
});

describe('egress resource limits and cleanup', () => {
  it('stops admitting requests at the per-job request limit', async () => {
    const destination = await httpFixture();
    const gateway = await proxy({ allowPrivate: true, allowedPorts: [destination.port], maxRequests: 1 });
    const target = `http://127.0.0.1:${destination.port}/`;
    expect((await getThroughProxy(gateway.url, target)).status).toBe(200);
    await expect(getThroughProxy(gateway.url, target)).rejects.toThrow();
    expect(gateway.failure?.message).toMatch(/request limit/i);
    expect(destination.connections).toBe(1);
  });

  it('terminates connections when the combined transfer budget is exceeded', async () => {
    const destination = await httpFixture((_req, res) => res.end(Buffer.alloc(8192, 'a')));
    const gateway = await proxy({ allowPrivate: true, allowedPorts: [destination.port], maxBytes: 512 });
    await getThroughProxy(gateway.url, `http://127.0.0.1:${destination.port}/`).catch(() => undefined);
    expect(gateway.failure?.message).toMatch(/transfer limit/i);
    await gateway.close();
  });

  it('expires the entire job, including idle open sockets', async () => {
    const gateway = await proxy({ timeoutMs: 100 });
    const socket = await client(gateway.url);
    await closed(socket);
    expect(gateway.failure?.message).toMatch(/deadline exceeded/i);
    expect(socket.destroyed).toBe(true);
  });

  it('terminates all job sockets when the connection limit is exceeded', async () => {
    const gateway = await proxy({ maxSockets: 1 });
    const first = await client(gateway.url);
    const firstClosed = closed(first);
    const second = await client(gateway.url);
    await Promise.all([firstClosed, closed(second)]);
    expect(gateway.failure?.message).toMatch(/connection limit/i);
    expect(first.destroyed).toBe(true);
    expect(second.destroyed).toBe(true);
    await gateway.close();
  });

  it('closes both sides of live tunnels and allows idempotent cleanup', async () => {
    const destination = await fixture(createTcpServer((socket) => socket.on('data', () => {})));
    const gateway = await proxy({ allowPrivate: true, allowedPorts: [destination.port] });
    const socket = await client(gateway.url);
    await exchange(socket, `CONNECT 127.0.0.1:${destination.port} HTTP/1.1\r\nHost: 127.0.0.1:${destination.port}\r\n\r\n`,
      (data) => data.includes('\r\n\r\n'));
    expect(destination.sockets.size).toBe(1);
    const destinationSocket = [...destination.sockets][0]!;
    const clientClosed = closed(socket);
    const destinationClosed = closed(destinationSocket);
    await Promise.all([gateway.close(), gateway.close(), clientClosed, destinationClosed]);
    expect(socket.destroyed).toBe(true);
    expect(destination.sockets.size).toBe(0);
    expect(gateway.failure).toBeUndefined();
    await expect(getThroughProxy(gateway.url, `http://127.0.0.1:${destination.port}/`)).rejects.toThrow();
    expect(destination.connections).toBe(1);
  });
});
