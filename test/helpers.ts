import type { Server } from 'node:http';
import { createApp } from '../src/http.js';

export interface TestServer {
  base: string;
  close: () => Promise<void>;
}

/** Start the real Express app on an ephemeral loopback port. */
export async function startTestServer(): Promise<TestServer> {
  const app = createApp();
  const server: Server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const addr = server.address();
  const port = addr && typeof addr === 'object' ? addr.port : 0;
  return {
    base: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}
