import { config } from './config.js';
import { logger } from './logger.js';
import { db, pruneExpired } from './store/db.js';
import { createApp } from './http.js';
import { warmupBrowser, closeBrowser } from './fetch/browser.js';
import { warmupDefender } from './filter/defender.js';
import { closeAllTransports } from './mcp/transport.js';

async function main(): Promise<void> {
  const app = createApp();

  const server = app.listen(config.PORT, config.BIND_HOST, () => {
    logger.info(
      {
        host: config.BIND_HOST,
        port: config.PORT,
        base: config.PUBLIC_BASE_URL,
        resource: config.resourceUrl.href,
        filter_mode: config.FILTER_MODE,
        oauth_only: config.OAUTH_ONLY,
        static_bearer: !!config.STATIC_BEARER_TOKEN && !config.OAUTH_ONLY,
      },
      'renderfetch-mcp listening',
    );
  });
  // Keep long-lived SSE streams from being torn down by Node's timeouts.
  server.requestTimeout = 0;
  server.headersTimeout = 65_000;

  // Warm heavy subsystems in the background (don't block accepting connections).
  warmupDefender().catch((err) => logger.warn({ err }, 'defender warmup error'));
  warmupBrowser().catch((err) => logger.warn({ err }, 'browser warmup error'));

  // Periodic cleanup of expired auth codes / refresh tokens.
  const prune = setInterval(() => {
    try {
      pruneExpired();
    } catch (err) {
      logger.warn({ err }, 'prune failed');
    }
  }, 60 * 60 * 1000);
  prune.unref();

  let shuttingDown = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info({ signal }, 'shutting down');
    server.close();
    await closeAllTransports();
    await closeBrowser();
    try {
      db.close();
    } catch {
      /* ignore */
    }
    logger.info('shutdown complete');
    process.exit(0);
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('unhandledRejection', (reason) => logger.error({ reason }, 'unhandledRejection'));
}

main().catch((err) => {
  logger.fatal({ err }, 'fatal startup error');
  process.exit(1);
});
