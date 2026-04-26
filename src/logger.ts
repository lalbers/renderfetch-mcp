import pino from 'pino';
import { config } from './config.js';

// Structured JSON to stdout -> podman logs / journald. Secrets are redacted in
// case a request/response object is ever logged verbatim.
export const logger = pino({
  level: config.LOG_LEVEL,
  base: { service: 'renderfetch-mcp' },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'authorization',
      'password',
      '*.password',
      'client_secret',
      '*.client_secret',
      'access_token',
      '*.access_token',
      'refresh_token',
      '*.refresh_token',
    ],
    censor: '[redacted]',
  },
});
