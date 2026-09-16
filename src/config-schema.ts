import { isIP } from 'node:net';
import { z } from 'zod';

const unset = (v: unknown) => v === undefined || v === '';
const intEnv = (value: number, min = 1, max = 2_147_483_647) =>
  z.preprocess((v) => unset(v) ? value : typeof v === 'string' ? Number(v) : v,
    z.number().int().min(min).max(max));
const boolEnv = (value: boolean) => z.preprocess((v) => {
  if (unset(v)) return value;
  if (typeof v === 'boolean') return v;
  if (/^(1|true|yes|on)$/i.test(String(v))) return true;
  if (/^(0|false|no|off)$/i.test(String(v))) return false;
  return v;
}, z.boolean());
const listEnv = (values: string[] = []) => z.preprocess((v) => unset(v) ? values :
  typeof v === 'string' ? v.split(',').map((s) => s.trim()).filter(Boolean) : v,
  z.array(z.string().min(1)).max(100));
const strongSecret = (min: number) => z.string().min(min).max(4096)
  .refine((s) => s.trim().length >= min, 'Secret must not be blank or padded to reach the minimum length')
  .refine((s) => !/^(change[-_ ]?me|replace[-_ ]?me|your[-_ ])/i.test(s), 'Replace example secrets before starting');

export function isOrigin(value: string): boolean {
  try {
    const u = new URL(value);
    return !u.username && !u.password && u.pathname === '/' && !u.search && !u.hash &&
      (u.protocol === 'https:' || (u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname)));
  } catch { return false; }
}
function isProxyAddress(value: string): boolean {
  const parts = value.split('/');
  const version = isIP(parts[0] ?? '');
  if (!version || parts.length > 2) return false;
  return parts.length === 1 || (/^\d+$/.test(parts[1] ?? '') && Number(parts[1]) <= (version === 4 ? 32 : 128));
}

/** Independently importable schema: validation errors never include secret values. */
export const ConfigSchema = z.object({
  PORT: intEnv(8080, 1, 65535),
  BIND_HOST: z.string().min(1).default('0.0.0.0'),
  PUBLIC_BASE_URL: z.string().refine((value) => isOrigin(value) && !(new URL(value).protocol === 'http:' && new URL(value).hostname === '[::1]'), 'Use an HTTPS origin without path, query, credentials or fragment (HTTP only for localhost/127.0.0.1)'),
  AUTH_USERNAME: z.string().min(1).max(200),
  AUTH_PASSWORD: strongSecret(12),
  JWT_SECRET: strongSecret(32),
  STATIC_BEARER_TOKEN: z.preprocess((v) => unset(v) ? undefined : v, strongSecret(32).optional()),
  OAUTH_ONLY: boolEnv(false),
  EXTRA_REDIRECT_URIS: listEnv(),
  ALLOWED_ORIGINS: listEnv().refine((values) => values.every(isOrigin), 'Each entry must be a valid origin'),
  TRUST_PROXY: listEnv().refine((values) => values.every(isProxyAddress), 'Use explicit proxy IP addresses or CIDRs, not a hop count'),
  ACCESS_TOKEN_TTL: intEnv(3600, 60, 86400),
  REFRESH_TOKEN_TTL: intEnv(2592000, 60, 7776000),
  AUTH_CODE_TTL: intEnv(600, 30, 600),
  CONSENT_REQUEST_TTL: intEnv(600, 30, 600),
  OAUTH_MAX_CLIENTS: intEnv(1000, 1, 10000),
  MCP_SESSION_TTL_MS: intEnv(900000, 1000, 86400000),
  MCP_MAX_SESSIONS: intEnv(100, 1, 1000),
  MCP_MAX_SESSIONS_PER_CLIENT: intEnv(10, 1, 1000),
  FILTER_MODE: z.enum(['strict', 'lenient']).default('strict'),
  FILTER_TIER2: boolEnv(false),
  NAV_TIMEOUT_MS: intEnv(30000, 100, 120000),
  DEFAULT_WAIT_MS: intEnv(0, 0, 60000),
  BROWSER_CONCURRENCY: intEnv(4, 1, 16),
  BROWSER_MAX_QUEUE: intEnv(16, 0, 100),
  BROWSER_RECYCLE_AFTER: intEnv(200, 0, 10000),
  // Enable Chromium's sandbox unless a container operator explicitly disables it.
  CHROMIUM_NO_SANDBOX: boolEnv(false),
  FETCH_TIMEOUT_MS: intEnv(90000, 1000, 180000),
  FETCH_MAX_REQUESTS: intEnv(300, 1, 2000),
  FETCH_MAX_HTML_BYTES: intEnv(2000000, 1000, 10000000),
  FETCH_MAX_TRANSFER_BYTES: intEnv(20000000, 1000, 100000000),
  FETCH_ALLOWED_PORTS: listEnv(['80', '443']).refine((v) => v.every((port) => /^\d+$/.test(port)), 'Use decimal port numbers').transform((v) => v.map(Number))
    .refine((v) => v.length > 0 && v.every((n) => Number.isInteger(n) && n >= 1 && n <= 65535), 'Use comma-separated TCP ports (1–65535)'),
  MAX_CHARS_DEFAULT: intEnv(50000, 100, 500000),
  FETCH_ALLOW_PRIVATE: boolEnv(false),
  FETCH_USER_AGENT: z.string().min(1).max(512).regex(/^[\x20-\x7e]+$/).default(
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/Safari renderfetch-mcp'),
  SCREENSHOT_ENABLED: boolEnv(false),
  DB_PATH: z.string().min(1).default('/data/renderfetch.db'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  RATE_LIMIT_WINDOW_MS: intEnv(60000, 1000, 3600000),
  RATE_LIMIT_MAX: intEnv(120, 1, 10000),
});
