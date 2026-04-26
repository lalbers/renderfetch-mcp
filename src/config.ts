import { z } from 'zod';

// Treat empty string the same as "unset" so blank lines in an env file fall back
// to the documented default rather than producing NaN / parse errors.
const isUnset = (v: unknown) => v === undefined || v === '';

const intEnv = (def: number) =>
  z.preprocess((v) => (isUnset(v) ? def : typeof v === 'string' ? Number(v) : v), z.number().int());

const boolEnv = (def: boolean) =>
  z.preprocess((v) => (isUnset(v) ? def : /^(1|true|yes|on)$/i.test(String(v))), z.boolean());

const listEnv = (def: string[] = []) =>
  z.preprocess(
    (v) =>
      isUnset(v)
        ? def
        : String(v)
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean),
    z.array(z.string()),
  );

const Schema = z.object({
  // --- network / identity ---------------------------------------------------
  PORT: intEnv(8080),
  BIND_HOST: z.string().default('0.0.0.0'),
  // Public origin this server is reachable at (no path). Used to derive the
  // OAuth issuer and the canonical MCP resource URI.
  PUBLIC_BASE_URL: z.string().url(),

  // --- auth -----------------------------------------------------------------
  // The single human credential gating consent/login. DCR registers the *client*
  // (Claude); this protects the *user* approval step.
  AUTH_USERNAME: z.string().min(1),
  AUTH_PASSWORD: z.string().min(1),
  // HMAC secret for signing access-token JWTs and consent-request tokens.
  JWT_SECRET: z.string().min(32),
  // Optional static bearer for headless/systemd Claude Code (not used by claude.ai).
  STATIC_BEARER_TOKEN: z.string().min(16).optional(),
  // When true, the static bearer path is disabled and only OAuth is accepted.
  OAUTH_ONLY: boolEnv(false),
  // Extra exact redirect URIs to permit during DCR (claude.ai callback and
  // loopback are always allowed).
  EXTRA_REDIRECT_URIS: listEnv([]),

  ACCESS_TOKEN_TTL: intEnv(3600), // seconds
  REFRESH_TOKEN_TTL: intEnv(60 * 60 * 24 * 30), // 30 days
  AUTH_CODE_TTL: intEnv(600), // 10 min
  CONSENT_REQUEST_TTL: intEnv(600), // 10 min

  // --- filter ---------------------------------------------------------------
  FILTER_MODE: z.enum(['strict', 'lenient']).default('strict'),
  // ONNX ML tier — opt-in (needs the defender peer deps). Regex layers (our
  // pattern detector + defender's tier1) are always on regardless of this.
  FILTER_TIER2: boolEnv(false),

  // --- fetch / browser ------------------------------------------------------
  NAV_TIMEOUT_MS: intEnv(30000),
  DEFAULT_WAIT_MS: intEnv(0),
  BROWSER_CONCURRENCY: intEnv(4),
  BROWSER_RECYCLE_AFTER: intEnv(200), // relaunch Chromium after N navigations (0 = never)
  CHROMIUM_NO_SANDBOX: boolEnv(true), // container is the isolation boundary in rootless podman
  MAX_CHARS_DEFAULT: intEnv(50000),
  FETCH_ALLOW_PRIVATE: boolEnv(false), // SSRF guard: allow private/loopback targets
  FETCH_USER_AGENT: z
    .string()
    .default(
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/Safari renderfetch-mcp',
    ),
  SCREENSHOT_ENABLED: boolEnv(false),

  // --- store / logging ------------------------------------------------------
  DB_PATH: z.string().default('/data/renderfetch.db'),
  LOG_LEVEL: z
    .enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'])
    .default('info'),

  // --- per-token rate limit (applied to /mcp after auth) --------------------
  RATE_LIMIT_WINDOW_MS: intEnv(60000),
  RATE_LIMIT_MAX: intEnv(120),
});

const parsed = Schema.safeParse(process.env);
if (!parsed.success) {
  const lines = parsed.error.issues.map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`);
  // Use console here: the logger depends on config, which isn't ready yet.
  console.error('Invalid renderfetch-mcp configuration:\n' + lines.join('\n'));
  process.exit(1);
}

const env = parsed.data;

// Canonical MCP resource URI (RFC 8707 / RFC 9728): base + /mcp, no trailing
// slash, no fragment. This is exactly the URL the user pastes into claude.ai and
// the audience every access token is bound to.
const issuerUrl = new URL(env.PUBLIC_BASE_URL);
const resourceUrl = new URL('/mcp', issuerUrl);

export const config = {
  ...env,
  issuerUrl,
  resourceUrl,
};

export type Config = typeof config;

// Single logical user behind the consent gate (the connector is single-user).
export const OWNER_USER_ID = 'owner';

// Advertised scopes. offline_access lets claude.ai request refresh tokens.
export const SUPPORTED_SCOPES = ['mcp:fetch', 'offline_access'];
