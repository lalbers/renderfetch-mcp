import { ConfigSchema } from './config-schema.js';

const parsed = ConfigSchema.safeParse(process.env);
if (!parsed.success) {
  const lines = parsed.error.issues.map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`);
  console.error('Invalid renderfetch-mcp configuration:\n' + lines.join('\n'));
  process.exit(1);
}
const env = parsed.data;
const issuerUrl = new URL(new URL(env.PUBLIC_BASE_URL).origin);
const resourceUrl = new URL('/mcp', issuerUrl);
export const config = {
  ...env,
  ALLOWED_ORIGINS: env.ALLOWED_ORIGINS.map((v) => new URL(v).origin),
  issuerUrl,
  resourceUrl,
};
export type Config = typeof config;
export const OWNER_USER_ID = 'owner';
export const SUPPORTED_SCOPES = ['mcp:fetch', 'offline_access'];
