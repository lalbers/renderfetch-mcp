import { describe, expect, it } from 'vitest';
import { ConfigSchema } from '../src/config-schema.js';

const base = { PUBLIC_BASE_URL: 'https://mcp.example.com', AUTH_USERNAME: 'owner',
  AUTH_PASSWORD: 'a-strong-test-passphrase', JWT_SECRET: 'a-long-test-secret-with-at-least-32-chars' };
describe('configuration security', () => {
  it('normalizes blank optional secrets and defaults', () => {
    const result = ConfigSchema.parse({ ...base, STATIC_BEARER_TOKEN: '', NAV_TIMEOUT_MS: '' });
    expect(result.STATIC_BEARER_TOKEN).toBeUndefined();
    expect(result.FETCH_ALLOWED_PORTS).toEqual([80, 443]);
    expect(result.TRUST_PROXY).toEqual([]);
    expect(result.CHROMIUM_NO_SANDBOX).toBe(false);
  });
  it.each(['tru', 'enabled', 'nope'])('rejects typoed security boolean %s', (v) => {
    expect(ConfigSchema.safeParse({ ...base, OAUTH_ONLY: v }).success).toBe(false);
  });
  it.each([['BROWSER_CONCURRENCY', 0], ['BROWSER_MAX_QUEUE', -1], ['NAV_TIMEOUT_MS', -1],
    ['MAX_CHARS_DEFAULT', 500001], ['FETCH_ALLOWED_PORTS', '80,65536'], ['PORT', 0],
    ['TRUST_PROXY', '1'], ['TRUST_PROXY', '127.0.0.1/999'], ['ALLOWED_ORIGINS', 'https://example.com/path']])
    ('rejects invalid %s', (key, value) => expect(ConfigSchema.safeParse({ ...base, [key]: value }).success).toBe(false));
  it.each(['https://user:password@foo.com', 'https://foo.com/path', 'https://foo.com?x=1',
    'http://foo.com', 'http://[::1]:8080', 'HTTP://[0:0:0:0:0:0:0:1]:8080', 'https://foo.com/#fragment', 'file:///tmp/test'])('rejects invalid public origin %s', (url) => {
    expect(ConfigSchema.safeParse({ ...base, PUBLIC_BASE_URL: url }).success).toBe(false);
  });
  it('accepts explicit loopback development origin and exact trusted proxy ranges', () => {
    expect(ConfigSchema.parse({ ...base, PUBLIC_BASE_URL: 'http://127.0.0.1:8080',
      TRUST_PROXY: '127.0.0.1/32,::1/128' }).TRUST_PROXY).toHaveLength(2);
  });
  it('rejects placeholder and short credentials', () => {
    expect(ConfigSchema.safeParse({ ...base, AUTH_PASSWORD: 'change-me-to-a-long-passphrase' }).success).toBe(false);
    expect(ConfigSchema.safeParse({ ...base, STATIC_BEARER_TOKEN: 'short' }).success).toBe(false);
    expect(ConfigSchema.safeParse({ ...base, JWT_SECRET: ' '.repeat(32) }).success).toBe(false);
  });
});
