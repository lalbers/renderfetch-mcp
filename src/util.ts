import { randomBytes, createHash, createHmac, timingSafeEqual } from 'node:crypto';

/** URL-safe random token (default 32 bytes => 43 base64url chars). */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/** Hex SHA-256 — used to store auth codes / refresh tokens at rest. */
export function sha256hex(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

// Per-process key: these digests are compared once and never stored or logged.
const compareKey = randomBytes(32);

/**
 * Constant-time string compare that never throws. Comparing fixed-size keyed
 * digests (HMAC-SHA-256) hides the secret's length too, which a length check
 * would leak.
 */
export function timingSafeEqualStr(a: string, b: string): boolean {
  const digest = (value: string) => createHmac('sha256', compareKey).update(value, 'utf8').digest();
  return timingSafeEqual(digest(a), digest(b));
}

export function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

const HTML_ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

export function htmlEscape(s: string): string {
  return s.replace(/[&<>"']/g, (c) => HTML_ESCAPES[c] ?? c);
}
