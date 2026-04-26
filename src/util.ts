import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';

/** URL-safe random token (default 32 bytes => 43 base64url chars). */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/** Hex SHA-256 — used to store auth codes / refresh tokens at rest. */
export function sha256hex(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

/** Constant-time string compare that never throws and is length-safe. */
export function timingSafeEqualStr(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) {
    // Still do a comparison against a fixed-length buffer to avoid leaking
    // length via early-return timing; result is irrelevant.
    timingSafeEqual(ab, ab);
    return false;
  }
  return timingSafeEqual(ab, bb);
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
