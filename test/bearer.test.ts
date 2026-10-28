import { describe, it, expect } from 'vitest';
import { bearerToken } from '../src/auth/bearer.js';

describe('bearerToken', () => {
  it('extracts exactly one token after a case-insensitive Bearer scheme', () => {
    expect(bearerToken('Bearer abc.DEF-123')).toBe('abc.DEF-123');
    expect(bearerToken('bearer \t abc ')).toBe('abc');
    expect(bearerToken('Bearer abc def')).toBeUndefined();
    expect(bearerToken('Basic abc')).toBeUndefined();
    expect(bearerToken('Bearer ')).toBeUndefined();
    expect(bearerToken(undefined)).toBeUndefined();
  });

  it('stays linear on long separator runs', () => {
    // The former /^Bearer\s+(.+)$/i backtracked quadratically on this input.
    const started = performance.now();
    expect(bearerToken(`Bearer${' '.repeat(50_000)}\n`)).toBeUndefined();
    expect(performance.now() - started).toBeLessThan(100);
  });
});
