import { describe, it, expect } from 'vitest';
import { timingSafeEqualStr } from '../src/util.js';

describe('timingSafeEqualStr', () => {
  it('matches only identical strings, whatever their lengths', () => {
    expect(timingSafeEqualStr('correct horse', 'correct horse')).toBe(true);
    expect(timingSafeEqualStr('correct horse', 'correct horsf')).toBe(false);
    expect(timingSafeEqualStr('short', 'a much longer secret value')).toBe(false);
    expect(timingSafeEqualStr('', '')).toBe(true);
    expect(timingSafeEqualStr('', 'x')).toBe(false);
    expect(timingSafeEqualStr('pässwört', 'pässwört')).toBe(true);
    expect(timingSafeEqualStr('pässwört', 'passwort')).toBe(false);
  });
});
