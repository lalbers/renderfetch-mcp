import { describe, it, expect } from 'vitest';
import { fetchResult } from '../src/fetch/tool.js';

// Regression for 2026-09-02: the claude.ai connector started rendering only
// `structuredContent` when present. Our structuredContent carried metadata
// alone, so every caller (briefing jobs role, conductor) saw
// {final_url, http_status, title, …} and not one character of page text —
// while the server log showed a successful, unblocked fetch.
const META = {
  final_url: 'https://example.com/',
  http_status: 200,
  title: 'Example Domain',
  truncated: false,
  format: 'markdown',
  filter: { risk_level: 'low', blocked: false, detections: 0 },
};

describe('fetchResult', () => {
  it('carries the page text in structuredContent as well as in content', () => {
    const body =
      'fetched: https://example.com/\nstatus: 200\n\n[UD-abc123] BEGIN untrusted\n# Example\n[UD-abc123] END untrusted';
    const r = fetchResult(META, body);
    expect(r.content).toEqual([{ type: 'text', text: body }]);
    expect(r.structuredContent).toMatchObject(META);
    expect(r.structuredContent?.text).toBe(body);
    expect(r.isError).toBeUndefined();
  });

  it('keeps the metadata keys intact next to the text', () => {
    const r = fetchResult(META, 'x');
    expect(Object.keys(r.structuredContent ?? {}).sort()).toEqual(
      [...Object.keys(META), 'text'].sort(),
    );
  });

  it('marks blocked results as errors and still explains why in both places', () => {
    const msg = 'fetch_url blocked: content tripped the prompt-injection filter';
    const r = fetchResult({ ...META, filter: { ...META.filter, blocked: true } }, msg, true);
    expect(r.isError).toBe(true);
    expect(r.structuredContent?.text).toBe(msg);
    expect(r.content[0]).toEqual({ type: 'text', text: msg });
  });
});
