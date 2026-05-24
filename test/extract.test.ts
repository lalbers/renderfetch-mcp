import { describe, it, expect } from 'vitest';
import { extract } from '../src/fetch/extract.js';

const HTML = `<!doctype html><html><head><title>Hello Title</title></head>
<body>
  <nav>site menu</nav>
  <article>
    <h1>Main Heading</h1>
    <p>First paragraph with <strong>bold</strong> text and a <a href="https://x.example">link</a>.</p>
    <ul><li>one</li><li>two</li></ul>
  </article>
  <footer>page footer</footer>
  <script>console.log('should not appear')</script>
</body></html>`;

describe('extract', () => {
  it('produces markdown from the main content and drops scripts', () => {
    const r = extract({ html: HTML, url: 'https://example.com/', format: 'markdown', maxChars: 50000 });
    expect(r.title).toBeTruthy();
    expect(r.content).toContain('Main Heading');
    expect(r.content).toMatch(/\*\*bold\*\*/);
    expect(r.content).toMatch(/-\s+one/);
    expect(r.content).not.toContain('console.log');
    expect(r.truncated).toBe(false);
  });

  it('scopes extraction with css_selector', () => {
    const r = extract({
      html: HTML,
      url: 'https://example.com/',
      format: 'text',
      cssSelector: 'article h1',
      maxChars: 50000,
    });
    expect(r.content.trim()).toBe('Main Heading');
  });

  it('truncates to max_chars and sets the flag', () => {
    const r = extract({ html: HTML, url: 'https://example.com/', format: 'text', maxChars: 5 });
    expect(r.truncated).toBe(true);
    expect(r.content.length).toBe(5);
  });
});
