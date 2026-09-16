import { describe, it, expect, vi } from 'vitest';
import { Readability } from '@mozilla/readability';
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

const HOSTILE = `<!doctype html><title>Untrusted title</title><body><article id="scope">
<h1>Visible heading</h1><p>Visible article text with useful information.</p>
<script>script_secret</script><style>.x { content: 'style_secret' }</style>
<form><p>form_secret</p><input value="secret"></form><iframe>frame_secret</iframe>
<object>object_secret</object><svg><text>svg_secret</text></svg><system-prompt>custom_secret</system-prompt>
<p hidden>hidden_secret</p><p aria-hidden="true">aria_secret</p><div style="display: none">display_secret</div>
<p style="visibility:hidden">visibility_secret</p><p style="opacity:0.0">opacity_secret</p>
<p style="font-size:0px">font_secret</p><p style="left:-9999px">offscreen_secret</p>
<p style="d\\69splay: none">escaped_css_secret</p><!-- comment_secret -->
<p onclick="event_secret()" class="secret" data-secret="metadata_secret">Ordinary paragraph</p>
<img src="https://beacon.example/remote" onerror="event_secret()" alt="Useful image description">
<a href="../guide?q=one">Relative guide</a><a href="javascript:alert('evil')">Unsafe script link</a>
<a href="data:text/html,evil">Unsafe data link</a><a href="https://user:password@evil.example/">Credential link</a>
<a href="//docs.example/help">Protocol relative link</a>
<p>&lt;img src="https://beacon.example/literal"&gt; ![secret](https://beacon.example/markdown)</p>
</article></body>`;

describe('extraction trust boundary', () => {
  for (const format of ['text', 'markdown', 'html'] as const) {
    it(`uses the same sanitizer for ${format}, selectors and fallback`, () => {
      for (const cssSelector of [undefined, '#scope']) {
        const result = extract({ html: HOSTILE, url: 'https://example.com/news/article', format, maxChars: 50000, cssSelector });
        expect(result.content).toContain('Visible heading');
        expect(result.content).toContain('Useful image description');
        for (const marker of ['script_secret', 'style_secret', 'form_secret', 'frame_secret', 'object_secret',
          'svg_secret', 'custom_secret', 'hidden_secret', 'aria_secret', 'display_secret', 'visibility_secret',
          'opacity_secret', 'font_secret', 'offscreen_secret', 'escaped_css_secret', 'comment_secret',
          'event_secret', 'metadata_secret']) expect(result.content).not.toContain(marker);
        expect(result.content).not.toMatch(/<(?:img|script|style|form|iframe|object|svg|custom-widget)\b/i);
        expect(result.content).not.toMatch(/!\[/);
        expect(result.content).not.toContain('javascript:');
        expect(result.content).not.toContain('data:text/html');
        expect(result.content).not.toContain('user:password');
        if (format !== 'text') {
          expect(result.content).toContain('https://example.com/guide?q=one');
          expect(result.content).toContain('https://docs.example/help');
        }
      }
    });
  }

  it('does not resurrect a selected hidden element or a hidden ancestor', () => {
    for (const html of ['<body hidden><p id="target">secret</p>',
      '<div style="display:none"><p id="target">secret</p></div>']) {
      expect(extract({ html, url: 'https://example.com/', format: 'text', cssSelector: '#target', maxChars: 50 }).content).toBe('');
    }
  });

  it('removes cookie banners from a detached document by default and supports opting out', () => {
    const html = '<article><h1>Story</h1><p>Useful article content.</p><div id="onetrust-banner-sdk">We use cookies. Accept all cookies.</div></article>';
    const input = { html, url: 'https://example.com/', format: 'text' as const, cssSelector: 'article', maxChars: 1000 };
    const hidden = extract(input);
    expect(hidden.cookieBanner).toMatchObject({ mode: 'hide', hidden: 1 });
    expect(hidden.content).not.toContain('Accept all');
    const off = extract({ ...input, cookieBanner: 'off' });
    expect(off.cookieBanner).toEqual({ mode: 'off', hidden: 0, rules: [] });
    expect(off.content).toContain('Accept all');
  });

  it('rejects an oversized document before parsing', async () => {
    const { config } = await import('../src/config.js');
    expect(() => extract({ html: '€'.repeat(Math.ceil(config.FETCH_MAX_HTML_BYTES / 3)),
      url: 'https://example.com/', format: 'text', maxChars: 10 })).toThrow('HTML byte limit');
  });

  it('reports selectors with no match without echoing the selector', () => {
    expect(() => extract({ html: '<p>Hello</p>', url: 'https://example.com/', format: 'text', maxChars: 10,
      cssSelector: '#sensitive-selector' })).toThrow('CSS selector did not match any element');
  });

  it('retains structural HTML but strips every non-allowlisted attribute', () => {
    const result = extract({ html: '<table id="table"><tr><td colspan="2" style="color:red" onclick="evil()" data-token="secret">Cell</td></tr></table>',
      url: 'https://example.com/', format: 'html', cssSelector: '#table', maxChars: 1000 });
    expect(result.content).toContain('colspan="2"');
    expect(result.content).not.toMatch(/style=|onclick=|data-token=/);
  });
});

describe('bounded extraction work', () => {
  it('rejects relative-link expansion before allocating an oversized output', () => {
    const url = 'https://example.com/' + 'a'.repeat(7000) + '/article';
    const html = '<article>' + '<a href="next">link</a>'.repeat(400) + '</article>';
    expect(() => extract({ html, url, format: 'html', maxChars: 100 })).toThrow('extraction byte limit');
  });

  it('rejects pathological DOM nesting', () => {
    const html = '<div>'.repeat(150) + 'Nested' + '</div>'.repeat(150);
    expect(() => extract({ html, url: 'https://example.com/', format: 'text', maxChars: 100 })).toThrow('nesting limit');
  });

  it('rejects excessive node counts in otherwise small HTML', () => {
    const html = '<p>' + '<br>'.repeat(50001) + '</p>';
    expect(() => extract({ html, url: 'https://example.com/', format: 'text', maxChars: 100 })).toThrow('node limit');
  });
});

describe('rendered framework wrappers', () => {
  it.each(['html', 'markdown', 'text'] as const)('preserves safe app-root children in %s while removing custom behavior', (format) => {
    const html = '<app-root id="app" onclick="evil()"><main><h1>Rendered article</h1><p>Useful rendered prose.</p>' +
      '<script>script_secret</script><form>form_secret</form><svg><text>svg_secret</text></svg>' +
      '<system-prompt>role_secret</system-prompt><info-box data-token="secret">Additional detail.</info-box></main></app-root>';
    for (const cssSelector of [undefined, '#app']) {
      const result = extract({ html, url: 'https://example.com/', format, cssSelector, maxChars: 1000 });
      expect(result.content).toContain('Rendered article');
      expect(result.content).toContain('Additional detail.');
      expect(result.content).not.toMatch(/app-root|info-box|onclick|data-token|script_secret|form_secret|svg_secret|role_secret/);
    }
  });
});


describe('post-Readability parser boundary', () => {
  it('checks the transformed article byte size before reparsing it', async () => {
    const { config } = await import('../src/config.js');
    const parse = vi.spyOn(Readability.prototype, 'parse').mockReturnValue({
      title: 'Article', content: 'x'.repeat(config.FETCH_MAX_HTML_BYTES + 1),
      byline: null, dir: null, lang: null, textContent: '', length: 0, excerpt: null,
      siteName: null, publishedTime: null,
    });
    try {
      expect(() => extract({ html: '<p>Small input.</p>', url: 'https://example.com/',
        format: 'text', maxChars: 100 })).toThrow('Article extraction exceeds the HTML byte limit');
    } finally { parse.mockRestore(); }
  });
});
