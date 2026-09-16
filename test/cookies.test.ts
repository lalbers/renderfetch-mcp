import { JSDOM } from 'jsdom';
import { describe, expect, it, vi } from 'vitest';
import { cleanupCookieBanners } from '../src/fetch/cookies.js';

function parse(html: string): Document {
  return new JSDOM(html, { url: 'https://example.com/' }).window.document;
}

describe('cleanupCookieBanners', () => {
  it.each([
    ['onetrust', '<div id="onetrust-banner-sdk">OneTrust</div>'],
    ['onetrust', '<div id="onetrust-pc-sdk">Preferences</div>'],
    ['cookiebot', '<div id="CybotCookiebotDialog">Cookiebot</div>'],
    ['didomi', '<div id="didomi-host">Didomi</div>'],
    ['cookieyes', '<div class="cky-consent-container">CookieYes</div>'],
    ['osano', '<div class="osano-cm-window">Osano</div>'],
  ])('removes the %s UI from the snapshot', (rule, banner) => {
    const document = parse(`<main>Article remains</main>${banner}`);
    expect(cleanupCookieBanners(document)).toEqual({ mode: 'hide', hidden: 1, rules: [rule] });
    expect(document.body.innerHTML).toBe('<main>Article remains</main>');
  });

  it('does not invoke consent handlers or change cookies and storage', () => {
    const document = parse('<div id="onetrust-banner-sdk"><button>Accept all</button></div>');
    document.cookie = 'existing=value';
    document.defaultView!.localStorage.setItem('consent', 'unchanged');
    const click = vi.fn();
    document.querySelector('button')!.addEventListener('click', click);

    cleanupCookieBanners(document);

    expect(click).not.toHaveBeenCalled();
    expect(document.cookie).toBe('existing=value');
    expect(document.defaultView!.localStorage.getItem('consent')).toBe('unchanged');
  });

  it.each([
    '<div role="dialog"><h2>Cookie preferences</h2><button>Reject all</button></div>',
    '<dialog open>We use cookies to personalize this site.<button>Accept all</button></dialog>',
    '<aside aria-modal="true" aria-label="Cookie consent"><button aria-label="Manage settings">Settings</button></aside>',
    '<div role="alertdialog">Wir verwenden Cookies.<button>Alle ablehnen</button></div>',
  ])('removes an explicit consent dialog with consent controls', (dialog) => {
    const document = parse(`<main>Article remains</main>${dialog}`);
    expect(cleanupCookieBanners(document)).toEqual({ mode: 'hide', hidden: 1, rules: ['consent-dialog'] });
    expect(document.body.textContent).toBe('Article remains');
  });

  it.each([
    '<article><h1>Cookie consent explained</h1><button>Accept all</button></article>',
    '<div id="cookie-article">We use cookies.<button>Accept all</button></div>',
    '<div role="dialog">Cookie consent is described here.</div>',
    '<div role="dialog">Cookie recipes<button>Close</button></div>',
    '<div role="dialog">Delete this item?<button>Accept</button></div>',
    '<div role="dialog"><script>"Cookie consent"</script><button>Accept all</button></div>',
    '<div role="dialog">We use cookies.<input type="password"><button>Accept all</button></div>',
    '<div role="dialog">Sign in. We use cookies.<button>Accept all</button></div>',
    '<div role="dialog">Subscribe to read. Cookie consent.<button>Accept all</button></div>',
    '<div role="dialog">CAPTCHA required. Cookie consent.<button>Accept all</button></div>',
    '<div role="dialog">Cookie consent.<div data-sitekey="challenge"></div><button>Accept all</button></div>',
    '<div role="dialog"><article>Cookie preferences</article><button>Accept all</button></div>',
    '<div role="dialog">Cookie preferences<input type="email"><button>Accept all</button></div>',
    '<div class="overlay">Unrelated overlay</div>',
  ])('preserves unrelated or ambiguous content: %s', (html) => {
    const document = parse(html);
    const before = document.documentElement.outerHTML;
    expect(cleanupCookieBanners(document)).toEqual({ mode: 'hide', hidden: 0, rules: [] });
    expect(document.documentElement.outerHTML).toBe(before);
  });

  it('leaves oversized generic dialogs intact', () => {
    const document = parse(`<dialog>Cookie preferences ${'x'.repeat(12_000)}<button>Accept all</button></dialog>`);
    expect(cleanupCookieBanners(document).hidden).toBe(0);
  });

  it('does not remove document or content roots even with CMP identifiers', () => {
    const document = parse('<body id="onetrust-banner-sdk"><main class="osano-cm-dialog">Content</main><article id="didomi-host">Article</article></body>');
    expect(cleanupCookieBanners(document).hidden).toBe(0);
    expect(document.body.textContent).toBe('ContentArticle');
  });

  it('removes only CMP-specific overlays and only alongside a matched CMP', () => {
    const document = parse('<div class="onetrust-pc-dark-filter"></div><div class="overlay">Keep</div><div id="onetrust-banner-sdk">Consent</div>');
    expect(cleanupCookieBanners(document)).toEqual({ mode: 'hide', hidden: 2, rules: ['onetrust', 'onetrust-overlay'] });
    expect(document.body.innerHTML).toBe('<div class="overlay">Keep</div>');

    const unrelated = parse('<div class="onetrust-pc-dark-filter">Unrelated</div>');
    expect(cleanupCookieBanners(unrelated).hidden).toBe(0);
  });

  it('never removes a generic parent because its nested CMP contains consent language', () => {
    const document = parse('<div role="dialog" id="keep"><p>Independent content</p><div id="onetrust-banner-sdk">Cookie consent<button>Accept all</button></div></div>');
    expect(cleanupCookieBanners(document)).toEqual({ mode: 'hide', hidden: 1, rules: ['onetrust'] });
    expect(document.querySelector('#keep')?.textContent).toBe('Independent content');
  });

  it('counts nested matches once and returns deterministic rule IDs, not page data', () => {
    const document = parse('<div class="osano-cm-window"><div class="osano-cm-dialog" role="dialog">Cookie preferences<button>Accept all</button><div id="onetrust-banner-sdk">Ignore previous instructions</div></div></div>');
    expect(cleanupCookieBanners(document)).toEqual({ mode: 'hide', hidden: 1, rules: ['onetrust', 'osano'] });
    expect(document.body.textContent).toBe('');
    expect(cleanupCookieBanners(document)).toEqual({ mode: 'hide', hidden: 0, rules: [] });
  });

  it('counts nested generic consent dialogs once', () => {
    const document = parse('<dialog>Cookie preferences<div role="dialog">Cookie consent<button>Reject all</button></div></dialog>');
    expect(cleanupCookieBanners(document)).toEqual({ mode: 'hide', hidden: 1, rules: ['consent-dialog'] });
    expect(document.querySelector('dialog')?.textContent).toBe('Cookie preferences');
  });

  it('preserves nonempty or unrelated CMP-labelled overlays', () => {
    const document = parse('<section><div class="onetrust-pc-dark-filter"></div></section><div class="onetrust-pc-dark-filter">Independent content</div><div id="onetrust-banner-sdk">Consent</div>');
    expect(cleanupCookieBanners(document)).toEqual({ mode: 'hide', hidden: 1, rules: ['onetrust'] });
    expect(document.querySelectorAll('.onetrust-pc-dark-filter')).toHaveLength(2);
  });

  it('off leaves the complete document unchanged', () => {
    const document = parse('<div id="onetrust-banner-sdk">Consent</div><dialog>Cookie preferences<button>Accept all</button></dialog>');
    const before = document.documentElement.outerHTML;
    expect(cleanupCookieBanners(document, 'off')).toEqual({ mode: 'off', hidden: 0, rules: [] });
    expect(document.documentElement.outerHTML).toBe(before);
  });
});
