import { JSDOM } from 'jsdom';
import { Readability } from '@mozilla/readability';
import TurndownService from 'turndown';
import { gfm } from 'turndown-plugin-gfm';
import { config } from '../config.js';
import { cleanupCookieBanners, type CookieBannerMode, type CookieBannerCleanup } from './cookies.js';

export type OutputFormat = 'markdown' | 'text' | 'html';

export interface ExtractInput {
  html: string;
  url: string;
  format: OutputFormat;
  cssSelector?: string;
  maxChars: number;
  cookieBanner?: CookieBannerMode;
}

export interface ExtractResult {
  title: string | null;
  content: string;
  truncated: boolean;
  cookieBanner: CookieBannerCleanup;
}

// A small, inert document vocabulary. Foreign namespaces and active elements
// are dropped. Custom app wrappers become ordinary divs with no behavior/attrs.
const ALLOWED_TAGS = new Set([
  'a', 'abbr', 'address', 'article', 'aside', 'b', 'blockquote', 'br', 'caption',
  'cite', 'code', 'col', 'colgroup', 'dd', 'del', 'details', 'dfn', 'div', 'dl',
  'dt', 'em', 'figcaption', 'figure', 'footer', 'h1', 'h2', 'h3', 'h4', 'h5',
  'h6', 'header', 'hr', 'i', 'kbd', 'li', 'main', 'mark', 'nav', 'ol', 'p',
  'pre', 'q', 's', 'samp', 'section', 'small', 'span', 'strong', 'sub',
  'summary', 'sup', 'table', 'tbody', 'td', 'th', 'thead', 'time', 'tr', 'u',
  'ul', 'var', 'wbr',
]);
const BLOCK_TAGS = new Set([
  'address', 'article', 'aside', 'blockquote', 'br', 'dd', 'div', 'dl', 'dt',
  'figcaption', 'figure', 'footer', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'header', 'hr', 'li', 'main', 'nav', 'ol', 'p', 'pre', 'section', 'table',
  'tr', 'ul',
]);

// Do not let literal Markdown copied from page text recreate remote image
// beacons in a Markdown-rendering MCP client (including text/HTML formats).
function inertText(text: string): string {
  return text.replace(/!\[/g, '！[');
}

function isHidden(element: Element): boolean {
  if (element.hasAttribute('hidden') || element.hasAttribute('inert') ||
      element.getAttribute('aria-hidden')?.trim().toLowerCase() === 'true') return true;
  const style = (element.getAttribute('style') ?? '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\\([0-9a-f]{1,6})\s?|\\(.)/gi, (_match, hex: string | undefined, literal: string) => {
      const cp = hex ? Number.parseInt(hex, 16) : undefined;
      return cp !== undefined && cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : literal ?? '';
    });
  return /(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*(?:hidden|collapse)|(?:opacity|font-size)\s*:\s*[+-]?(?:0+(?:\.0*)?|\.0+)(?:[a-z%]+)?(?:\s*!important)?\s*(?:;|$)|(?:left|top|text-indent)\s*:\s*-\s*\d{3,}(?:px|em|rem))/i.test(style);
}

function safeHref(value: string, base: string): string | null {
  if (Buffer.byteLength(base, 'utf8') > 8192) throw new Error('Document base URL exceeds the extraction limit');
  if (/[\u0000-\u001f\u007f-\u009f\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u.test(value)) return null;
  try {
    const url = new URL(value, base);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
    return url.href;
  } catch {
    return null;
  }
}

interface SanitizerBudget { bytes: number; nodes: number; replacements?: WeakMap<Element, Element> }
function consume(budget: SanitizerBudget, value: string, attribute = false): void {
  // Include HTML serialization expansion before assigning an expanded href or
  // retaining a text node. This prevents many short relative links plus a long
  // base URL from creating an unbounded intermediate DOM/string.
  budget.bytes += Buffer.byteLength(value, 'utf8');
  for (const char of value) {
    if (char === '&') budget.bytes += 4;
    else if (char === '<' || char === '>') budget.bytes += 3;
    else if (attribute && char === '"') budget.bytes += 5;
  }
  if (budget.bytes > config.FETCH_MAX_HTML_BYTES) throw new Error('Sanitized document exceeds the extraction byte limit');
}

/** Sanitize before every extraction route, including the Readability fallback. */
function sanitize(root: Element, baseUrl: string, budget: SanitizerBudget = { bytes: 0, nodes: 0 }, depth = 0): void {
  if (depth > 128) throw new Error('Document exceeds the extraction nesting limit');
  for (const child of [...root.childNodes]) {
    if (++budget.nodes > 50000) throw new Error('Document exceeds the extraction node limit');
    if (child.nodeType === 3) {
      const text = inertText(child.textContent ?? '');
      consume(budget, text);
      child.textContent = text;
      continue;
    }
    if (child.nodeType !== 1) {
      child.remove(); // comments, processing instructions, etc.
      continue;
    }
    let element = child as Element;
    let tag = element.localName.toLowerCase();
    if (element.namespaceURI !== 'http://www.w3.org/1999/xhtml' || isHidden(element)) {
      element.remove();
      continue;
    }
    if (tag === 'img') {
      const alt = inertText(element.getAttribute('alt') ?? '');
      consume(budget, alt);
      element.replaceWith(root.ownerDocument.createTextNode(alt));
      continue;
    }
    if (!ALLOWED_TAGS.has(tag)) {
      if (/^[a-z][a-z0-9]*-[a-z0-9-]+$/.test(tag) &&
          !/^(?:system|assistant|developer|prompt|instruction|instructions|admin|im)-/.test(tag)) {
        // Framework roots (<app-root>, etc.) often contain the entire article.
        // Preserve their already-rendered children, never the custom behavior.
        const wrapper = root.ownerDocument.createElement('div');
        while (element.firstChild) wrapper.appendChild(element.firstChild);
        element.replaceWith(wrapper);
        budget.replacements?.set(element, wrapper);
        element = wrapper;
        tag = 'div';
      } else {
        element.remove();
        continue;
      }
    }
    budget.bytes += tag.length * 2 + 5;
    consume(budget, '');
    const href = tag === 'a' && element.hasAttribute('href')
      ? safeHref(element.getAttribute('href')!, baseUrl) : null;
    const numeric = new Map<string, string>();
    for (const name of tag === 'td' || tag === 'th' ? ['colspan', 'rowspan'] : tag === 'ol' ? ['start'] : []) {
      const value = element.getAttribute(name);
      if (value && /^\d{1,4}$/.test(value) && Number(value) > 0) numeric.set(name, value);
    }
    for (const attribute of [...element.attributes]) element.removeAttribute(attribute.name);
    if (href) {
      consume(budget, href, true);
      consume(budget, ' href=');
      budget.bytes += 2;
      element.setAttribute('href', href);
    }
    for (const [name, value] of numeric) {
      consume(budget, `${name}=${value}`);
      budget.bytes += 3;
      element.setAttribute(name, value);
    }
    sanitize(element, baseUrl, budget, depth + 1);
  }
}

function makeTurndown(): TurndownService {
  const td = new TurndownService({
    headingStyle: 'atx',
    codeBlockStyle: 'fenced',
    bulletListMarker: '-',
    emDelimiter: '*',
  });
  td.use(gfm);
  return td;
}

function toText(root: Node): string {
  let text = '';
  for (const node of [...root.childNodes]) {
    if (node.nodeType === 3) text += node.textContent ?? '';
    else if (node.nodeType === 1) {
      const tag = (node as Element).localName;
      const content = toText(node);
      text += BLOCK_TAGS.has(tag) ? `\n${content}\n` : tag === 'td' || tag === 'th' ? `${content}\t` : content;
    }
  }
  return text;
}

export function extract(input: ExtractInput): ExtractResult {
  if (Buffer.byteLength(input.html, 'utf8') > config.FETCH_MAX_HTML_BYTES) {
    throw new Error('Rendered document exceeds the configured HTML byte limit');
  }
  if (!Number.isSafeInteger(input.maxChars) || input.maxChars < 0) throw new Error('Invalid extraction character limit');
  // No runScripts/resources options: this detached DOM never executes scripts,
  // loads resources, clicks consent controls, or changes the live browser page.
  const baseDom = new JSDOM(input.html, { url: input.url });
  let outputDom: JSDOM | undefined;
  try {
    const document = baseDom.window.document;
    let title: string | null = document.title || null;
    const cookieBanner = cleanupCookieBanners(document, input.cookieBanner ?? 'hide');
    // Keep the selected node reference while stripping selector attributes.
    let selected = input.cssSelector ? document.querySelector(input.cssSelector) : null;
    if (input.cssSelector && !selected) throw new Error('CSS selector did not match any element');
    if (isHidden(document.documentElement) || isHidden(document.body)) document.body.replaceChildren();
    const replacements = new WeakMap<Element, Element>();
    sanitize(document.body, input.url, { bytes: 0, nodes: 0, replacements });
    if (selected) selected = replacements.get(selected) ?? selected;
    let contentHtml: string;
    if (input.cssSelector) {
      contentHtml = selected?.isConnected && document.body.contains(selected) ? selected.outerHTML : '';
    } else {
      // Clone the already-cleaned document; never let the fallback resurrect
      // removed hidden text, forms, comments, scripts, or cookie banners.
      const copy = document.cloneNode(true) as Document;
      let article: ReturnType<Readability['parse']> = null;
      try {
        article = new Readability(copy).parse();
      } catch {
        article = null;
      }
      contentHtml = article?.content || document.body.innerHTML;
      title = article?.title || title;
    }

    // Readability can insert markup/attributes. Apply the same allowlist again
    // so text, Markdown and HTML have precisely the same content trust policy.
    if (Buffer.byteLength(contentHtml, 'utf8') > config.FETCH_MAX_HTML_BYTES) {
      throw new Error('Article extraction exceeds the HTML byte limit');
    }
    outputDom = new JSDOM(contentHtml, { url: input.url });
    sanitize(outputDom.window.document.body, input.url);
    const body = outputDom.window.document.body;
    let content: string;
    if (input.format === 'html') {
      content = body.innerHTML.trim();
    } else {
      content = input.format === 'text' ? toText(body) : makeTurndown().turndown(body.innerHTML);
      // Decoded literal HTML must not become active markup when a client renders
      // a text/Markdown response. Existing HTML entities remain ordinary text.
      content = inertText(content).replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
    }
    if (Buffer.byteLength(content, 'utf8') > config.FETCH_MAX_HTML_BYTES) {
      throw new Error('Converted document exceeds the extraction byte limit');
    }
    const truncated = content.length > input.maxChars;
    if (truncated) content = content.slice(0, input.maxChars);
    return { title, content, truncated, cookieBanner };
  } finally {
    outputDom?.window.close();
    baseDom.window.close();
  }
}
