import { JSDOM } from 'jsdom';
import { Readability } from '@mozilla/readability';
import TurndownService from 'turndown';
import { gfm } from 'turndown-plugin-gfm';

export type OutputFormat = 'markdown' | 'text' | 'html';

export interface ExtractInput {
  html: string;
  url: string;
  format: OutputFormat;
  cssSelector?: string;
  maxChars: number;
}

export interface ExtractResult {
  title: string | null;
  content: string;
  truncated: boolean;
}

function makeTurndown(): TurndownService {
  const td = new TurndownService({
    headingStyle: 'atx',
    codeBlockStyle: 'fenced',
    bulletListMarker: '-',
    emDelimiter: '*',
  });
  td.use(gfm);
  const DROP = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'IFRAME', 'SVG', 'CANVAS', 'FORM']);
  td.remove((node) => DROP.has(node.nodeName));
  return td;
}

function htmlToText(html: string): string {
  const dom = new JSDOM(html);
  const text = dom.window.document.body?.textContent ?? '';
  return text.replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
}

function normalizeMarkdown(md: string): string {
  return md.replace(/\n{3,}/g, '\n\n').trim();
}

export function extract(input: ExtractInput): ExtractResult {
  const baseDom = new JSDOM(input.html, { url: input.url });
  let title: string | null = baseDom.window.document.title || null;
  let contentHtml: string;

  if (input.cssSelector) {
    const el = baseDom.window.document.querySelector(input.cssSelector);
    contentHtml = el ? el.innerHTML : '';
  } else {
    // Readability mutates the document, so parse on a throwaway copy and keep
    // baseDom intact for the fallback.
    const rdDom = new JSDOM(input.html, { url: input.url });
    let article: ReturnType<Readability['parse']> = null;
    try {
      article = new Readability(rdDom.window.document).parse();
    } catch {
      article = null;
    }
    if (article && article.content) {
      contentHtml = article.content;
      title = article.title || title;
    } else {
      contentHtml = baseDom.window.document.body?.innerHTML ?? input.html;
    }
  }

  let content: string;
  if (input.format === 'html') {
    content = contentHtml.trim();
  } else if (input.format === 'text') {
    content = htmlToText(contentHtml);
  } else {
    content = normalizeMarkdown(makeTurndown().turndown(contentHtml));
  }

  let truncated = false;
  if (content.length > input.maxChars) {
    content = content.slice(0, input.maxChars);
    truncated = true;
  }

  return { title, content, truncated };
}
