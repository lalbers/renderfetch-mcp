export type CookieBannerMode = 'hide' | 'off';

export interface CookieBannerCleanup {
  mode: CookieBannerMode;
  /** Number of removed outermost DOM roots, including CMP-specific overlays. */
  hidden: number;
  /** Fixed rule identifiers only; never text or attributes supplied by a page. */
  rules: string[];
}

// Exact CMP UI selectors only. Do not add substring selectors such as [id*=cookie]
// or remove generic overlays: those can match articles, login, and access gates.
const CMP_RULES = [
  { id: 'onetrust', selector: '#onetrust-banner-sdk, #onetrust-pc-sdk' },
  { id: 'cookiebot', selector: '#CybotCookiebotDialog' },
  { id: 'didomi', selector: '#didomi-host' },
  { id: 'cookieyes', selector: '.cky-consent-container' },
  { id: 'osano', selector: '.osano-cm-window, .osano-cm-dialog' },
] as const;

type CookieRule = (typeof CMP_RULES)[number]['id'] | 'onetrust-overlay' | 'consent-dialog';
const RULE_ORDER: readonly CookieRule[] = [
  ...CMP_RULES.map((rule) => rule.id), 'onetrust-overlay', 'consent-dialog',
];
const PROTECTED_ROOTS = 'html, head, body, main, article';
const DIALOGS = 'dialog, [role="dialog"], [role="alertdialog"], [aria-modal="true"]';
const CONTROLS = 'button, [role="button"], input[type="button"], input[type="submit"]';
const AUTH_OR_CHALLENGE_CONTROLS = [
  'input:not([type="checkbox"]):not([type="radio"]):not([type="button"]):not([type="submit"]):not([type="hidden"])',
  '[data-sitekey]', '.g-recaptcha', '.h-captcha',
  'iframe[src*="recaptcha"]', 'iframe[src*="hcaptcha"]',
].join(', ');
const ACCESS_GATE_LANGUAGE = /\b(?:sign\s?in|log\s?in|subscribe|subscription|paywall|captcha|password|anmelden|einloggen|abonnieren|passwort)\b/i;
const COOKIE_LANGUAGE = /\bcookies?\b/i;
const CONSENT_LANGUAGE = /\b(?:consent|preferences|accept|reject|allow|decline|use\s+cookies?|cookies?\s+(?:settings|policy)|einwilligung|zustimmung|akzeptieren|ablehnen|cookie[- ]?einstellungen|(?:verwenden|nutzen)\s+(?:wir\s+)?cookies)\b/i;
const CONSENT_CONTROL = /^(?:(?:accept|reject|allow|decline)(?:\s+(?:all|cookies|all\s+cookies|optional\s+cookies))?|(?:manage|save|cookie)\s+(?:preferences|settings)|(?:only\s+)?(?:necessary|essential)\s+(?:cookies|only)|(?:continue|proceed)\s+without\s+(?:accepting|consent)|i\s+agree|agree(?:\s+and\s+continue)?|(?:alle\s+)?(?:akzeptieren|ablehnen)|nur\s+(?:notwendige|essenzielle)(?:\s+cookies)?|(?:cookie[- ]?)?einstellungen(?:\s+(?:speichern|verwalten))?)[.!]?$/i;

function isConsentDialog(element: Element): boolean {
  if (element.matches(PROTECTED_ROOTS) || element.querySelector(`main, article, ${DIALOGS}`)) return false;
  if (element.querySelector(AUTH_OR_CHALLENGE_CONTROLS)) return false;

  // Keep the fallback conservative and bounded. Long dialogs are more likely to
  // contain substantive content than a consent notice and are left untouched.
  let rawText = element.getAttribute('aria-label') ?? '';
  const textNodes = element.ownerDocument.createTreeWalker(element, 4 /* SHOW_TEXT */);
  let node = textNodes.nextNode();
  while (node) {
    if (!node.parentElement?.closest('script, style, noscript, template')) {
      rawText += ` ${node.textContent ?? ''}`;
      if (rawText.length > 12_000) return false;
    }
    node = textNodes.nextNode();
  }
  const text = rawText.replace(/\s+/g, ' ').trim();
  if (!COOKIE_LANGUAGE.test(text) || !CONSENT_LANGUAGE.test(text) || ACCESS_GATE_LANGUAGE.test(text)) {
    return false;
  }

  return [...element.querySelectorAll(CONTROLS)].some((control) => {
    const label = (control.getAttribute('aria-label') ?? control.getAttribute('value') ?? control.textContent ?? '')
      .replace(/\s+/g, ' ').trim();
    return label.length <= 100 && CONSENT_CONTROL.test(label);
  });
}

/**
 * Remove cookie UI from an inert, detached extraction document only.
 * This is cosmetic snapshot cleanup, not acceptance or rejection of consent.
 * Never run it in the rendered page: no clicks, handlers, cookies, or storage
 * changes are needed, and access gates must remain intact.
 */
export function cleanupCookieBanners(
  document: Document,
  mode: CookieBannerMode = 'hide',
): CookieBannerCleanup {
  if (mode === 'off') return { mode, hidden: 0, rules: [] };

  const candidates = new Map<Element, Set<CookieRule>>();
  const add = (element: Element, rule: CookieRule): void => {
    if (element.matches(PROTECTED_ROOTS)) return;
    const rules = candidates.get(element) ?? new Set<CookieRule>();
    rules.add(rule);
    candidates.set(element, rules);
  };

  for (const rule of CMP_RULES) {
    for (const element of document.querySelectorAll(rule.selector)) add(element, rule.id);
  }

  // Only suppress this precise OneTrust overlay if its actual CMP UI exists.
  const oneTrust = [...candidates].filter(([, rules]) => rules.has('onetrust')).map(([element]) => element);
  if (oneTrust.length) {
    for (const element of document.querySelectorAll('.onetrust-pc-dark-filter')) {
      if (!element.childElementCount && !element.textContent?.trim()
        && oneTrust.some((banner) => banner.parentElement === element.parentElement)) {
        add(element, 'onetrust-overlay');
      }
    }
  }

  const knownCandidates = [...candidates.keys()];
  for (const element of document.querySelectorAll(DIALOGS)) {
    // A generic parent must not disappear merely because it contains a CMP.
    if (knownCandidates.some((known) => known.contains(element) || element.contains(known))) continue;
    if (isConsentDialog(element)) add(element, 'consent-dialog');
  }

  const matchedRules = new Set<CookieRule>();
  const roots: Element[] = [];
  for (const [element, rules] of candidates) {
    for (const rule of rules) matchedRules.add(rule);
    let parent = element.parentElement;
    while (parent && !candidates.has(parent)) parent = parent.parentElement;
    if (!parent) roots.push(element);
  }
  for (const root of roots) root.remove();

  return { mode, hidden: roots.length, rules: RULE_ORDER.filter((rule) => matchedRules.has(rule)) };
}
