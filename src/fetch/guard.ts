import { lookup } from 'node:dns/promises';
import { isIP, BlockList } from 'node:net';
import { config } from '../config.js';

/** Thrown when a URL is rejected before any network access (SSRF guard). */
export class FetchGuardError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FetchGuardError';
  }
}

// Loopback, private, link-local (incl. cloud metadata 169.254.169.254), CGNAT,
// multicast, and reserved ranges. net.BlockList does correct subnet matching.
const blocked = new BlockList();
const V4: ReadonlyArray<readonly [string, number]> = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];
for (const [addr, prefix] of V4) blocked.addSubnet(addr, prefix, 'ipv4');
blocked.addAddress('::1', 'ipv6'); // loopback
blocked.addAddress('::', 'ipv6'); // unspecified
blocked.addSubnet('fc00::', 7, 'ipv6'); // unique local
blocked.addSubnet('fe80::', 10, 'ipv6'); // link-local
blocked.addSubnet('fec0::', 10, 'ipv6'); // site-local (deprecated, still routable on some stacks)
blocked.addSubnet('ff00::', 8, 'ipv6'); // multicast

const isPrivateV4 = (addr: string): boolean => blocked.check(addr, 'ipv4');

// Parse any IPv6 textual form (incl. "::" compression and a trailing dotted
// IPv4) into 16 bytes. Returns null if it isn't a parseable IPv6 literal.
function parseIPv6ToBytes(input: string): number[] | null {
  let s = input;
  const pct = s.indexOf('%');
  if (pct >= 0) s = s.slice(0, pct); // strip zone id
  if (s.length === 0) return null;

  // Convert a trailing dotted-quad (e.g. ::ffff:127.0.0.1) into two hextets.
  const dot = s.indexOf('.');
  if (dot >= 0) {
    const lastColon = s.lastIndexOf(':', dot);
    if (lastColon < 0) return null;
    const quad = s.slice(lastColon + 1).split('.');
    if (quad.length !== 4) return null;
    const o = quad.map(Number);
    if (o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    const h1 = (((o[0] ?? 0) << 8) | (o[1] ?? 0)).toString(16);
    const h2 = (((o[2] ?? 0) << 8) | (o[3] ?? 0)).toString(16);
    s = s.slice(0, lastColon + 1) + h1 + ':' + h2;
  }

  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : null;

  let hextets: string[];
  if (tail === null) {
    hextets = head;
    if (hextets.length !== 8) return null;
  } else {
    const missing = 8 - (head.length + tail.length);
    if (missing < 1) return null; // "::" must compress at least one group
    hextets = [...head, ...Array(missing).fill('0'), ...tail];
  }
  if (hextets.length !== 8) return null;

  const bytes: number[] = [];
  for (const h of hextets) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(h)) return null;
    const v = parseInt(h, 16);
    bytes.push((v >> 8) & 0xff, v & 0xff);
  }
  return bytes;
}

// Extract the embedded IPv4 from the known IPv6→IPv4 carriers so they can be
// range-checked. Covers IPv4-mapped (::ffff:0:0/96), IPv4-compatible (::/96),
// NAT64 (64:ff9b::/96) and 6to4 (2002::/16). Without this, e.g. [::a9fe:a9fe]
// or [64:ff9b::a9fe:a9fe] would smuggle 169.254.169.254 past the v4 guard.
function embeddedV4(b: number[]): string | null {
  const zero = (from: number, to: number) => b.slice(from, to).every((x) => x === 0);
  const quad = (i: number) => `${b[i]}.${b[i + 1]}.${b[i + 2]}.${b[i + 3]}`;
  if (zero(0, 10) && b[10] === 0xff && b[11] === 0xff) return quad(12); // ::ffff:a.b.c.d
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && zero(4, 12)) return quad(12); // 64:ff9b::
  if (b[0] === 0x20 && b[1] === 0x02) return quad(2); // 2002:: (6to4)
  if (zero(0, 12)) return quad(12); // ::a.b.c.d (IPv4-compatible)
  return null;
}

/** True if a literal IP address is private/reserved/loopback/link-local. */
export function isPrivateAddr(addr: string): boolean {
  const v = isIP(addr);
  if (v === 0) return true; // not a literal IP -> fail closed
  if (v === 6) {
    const bytes = parseIPv6ToBytes(addr);
    if (bytes) {
      const emb = embeddedV4(bytes);
      if (emb && isPrivateV4(emb)) return true;
    }
    return blocked.check(addr, 'ipv6');
  }
  return isPrivateV4(addr);
}

async function resolveAddresses(host: string): Promise<string[]> {
  if (isIP(host)) return [host];
  const res = await lookup(host, { all: true });
  return res.map((r) => r.address);
}

/**
 * Async, DNS-resolving guard for the top-level navigation target. Rejects
 * non-http(s) schemes and any host that resolves to a private/reserved address.
 */
export async function assertFetchableUrl(raw: string): Promise<URL> {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new FetchGuardError('Invalid URL');
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new FetchGuardError(`Unsupported protocol "${u.protocol}" (only http and https are allowed)`);
  }
  if (config.FETCH_ALLOW_PRIVATE) return u;

  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (host.toLowerCase() === 'localhost') throw new FetchGuardError('Refusing to fetch localhost');

  let addresses: string[];
  try {
    addresses = await resolveAddresses(host);
  } catch {
    throw new FetchGuardError(`DNS resolution failed for "${host}"`);
  }
  if (addresses.length === 0) throw new FetchGuardError(`No addresses found for "${host}"`);
  for (const a of addresses) {
    if (isPrivateAddr(a)) {
      throw new FetchGuardError(`Refusing to fetch private/reserved address (${host} -> ${a})`);
    }
  }
  return u;
}

// Short-lived verdict cache so the per-request route guard can resolve DNS for
// every request (incl. redirects/subresources, by hostname) without hammering
// the resolver. This narrows the DNS-rebinding window left by checking only the
// initial navigation target. Residual TOCTOU is documented in the README.
const verdictCache = new Map<string, { blocked: boolean; exp: number }>();
const VERDICT_TTL_MS = 30_000;

/**
 * Per-request guard used by the Playwright router: resolves the host (cached)
 * and blocks non-http(s) schemes plus any private/reserved target. Fails closed.
 */
export async function isTargetBlocked(raw: string): Promise<boolean> {
  if (config.FETCH_ALLOW_PRIVATE) return false;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return true;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return true;
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (host.toLowerCase() === 'localhost') return true;

  const now = Date.now();
  const cached = verdictCache.get(host);
  if (cached && cached.exp > now) return cached.blocked;

  let result: boolean;
  try {
    const addresses = await resolveAddresses(host);
    result = addresses.length === 0 || addresses.some((a) => isPrivateAddr(a));
  } catch {
    result = true; // fail closed on resolution failure
  }
  if (verdictCache.size > 1000) verdictCache.clear();
  verdictCache.set(host, { blocked: result, exp: now + VERDICT_TTL_MS });
  return result;
}
