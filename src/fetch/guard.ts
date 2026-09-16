import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP, BlockList } from 'node:net';
import { config } from '../config.js';

/** Thrown when a URL or its resolved destination violates the network policy. */
export class FetchGuardError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FetchGuardError';
  }
}

export interface FetchUrlPolicy {
  // Explicitly opt out of address-class restrictions, including special-use
  // and translation ranges. URL syntax, port and DNS-answer checks still apply.
  allowPrivate?: boolean;
  allowedPorts?: readonly number[];
}

export interface FetchTargetOptions extends FetchUrlPolicy {
  lookup?: (hostname: string) => Promise<Array<{ address: string; family: number }>>;
  dnsTimeoutMs?: number;
}

export interface FetchTarget {
  url: URL;
  hostname: string;
  address: string;
  family: 4 | 6;
  port: number;
}

const DEFAULT_ALLOWED_PORTS = [80, 443] as const;
const DEFAULT_DNS_TIMEOUT_MS = 5_000;
const MAX_DNS_ANSWERS = 64;
const MAX_ACTIVE_DNS_LOOKUPS = 64;
let activeDnsLookups = 0;

/**
 * dns.lookup cannot be cancelled by a caller's timeout. Keep its slot occupied
 * until the actual OS lookup settles, otherwise repeated timeouts can build an
 * unbounded resolver queue. This cap is shared by every fetch and preflight;
 * overload fails immediately instead of creating another application queue.
 */
function boundedLookup(
  hostname: string,
  lookup: NonNullable<FetchTargetOptions['lookup']>,
): Promise<Array<{ address: string; family: number }>> {
  if (activeDnsLookups >= MAX_ACTIVE_DNS_LOOKUPS) {
    throw new FetchGuardError('DNS resolver capacity exceeded');
  }
  activeDnsLookups++;
  try {
    return Promise.resolve(lookup(hostname)).finally(() => { activeDnsLookups--; });
  } catch (error) {
    // Injectable resolvers may throw synchronously before returning a Promise.
    activeDnsLookups--;
    throw error;
  }
}

// Conservative special-purpose policy: some globally reachable exceptions in
// these ranges are deliberately unavailable. Keep this synchronized with the
// IANA IPv4/IPv6 Special-Purpose Address Registries rather than treating all
// non-RFC1918 addresses as safe Internet destinations.
const blockedV4 = new BlockList();
const V4: ReadonlyArray<readonly [string, number]> = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.31.196.0', 24],
  ['192.52.193.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['192.175.48.0', 24],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];
for (const [address, prefix] of V4) blockedV4.addSubnet(address, prefix, 'ipv4');

const globalV6 = new BlockList();
globalV6.addSubnet('2000::', 3, 'ipv6');
const blockedV6 = new BlockList();
blockedV6.addSubnet('2001::', 23, 'ipv6'); // IETF assignments, incl. Teredo, benchmarking, ORCHID
blockedV6.addSubnet('2001:db8::', 32, 'ipv6'); // documentation
blockedV6.addSubnet('2002::', 16, 'ipv6'); // deprecated 6to4; do not trust embedded IPv4
blockedV6.addSubnet('2620:4f:8000::', 48, 'ipv6'); // direct delegation AS112 service
blockedV6.addSubnet('3fff::', 20, 'ipv6'); // documentation

/**
 * True unless a literal address is permitted by our conservative public-only
 * policy. IPv6 must be ordinary global unicast: mapped/compatible IPv4, NAT64,
 * local-use translation, zone identifiers and other reserved ranges fail shut.
 */
export function isPrivateAddr(address: string): boolean {
  if (typeof address !== 'string' || address.includes('%')) return true;
  const family = isIP(address);
  if (family === 4) return blockedV4.check(address, 'ipv4');
  if (family === 6) {
    return !globalV6.check(address, 'ipv6') || blockedV6.check(address, 'ipv6');
  }
  return true;
}

const hostnameOf = (url: URL): string => url.hostname.replace(/^\[|\]$/g, '');
const portOf = (url: URL): number => Number(url.port || (url.protocol === 'https:' ? 443 : 80));

/** Pure URL validation, with secure defaults independent of process configuration. */
export function parseFetchUrl(raw: string, policy: FetchUrlPolicy = {}): URL {
  // WHATWG URL parsing silently removes tabs/newlines and rewrites backslashes.
  // Reject ambiguous inputs before parsing instead of validating another URL.
  if (
    typeof raw !== 'string' || raw.length === 0 || Buffer.byteLength(raw, 'utf8') > 8192 ||
    /[\s\u0000-\u001f\u007f-\u009f\\]/u.test(raw) || !/^https?:\/\//i.test(raw)
  ) {
    throw new FetchGuardError('Invalid HTTP(S) URL');
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new FetchGuardError('Invalid HTTP(S) URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new FetchGuardError('Only HTTP(S) URLs are allowed');
  }
  if (Buffer.byteLength(url.href, 'utf8') > 8192) {
    throw new FetchGuardError('URL exceeds the maximum encoded length');
  }
  // The raw authority check also catches empty userinfo, which URL normalizes
  // away (e.g. https://@example.com). Never pass URL credentials to a server.
  const authority = raw.slice(raw.indexOf('//') + 2).split(/[/?#]/, 1)[0] ?? '';
  if (!authority || authority.includes('@') || url.username || url.password) {
    throw new FetchGuardError('URL credentials are not allowed');
  }
  const port = portOf(url);
  if (!(policy.allowedPorts ?? DEFAULT_ALLOWED_PORTS).includes(port)) {
    throw new FetchGuardError('Destination port is not allowed');
  }
  const hostname = hostnameOf(url);
  const localName = hostname.toLowerCase().replace(/\.$/, '');
  if (!policy.allowPrivate && (
    localName === 'localhost' || localName.endsWith('.localhost') ||
    (isIP(hostname) !== 0 && isPrivateAddr(hostname))
  )) {
    throw new FetchGuardError('Private or reserved destinations are not allowed');
  }
  return url;
}

/**
 * Resolve once and return an approved literal IP for the caller to CONNECT to.
 * The caller MUST connect to `address`, not re-resolve `hostname`, while keeping
 * the original hostname for HTTP Host and TLS SNI/certificate verification.
 * Validate every answer before selecting one; mixed public/private DNS fails
 * closed. There is deliberately no cross-request verdict cache.
 * Raw inputs must first go through parseFetchUrl: URL construction itself loses
 * raw-only evidence such as empty userinfo or stripped tabs/newlines.
 */
export async function resolveFetchTarget(url: URL, options: FetchTargetOptions = {}): Promise<FetchTarget> {
  const checked = parseFetchUrl(url.href, options);
  const hostname = hostnameOf(checked);
  const literalFamily = isIP(hostname);
  let answers: Array<{ address: string; family: number }>;
  if (literalFamily !== 0) {
    answers = [{ address: hostname, family: literalFamily }];
  } else {
    const timeoutMs = options.dnsTimeoutMs ?? DEFAULT_DNS_TIMEOUT_MS;
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 60_000) {
      throw new FetchGuardError('Invalid DNS timeout');
    }
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const lookup = options.lookup ?? ((host: string) => dnsLookup(host, { all: true }));
      answers = await Promise.race([
        boundedLookup(hostname, lookup),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new FetchGuardError('DNS resolution timed out')), timeoutMs);
        }),
      ]);
    } catch (error) {
      if (error instanceof FetchGuardError) throw error;
      throw new FetchGuardError('DNS resolution failed');
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }
  if (!Array.isArray(answers) || answers.length === 0 || answers.length > MAX_DNS_ANSWERS) {
    throw new FetchGuardError('DNS returned no usable addresses');
  }
  for (const answer of answers) {
    const family = typeof answer?.address === 'string' ? isIP(answer.address) : 0;
    if (
      family === 0 || answer.family !== family || answer.address.includes('%') ||
      (!options.allowPrivate && isPrivateAddr(answer.address))
    ) {
      throw new FetchGuardError('DNS returned an invalid, private or reserved address');
    }
  }
  const selected = answers[0]!;
  return {
    url: checked,
    hostname,
    address: selected.address,
    family: selected.family as 4 | 6,
    port: portOf(checked),
  };
}

const configuredPolicy = (): FetchUrlPolicy => ({
  allowPrivate: config.FETCH_ALLOW_PRIVATE,
  allowedPorts: config.FETCH_ALLOWED_PORTS,
});

/** Compatibility preflight; this alone is NOT a connection-level SSRF boundary. */
export async function assertFetchableUrl(raw: string): Promise<URL> {
  const policy = configuredPolicy();
  const target = await resolveFetchTarget(parseFetchUrl(raw, policy), policy);
  return target.url;
}

/** Compatibility guard. Actual connections must use resolveFetchTarget's IP. */
export async function isTargetBlocked(raw: string): Promise<boolean> {
  try {
    await assertFetchableUrl(raw);
    return false;
  } catch {
    return true;
  }
}
