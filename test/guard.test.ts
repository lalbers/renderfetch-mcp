import { describe, it, expect } from 'vitest';
import { isPrivateAddr } from '../src/fetch/guard.js';

// H1 regression guard: every private/reserved form (incl. IPv6 carriers of
// IPv4) must be blocked; genuine public addresses must be allowed.
describe('SSRF address classification (isPrivateAddr)', () => {
  const mustBlock = [
    '127.0.0.1',
    '10.1.2.3',
    '172.16.0.1',
    '192.168.1.1',
    '169.254.169.254', // cloud metadata
    '100.64.0.1', // CGNAT
    '0.0.0.0',
    '::1',
    '::',
    'fe80::1',
    'fc00::1',
    'fd12:3456::1',
    'fec0::1', // site-local
    'ff02::1', // multicast
    '::ffff:127.0.0.1', // IPv4-mapped (dotted)
    '::ffff:169.254.169.254',
    '::ffff:a9fe:a9fe', // IPv4-mapped (compressed hex)
    '::a9fe:a9fe', // IPv4-compatible -> 169.254.169.254
    '::7f00:1', // IPv4-compatible -> 127.0.0.1
    '64:ff9b::a9fe:a9fe', // NAT64 -> 169.254.169.254
    '2002:a9fe:a9fe::', // 6to4 -> 169.254.169.254
  ];
  const mustAllow = [
    '8.8.8.8',
    '1.1.1.1',
    '93.184.216.34',
    '2606:4700:4700::1111', // public IPv6
    '2a03:4000:3e:15e::1', // the server's own public AAAA
  ];

  for (const a of mustBlock) it(`blocks ${a}`, () => expect(isPrivateAddr(a)).toBe(true));
  for (const a of mustAllow) it(`allows ${a}`, () => expect(isPrivateAddr(a)).toBe(false));
});
