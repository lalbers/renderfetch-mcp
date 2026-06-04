# Security

renderfetch-mcp is built to treat the web as hostile. This document summarizes the
threat model and how to report problems.

## Reporting a vulnerability

Please report security issues privately. Open a
[GitHub Security Advisory](https://docs.github.com/en/code-security/security-advisories)
on this repo (Security → Report a vulnerability) rather than a public issue.

## What's protected

- **Single-user gate.** Every request needs OAuth (with an explicit consent
  screen behind one username/password) or an optional static bearer token. Use a
  long `AUTH_PASSWORD` and a long `JWT_SECRET`.
- **OAuth 2.1.** Dynamic client registration, PKCE (S256), audience-bound access
  tokens, refresh-token rotation with reuse detection, a one-time-use consent
  step, and a rate-limited login.
- **Untrusted content.** Every fetched page is wrapped in a per-call, unguessable
  boundary fence and screened for prompt-injection patterns (instruction
  overrides, role/system tags, hidden / zero-width text, exfiltration phrasing,
  forged boundary markers). `FILTER_MODE=strict` blocks high-risk pages.
- **SSRF guard.** The fetcher refuses non-HTTP(S) schemes and any host that
  resolves to private / loopback / link-local / reserved ranges — including IPv6
  carriers of IPv4 (mapped, compatible, NAT64, 6to4) and cloud-metadata
  `169.254.169.254` — on the initial request and on redirects/subresources. Keep
  `FETCH_ALLOW_PRIVATE=false`.
- **Least-privilege container.** Runs rootless as a non-root user, `cap-drop=ALL`,
  `no-new-privileges`. Chromium runs with `--no-sandbox` because the container is
  the isolation boundary.

## Known residual risks

- **DNS rebinding.** The SSRF guard resolves names itself (with a short cache),
  but an attacker controlling a domain's DNS could race the resolution window.
  For hard isolation, run the container in a network namespace with an egress
  firewall that drops RFC1918 / link-local / ULA.
- **Prompt injection is probabilistic.** The filter and boundary reduce risk but
  cannot guarantee a model ignores cleverly-worded content. Be cautious enabling
  this alongside connectors that can read or send your private data.

## Hardening tips

- Serve over HTTPS only; never expose the container port to the public internet —
  only your reverse proxy should reach it.
- Set `OAUTH_ONLY=true` if you don't need the static-token path.
- Rotate `JWT_SECRET` to invalidate all issued access tokens.
- Keep `FETCH_ALLOW_PRIVATE=false` unless you fully trust every URL you fetch.
