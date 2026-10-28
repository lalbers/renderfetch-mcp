# Changelog

All notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [2.0.0] – 2026-10-28

A security hardening release with breaking configuration and output changes.
Read [Upgrading from 1.0.0](#upgrading-from-100) before rolling it out.

### Security

- Connection-level SSRF protection: every render gets a loopback-only egress proxy
  that validates the complete DNS answer, connects to the checked numeric IP and
  keeps Host/TLS validation on the original name. This closes DNS rebinding and
  covers redirects and subresources that Playwright routing never sees.
- Service workers, WebSockets, downloads, extra pages, QUIC and non-proxied
  WebRTC UDP are blocked, and so are write-method requests.
- Untrusted-output pipeline: consistent sanitizing across formats, Unicode
  normalization before matching, screening of the full bounded document before
  truncation, and page titles/URLs only inside the untrusted envelope. Errors no
  longer reflect page content.
- OAuth: a required `mcp:fetch` scope, sessions bound to client and identity,
  client-bound revocation, refresh-token families with replay detection and a
  fixed absolute expiry, and restart-safe one-use consent.
- The consent login limit counts only failed same-origin credential attempts, so
  anonymous junk requests can no longer lock the owner out.
- Dynamic client registrations that never obtain a token are pruned after
  `OAUTH_UNUSED_CLIENT_TTL`, so `/register` cannot be filled up permanently.
- Secret comparisons no longer leak the secret's length.
- Container deployments run Chromium's renderers in its sandbox, via
  `deploy/seccomp-chromium.json`. The container smoke test verifies it.
- Dependencies updated, `npm audit` clean: MCP SDK 1.32.2, Playwright 1.64.1,
  zod 4, jose 6, jsdom 30, express 5.3.

### Added

- `cookie_banner` tool option (`hide` by default) removes recognized consent
  overlays from the output snapshot without clicking or changing consent.
- Settings: `ALLOWED_ORIGINS`, `TRUST_PROXY`, `FETCH_ALLOWED_PORTS`,
  `FETCH_TIMEOUT_MS`, `FETCH_MAX_REQUESTS`, `FETCH_MAX_HTML_BYTES`,
  `FETCH_MAX_TRANSFER_BYTES`, `BROWSER_MAX_QUEUE`, `MCP_SESSION_TTL_MS`,
  `MCP_MAX_SESSIONS`, `MCP_MAX_SESSIONS_PER_CLIENT`, `OAUTH_MAX_CLIENTS`,
  `OAUTH_UNUSED_CLIENT_TTL` and `CLIENT_SECRET_TTL`.
- Real-browser security regression tests run in CI.

### Changed

- Page text is returned in both `content` and `structuredContent.text`. Some
  clients, including the claude.ai connector, render only `structuredContent`.
- Client secrets issued by dynamic registration live for one year
  (`CLIENT_SECRET_TTL`) instead of the SDK's 30 days.
- Client registrations are logged by `client_id` only, without client-supplied
  names or redirect URIs.
- Invalid configuration (short secrets, malformed booleans, out-of-range numbers)
  fails at startup. An empty `STATIC_BEARER_TOKEN` disables static bearer auth.

### Removed

- `structuredContent.title` and `structuredContent.final_url`. Read them from the
  fenced text instead.

### Upgrading from 1.0.0

- Node **22.22.2+**, **24.15+** or **26+** is required (Node 24 recommended). Use
  the committed lockfile.
- Back up the OAuth database first: the refresh-token migration is one-way.
  Rotations made under 1.0.0 cannot be recognized as replays afterwards.
- Existing tokens without `mcp:fetch` must reconnect. Refresh requires
  `offline_access`.
- Configuration is validated at startup. The example values from 1.0.0's
  `.env.example` (`change-me…`) are rejected. `AUTH_PASSWORD` needs 12+
  characters. `STATIC_BEARER_TOKEN` needs 32+ printable ASCII characters without
  whitespace. `PUBLIC_BASE_URL` must be an HTTPS origin (HTTP only for localhost).
  Booleans must be `true`/`false` (or `1`/`0`, `yes`/`no`, `on`/`off`), and numeric
  settings have bounds; the startup error names any value out of range.
- Clients registered under 1.0.0 keep their 30-day client secret. A connector may
  need to be re-linked once when it expires; new registrations get one year.
- `structuredContent.title` and `.final_url` are gone; read the fenced text.
- Behind a reverse proxy, set `TRUST_PROXY` to its address. Otherwise all clients
  share one rate-limit bucket and anyone can lock out the login.
- Browser tools such as MCP Inspector need an explicit `ALLOWED_ORIGINS` entry.
- Nonstandard destination ports require `FETCH_ALLOWED_PORTS`. Unsafe schemes and
  URL credentials are rejected even with private access enabled.
- JavaScript still runs, but service workers, WebSockets and write-method requests
  are blocked. Some POST-backed applications render incompletely.
- The code default of `CHROMIUM_NO_SANDBOX` changed from `true` to `false`. Add
  `deploy/seccomp-chromium.json` to your container setup (see the README).
  Without it Chromium cannot start sandboxed: `/healthz` still reports ok, but
  every fetch fails. 1.0.0's example `.env` set `CHROMIUM_NO_SANDBOX=true`
  explicitly: change it to `false` after adding the profile, or Chromium keeps
  running unsandboxed. Use `true` only as a last resort.
- Cookie cleanup defaults to `hide`. Use `cookie_banner: "off"` for unmodified
  consent text.

## [1.0.0] – 2026-06-04

First public release: a headless-Chromium `fetch_url` MCP tool with readability
extraction to Markdown, a self-contained OAuth 2.1 server (dynamic client
registration, PKCE, refresh-token rotation, SQLite store), prompt-injection
screening, an SSRF guard and rootless-Podman deployment examples.

[2.0.0]: https://github.com/lalbers/renderfetch-mcp/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/lalbers/renderfetch-mcp/releases/tag/v1.0.0
