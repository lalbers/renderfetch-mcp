# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- CI checks out the repository with `persist-credentials: false`.

### Changed

- `actions/checkout` and `actions/setup-node` are bumped to v7 and pinned to
  commit SHAs.
- The test suite uses Vitest 5.
- Dependabot ignores TypeScript major updates.
- The Quadlet install comment now includes `mkdir -p` and
  `loginctl enable-linger`.

## [2.0.0] - 2026-10-28

Security hardening release with breaking configuration and output changes.
Read [Upgrading from 1.0.0](#upgrading-from-100) before you roll it out.

### Security

- Each render gets a loopback-only egress proxy that checks the DNS answer
  and connects to a pinned numeric IP. This closes DNS rebinding.
- Service workers, WebSockets, downloads, extra pages, QUIC, and
  non-proxied WebRTC UDP are blocked. On plain HTTP the egress proxy
  allows only GET, HEAD, and OPTIONS. On HTTPS, Playwright rejects write
  methods in its route handler and counts requests through its request
  events. Neither is an absolute guarantee.
- Every output format is sanitized the same way, and the bounded document
  is screened before truncation.
- OAuth requires `mcp:fetch`. Sessions bind to the auth kind, the user, and
  the client. Refresh tokens use families, replay detection, and a fixed
  absolute expiry. Revocation is client-bound. Consent is one-use and
  survives a restart.
- Consent allows 10 failed attempts per 15 minutes. Only a failed
  same-origin credential attempt counts, so anonymous junk cannot lock the
  owner out.
- The hourly job deletes dynamic clients that never obtained a token and
  are older than `OAUTH_UNUSED_CLIENT_TTL`.
- Secret comparisons no longer leak the secret's length.
- Container deployments sandbox Chromium's renderers with
  `deploy/seccomp-chromium.json`.
- Dependencies: MCP SDK 1.32.2, Playwright 1.64.1, zod 4, jose 6, jsdom 30,
  express 5.3.

### Added

- `cookie_banner` (`hide` by default) removes recognized consent overlays
  from the output snapshot without clicking.
- Settings: `ALLOWED_ORIGINS`, `TRUST_PROXY`, `FETCH_ALLOWED_PORTS`,
  `FETCH_TIMEOUT_MS`, `FETCH_MAX_REQUESTS`, `FETCH_MAX_HTML_BYTES`,
  `FETCH_MAX_TRANSFER_BYTES`, `BROWSER_MAX_QUEUE`, `MCP_SESSION_TTL_MS`,
  `MCP_MAX_SESSIONS`, `MCP_MAX_SESSIONS_PER_CLIENT`, `OAUTH_MAX_CLIENTS`,
  `OAUTH_UNUSED_CLIENT_TTL`, and `CLIENT_SECRET_TTL`.
- Real-browser security regression tests run in CI.

### Changed

- Page text is returned in both `content` and `structuredContent.text`. Some
  clients, including the claude.ai connector, render only
  `structuredContent`.
- Dynamic-registration client secrets default to one year
  (`CLIENT_SECRET_TTL`) instead of the SDK's 30 days.
- Registrations are logged by `client_id` only, without client-supplied
  names or redirect URIs.
- Invalid configuration fails at startup. An empty `STATIC_BEARER_TOKEN`
  disables static bearer auth.

### Removed

- `structuredContent.title` and `structuredContent.final_url`.

### Upgrading from 1.0.0

- Before you replace the running container, add
  `deploy/seccomp-chromium.json` and set `CHROMIUM_NO_SANDBOX=false`. In
  1.0.0 the code default and example `.env` were `true` (unsandboxed), so
  a setup that never set the variable also changes.
- Use Node 22 (22.22.2 or later), Node 24 (24.15 or later), or Node 26 and
  later. Node 23 and 25 are not supported. Use the committed lockfile.
- Back up the OAuth database first. 1.0.0 deleted revoked refresh tokens in
  its hourly prune, so those tombstones cannot be rebuilt and a replay of
  one goes undetected. Surviving chains are migrated in place, and a replay
  of a stored row is detected. Reauthorize clients if that history matters.
- Existing tokens without `mcp:fetch` must reconnect. Refresh requires
  `offline_access`.
- Read the title and the source URL from the fenced text. This replaces the
  removed `structuredContent.title` and `structuredContent.final_url`.
- Configuration is validated at startup. Example `change-me…` secrets are
  rejected, and the error names any rejected setting.
- Clients registered under 1.0.0 keep their 30-day secret and may need one
  re-link when it expires. New secrets follow `CLIENT_SECRET_TTL`.
- Browser tools such as MCP Inspector need an explicit `ALLOWED_ORIGINS`
  entry.
- Behind a reverse proxy, set `TRUST_PROXY` to the proxy address seen inside
  the container.
- Nonstandard destination ports require `FETCH_ALLOWED_PORTS`.
- On HTTPS, Playwright's route handler rejects write methods it sees, but
  misses some requests. Plain HTTP is also limited at the egress proxy.
  Some POST-backed pages render incompletely.
- Cookie cleanup defaults to `hide`. Pass `cookie_banner: "off"` for the
  unmodified consent text.

## [1.0.0] - 2026-06-04

First public release: a headless-Chromium `fetch_url` MCP tool with
readability extraction to Markdown, a self-contained OAuth 2.1 server
(dynamic client registration, PKCE, refresh-token rotation, SQLite store),
prompt-injection screening, an SSRF guard, and rootless-Podman deployment
examples. The `v1.0.0` tag was created on 2026-10-28 and points at this
2026-06-04 tree.

[Unreleased]: https://github.com/lalbers/renderfetch-mcp/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/lalbers/renderfetch-mcp/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/lalbers/renderfetch-mcp/releases/tag/v1.0.0
