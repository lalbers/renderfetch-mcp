# Security

## Reporting

Report vulnerabilities in private. Open a GitHub Security Advisory:

https://github.com/lalbers/renderfetch-mcp/security/advisories/new

Do not file a public issue. Send a minimal reproduction and leave out real
secrets.

## Threat model

This is a single user fetcher for the public web, not an authenticated
browser or a general browser automation service. Treat every fetched page,
script, URL, title, image, redirect, and DNS answer as hostile. The server
holds OAuth credentials and tokens. A fetched page must not acquire them.

### Network boundary

Each render uses a new browser context and a loopback only egress proxy. The
proxy resolves every new upstream name, rejects the whole DNS answer if any
address is private, reserved, or special purpose (some of those ranges are
still globally reachable), and connects to one validated IP. The browser's
dead proxy at `127.0.0.1:9` blocks direct background HTTP. Host and
certificate checks use the original hostname. Redirects and subresources,
including requests Playwright routing does not see, take the same path. Do
not disable TLS verification.

Only HTTP and HTTPS URLs are accepted, with no username or password, and
only on ports in `FETCH_ALLOWED_PORTS` (default `80,443`).
`FETCH_ALLOW_PRIVATE=true` relaxes the address check only.

Service workers, WebSockets, downloads, and extra pages are blocked.
QUIC and non-proxied WebRTC UDP stay off so they cannot skip the proxy.

On plain HTTP the egress proxy allows only GET, HEAD, and OPTIONS. Each TLS
CONNECT counts toward `FETCH_MAX_REQUESTS`. The proxy cannot see methods or
requests inside a tunnel. On HTTPS, Playwright rejects write methods in its
route handler, which does not see every request, and counts requests through
its request events. Neither is an absolute guarantee. A GET can change state;
a rejected POST can leave a page incomplete.

### Output and prompt injection

- The sanitizer removes active HTML, event handlers, unsafe links, remote
  images, comments, and elements hidden by hidden, inert, or aria-hidden
  attributes or inline styles (display none, visibility hidden or collapse,
  zero opacity or font size, large negative left, top, or text-indent
  values) before extraction, in every format. Content hidden through
  stylesheets or classes can remain in the extracted text.
- The whole bounded document, the title, and the source URL are screened
  before truncation. Unicode is normalized before matching.
- The title and the source URL appear only inside a random untrusted-content
  envelope. Structured metadata outside it is server-generated and has no
  page strings.
- Blocked results and errors do not echo hostile content. A detector
  failure withholds the content, including in lenient mode.
- `FILTER_MODE=lenient` returns high and critical text in the same
  untrusted envelope. Risk is only in
  `structuredContent.filter.risk_level`. Strict blocks high and critical
  risk; medium-risk matches return in both modes. Boundary markers do not
  bind the model.
- With `FILTER_TIER2` enabled, startup warmup must finish or the server does
  not listen. One screening call has a 10-second deadline for any
  unfinished warmup and then every chunk: about 98 KB of normalized
  content (512 windows of 256 bytes with a 64-byte overlap). Concurrent
  ML screening caps at 4; a timed-out call keeps its slot until inference
  finishes. Oversized input, a timeout, an incomplete result, a failed
  init, or a further call while 4 are running (rejected, not queued)
  withholds the text. Regex layers have no deadline.
- Screenshots are opt-in. Text preflight misses some visual instructions and
  later text.

No filter makes prompt injection impossible. Keep privileged or
write-capable connectors behind separate approvals. This server cannot
enforce another client's tool permissions.

### Cookie cleanup

`cookie_banner=hide` removes recognized cookie overlays from a detached
snapshot. It does not click, change cookies, or bypass a login, paywall, or
CAPTCHA.

### Access control

MCP calls need OAuth with the `mcp:fetch` scope, or a configured static
bearer. Authorization uses S256 PKCE. JWTs are checked for audience, type,
and claims. Consent is one-time, stored in SQLite, and survives a restart.

A redirect URI must match `https://claude.ai/api/mcp/auth_callback` or an
`EXTRA_REDIRECT_URIS` entry exactly. RFC 8252's any-port rule applies to
the loopback literals `127.0.0.1` and `[::1]`. This server accepts any
port on the hostname `localhost`, and any path and query on all three, over
HTTP or HTTPS. Usernames, passwords, and fragments are rejected.

The hourly job deletes a client only when it never obtained a token and is
older than `OAUTH_UNUSED_CLIENT_TTL` (default 1 hour). Retrying an
abandoned flow requires a new registration only after that prune. The job
does not run at startup, so a registration burst can keep
`OAUTH_MAX_CLIENTS` full for up to the TTL plus one hour.

On `/mcp`, a present `Origin` must be this server's origin or listed in
`ALLOWED_ORIGINS`. A missing `Origin` is allowed for non-browser clients.
Consent ignores that list and requires this server's origin. Consent
responses are `no-store`, cannot be framed (`X-Frame-Options: DENY`,
`frame-ancestors`), and default to `Referrer-Policy: no-referrer`.
A valid form or POST sets `same-origin`, because `no-referrer` makes
Chromium send `Origin: null`. A cross-origin redirect does not receive the
consent URL.

Sessions bind to authentication kind, user, and client, not to token bytes.
That identity keeps its session across refresh. Another client cannot reuse
it. Idle expiry defaults to 15 minutes (`MCP_SESSION_TTL_MS`). Caps default
to 100 sessions (`MCP_MAX_SESSIONS`) and 10 per identity
(`MCP_MAX_SESSIONS_PER_CLIENT`). `/mcp` is limited per identity, so an
empty `TRUST_PROXY` does not affect it.

Consent, `/authorize`, `/token`, `/register`, and `/revoke` each have a
separate counter keyed by client address. Consent allows 10 failed attempts
per 15 minutes, and only a failed same-origin approve with a valid signed
request counts. The MCP SDK allows 100 `/authorize`, 50 `/token`, and 50
`/revoke` per 15 minutes, and 20 `/register` per hour. Set `TRUST_PROXY`
to the address the container sees. It depends on the Podman network mode.
Use an exact IP or CIDR, not a hop count or a wide public
range. If it is empty, every caller shares the peer address and one key
per limiter. Failed signed logins then share the consent limit, and
exhausting `/token` stops refresh.

Refresh tokens rotate in one transaction; the family keeps its original
expiry. Replaying an old refresh token revokes the family, bound to the
owning client. Access JWTs last `ACCESS_TOKEN_TTL` (default 1 hour).
Verification does not use the database, so revoking a refresh token does
not end them. Clients and consent records remain. Deleting the database,
a separate step, removes registered clients, refresh tokens, and consent
records. Rotate `JWT_SECRET` and delete the database to cut off every
OAuth client immediately. Rotation invalidates those JWTs and in-flight
consent requests signed with it. The static bearer and stored refresh
tokens survive a `JWT_SECRET` rotation. 1.0.0's prune deleted revoked
refresh tombstones, so they cannot be rebuilt. Surviving chains are
migrated, and a stored replay is detected. Protect that volume and its backups.

## Deployment requirements and remaining risks

1. Terminate TLS at a reverse proxy you trust, and publish the container
   only on loopback. The process binds `0.0.0.0` by default (`BIND_HOST`).

2. Leave Chromium's sandbox on (`CHROMIUM_NO_SANDBOX=false`, the default).
   With capabilities dropped, the stock seccomp profile blocks the sandbox
   `chroot`. Compose and `podman run` pass
   `deploy/seccomp-chromium.json`. Quadlet loads
   `~/.config/renderfetch-mcp-seccomp.json`
   (`SeccompProfile=%h/.config/renderfetch-mcp-seccomp.json`): the
   containers-common default plus one change, from
   `scripts/seccomp-chromium.mjs`. Podman refuses to start if that file is
   missing. `chroot` always needs `CAP_SYS_CHROOT`. The sandboxing process
   holds it inside the user namespace it creates, so allowing the syscall
   in seccomp is enough. The maintainer checked rootless
   Podman on 2026-10-28: sandboxed startup needs that profile, and the
   smoke test passes. With `false` and the stock profile, `/healthz`
   returns ok and every fetch fails. `true` leaves Chromium unsandboxed.

3. Docker is untested. Under Docker the file replaces a stricter default
   and permits unprivileged user namespaces, the mount API, and
   `keyctl`. Hosts that forbid unprivileged user namespaces cannot use this
   sandbox: Ubuntu's
   `kernel.apparmor_restrict_unprivileged_userns` or a disabled
   `kernel.unprivileged_userns_clone`.

4. One container is not strong isolation against a browser compromise.
   Renderers are sandboxed; the browser, GPU, and utility processes,
   including the network service, are not. That service parses every HTTP
   and TLS response and decompresses bodies. Those processes share the
   server's user and filesystem, so an exploit there, or a renderer exploit
   plus a sandbox escape, can read OAuth data or the parent environment and
   connect out. A reduced browser environment limits accidental exposure,
   not compromise.

5. For high assurance, put the browser in its own unprivileged worker with
   no auth data and no secrets, able to reach only the guarded proxy, and
   drop private, link-local, and metadata destinations.

6. Use a read-only root, bounded tmpfs, and CPU, memory, and PID limits.
   Drop capabilities and set no-new-privileges. Byte and DOM limits do not
   stop every decompression, script, or synchronous parse bomb.

7. Keep the lockfile and the Chromium image current. `npm audit` does not
   scan browser binaries or OS packages. Bump `playwright` and the
   Containerfile base image tag together by hand. Dependabot ignores
   `playwright` version updates.

## Verification

`RUN_E2E=1 npm test` includes network tests that require blocked targets to
receive no connection. CI builds the server, runs those tests with
`CHROMIUM_NO_SANDBOX=true` (`vitest.config.ts`), and runs
`npm audit --audit-level=high`. It does not build the image. Advisory
audits cover known issues only. A full `npm audit` at the 2.0.0 release
reported 0 vulnerabilities. Only `scripts/container-smoke.mjs`, run against
a locally built image, checks an active sandbox. It also checks a real render.
