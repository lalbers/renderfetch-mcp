# Security

## Reporting

Report vulnerabilities privately through this repository's GitHub Security
Advisories, not public issues. Include a minimal reproduction without real secrets.

## Threat model

This is a single-user public-web fetcher, not an authenticated browser or a general
browser-automation service. Assume every fetched page, script, URL, title, image,
redirect, and DNS answer is hostile. The server holds OAuth credentials and tokens;
fetched pages must not acquire their authority.

### Network boundary

Each render uses a new browser context and a loopback-only egress proxy. The proxy
resolves each new upstream connection and rejects the whole DNS answer if any address
is private, reserved, or special-purpose, including some ranges that are still
globally reachable. It then connects to a validated **numeric IP**. Chromium does not
resolve that destination again. HTTP Host and HTTPS end-to-end TLS validation
retain the original hostname. This covers redirects and subresources even when
Playwright routing does not see them. Contexts do not share upstream connections.

Only HTTP(S), credential-free URLs, and explicitly allowed destination ports are
accepted. `FETCH_ALLOWED_PORTS` defaults to `80,443`. `FETCH_ALLOW_PRIVATE=true`
relaxes the address restriction only; it does not disable scheme or port checks.
Never enable it for an internet-facing deployment.

Service workers, WebSockets, downloads, and extra pages are blocked or closed. CSP is
respected. QUIC and non-proxied WebRTC UDP are disabled as defense in depth. The
HTTP proxy allows only GET, HEAD, and OPTIONS.

HTTPS CONNECT is opaque. Method and request-count checks on HTTPS depend on
Playwright and are **not an absolute read-only network guarantee**. Even GET
requests can have server-side effects. POST-backed pages may not render completely.

### Output and prompt injection

- Active HTML, event handlers, unsafe links, remote images, comments, and common
  hidden content are removed before extraction, consistently across output formats.
- The complete bounded extracted document, title, and source URL are screened
  **before** the caller's output truncation. Unicode normalization precedes matching.
- Title and source URL exist only inside the random untrusted-content envelope.
  Structured metadata outside it contains server-generated fields, not page strings.
- Blocked results and errors do not echo hostile content or suggest disabling the
  filter. Enabled detector failures withhold content, including in lenient mode.
- `FILTER_MODE=lenient` is explicitly weaker: risky text may still be returned.
  Random markers are a labeling aid, not a model-enforced trust boundary.
- The optional ML tier is required to initialize when enabled. Limits are at most
  512 windows of 256 bytes with a 64-byte overlap (about 98 KB of normalized content)
  and 10 seconds per ML screening call, warmup included. Oversized input, a timeout,
  or a failed init fails closed rather than skipping that text. The regex layers have
  no such deadline.
- Screenshots are opt-in. Text preflight cannot detect all visual instructions or
  text added after the snapshot. Cookie cleanup does not modify screenshots.

**No filter guarantees immunity to prompt injection.** A downstream agent must not
interpret fetched content as authorization to use unrelated tools, disclose secrets,
change its policy, or execute code. Keep privileged or write-capable connectors
behind separate approvals. This server cannot enforce another client's tool
permissions.

### Cookie cleanup

`cookie_banner=hide` removes recognized cookie overlays from a **detached snapshot**.
It does not click buttons, reject or accept tracking, change browser cookies, run
event handlers, or bypass login, paywall, or CAPTCHA controls. Only banners present
when the snapshot is taken can be detected. Unsupported iframe or shadow content may
remain. Use `off` when the exact page content matters.

### Access control

MCP requires OAuth with the `mcp:fetch` scope, or an explicitly configured static
bearer. Authorization uses S256 PKCE, audience-, type-, and claim-checked JWTs,
bounded client registration, and one-time consent stored in SQLite.

Redirect URIs must match `https://claude.ai/api/mcp/auth_callback` or an
`EXTRA_REDIRECT_URIS` entry exactly, except loopback hosts (`localhost`, `127.0.0.1`,
`[::1]`), which native clients may use over HTTP or HTTPS on any port, path, or query
(RFC 8252). URIs with userinfo (a username or password) or a fragment are rejected.
Unauthenticated registrations that never obtain a token are pruned after
`OAUTH_UNUSED_CLIENT_TTL`; a client that retries an abandoned flow has to register
again.

On `/mcp`, a present `Origin` must be this server's origin or listed in
`ALLOWED_ORIGINS`. A missing `Origin` is allowed for non-browser clients. Consent
does not use that list. The consent POST must come from this server's own origin.
Consent responses are `no-store` and cannot be framed. The route defaults to
`Referrer-Policy: no-referrer`. A valid form overrides that with `same-origin`, and
a consent POST does too once the token is valid and the redirect target is allowed.
A cross-origin redirect does not receive the consent URL as a referrer. With
`same-origin`, Chromium still sends the real `Origin` on the consent POST; under
`no-referrer` it would send `Origin: null`.

Sessions bind to authentication kind, user, and client, not to token bytes.
Refreshing a token for the same identity works; another client cannot reuse the
session. Sessions have an idle expiry and a global cap plus a per-identity cap. The
`/mcp` limiter uses that stable identity, so a refresh does not open a new bucket.
Consent, `/authorize`, `/token`, `/register`, and `/revoke` are keyed by client IP.

Refresh tokens rotate atomically with a fixed family expiry. Replaying an old refresh
token revokes the family, rotation does not extend the original grant, and revocation
is client-bound. Existing surviving token chains are migrated; replay evidence
already deleted by older releases cannot be recovered, so reauthorize clients for a
clean grant history. Access JWTs remain valid until expiry. Rotate `JWT_SECRET` to
invalidate those access JWTs immediately; the static bearer is unaffected. Refresh
tokens survive a rotation; to cut off every OAuth client, also delete the database.
The SQLite file is sensitive: protect its volume and backups, including registered
client metadata.

## Deployment requirements and remaining risks

1. Terminate TLS at a trusted reverse proxy. Publish the container only on loopback.
   Inside the container the process binds `0.0.0.0` by default (`BIND_HOST`). Do not
   publish that socket on a public interface.

   Behind a proxy, set `TRUST_PROXY` to the proxy's address as seen inside the
   container (exact IP or CIDR). Do not use a hop count or an internet range. Without
   it, every caller shares the proxy's address. The IP-keyed limits on consent,
   `/authorize`, `/token`, `/register`, and `/revoke` collapse into one bucket.

   Only failed same-origin credential attempts that carry a valid signed request
   count toward the login limit. Anyone can obtain such a request, so without
   `TRUST_PROXY` any caller can lock the owner out. The shared proxy address is also
   one bucket for `/token`, and exhausting that bucket stops connectors from
   refreshing. List browser MCP clients in `ALLOWED_ORIGINS`. A missing `Origin`
   header stays allowed for server clients.

2. Leave Chromium's sandbox on (the default). With every capability dropped, the
   stock container seccomp profile denies the `chroot` the sandbox performs inside
   its own user namespace, so Chromium cannot start sandboxed. The Compose, Quadlet,
   and `podman run` examples therefore load `deploy/seccomp-chromium.json`: the
   containers-common default, plus that one change, generated by
   `scripts/seccomp-chromium.mjs`. The kernel still refuses `chroot` without the
   capability, so the sandbox works only inside a user namespace the process created.

   Under Docker the profile replaces Docker's stricter default, so it also permits
   unprivileged user namespaces, the mount API, and `keyctl`, among others, as
   Podman's default does. Verified with rootless Podman. Docker is untested. Hosts
   that forbid unprivileged user namespaces (an AppArmor policy, for example) cannot
   use the sandbox.

   `CHROMIUM_NO_SANDBOX=true` is a last resort. Do not disable TLS verification to
   make a site load.

3. **One container is not strong isolation against a browser compromise.** Renderers
   are sandboxed. The browser process, the GPU process, and the network service are
   not. The network service parses every fetched HTTP and TLS response and
   decompresses bodies. All of them share a user ID and a filesystem with the server.
   An exploit in one of those processes, or a renderer exploit plus a sandbox escape,
   can read OAuth data or the parent environment and can try to connect out directly.
   A minimal child environment reduces accidental exposure, not this compromise risk.

4. For a high-assurance deployment, put the browser in its own unprivileged worker
   or container. That worker gets no auth data and no secrets. Its network namespace,
   or a firewall, should allow only the guarded proxy. Drop private, link-local, and
   metadata destinations at the network layer as well. Chromium flags are not a
   substitute for that policy.

5. Use a read-only root filesystem; bounded tmpfs; CPU, memory, and PID limits;
   dropped capabilities; and no-new-privileges. The Compose, Quadlet, and
   `podman run` examples include these. A wire-byte limit does not stop every
   decompression bomb or JavaScript memory bomb. DOM limits do not interrupt every
   synchronous parse. Keep the container limits.

6. Keep the lockfile and the Chromium image current. Advisory audits cover known
   issues only. `npm audit` does not scan browser binaries or OS packages. Dependabot
   proposes npm and GitHub Actions updates. Bump the `playwright` package and the
   Containerfile base image tag together, by hand.

## Verification

Run the full suite with `RUN_E2E=1 npm test` in the matching Playwright environment.
Network tests assert that blocked targets receive no connections, not merely that
a fetch reports an error. CI also builds the server and runs
`npm audit --audit-level=high`. It does not build the container image.
