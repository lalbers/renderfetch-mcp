# Security

## Reporting

Report vulnerabilities privately through this repository's GitHub Security
Advisories, not public issues. Include a minimal reproduction without real secrets.

## Threat model

This is a single-user public-web fetcher, not an authenticated browser or a general
browser-automation service. Assume every fetched page, script, URL, title, image,
redirect and DNS answer is hostile. The server holds OAuth credentials and tokens;
fetched pages must not acquire their authority.

### Network boundary

Each render uses a new browser context and a loopback-only egress proxy. The proxy
resolves each new upstream connection, rejects an entire DNS answer containing a
non-public address, then connects to a validated **numeric IP**. Chromium does not
resolve that destination again. HTTP Host and HTTPS end-to-end TLS validation
retain the original hostname. This covers redirects and subresources even when
Playwright routing does not see them. Contexts do not share upstream connections.

Only HTTP(S), credential-free URLs and explicitly allowed destination ports are
accepted. `FETCH_ALLOWED_PORTS` defaults to `80,443`. `FETCH_ALLOW_PRIVATE=true`
relaxes the address restriction only; it does not disable scheme or port checks.
Never enable it for an internet-facing deployment.

Service workers, WebSockets, downloads and extra pages are blocked/closed. CSP is
respected. QUIC and non-proxied WebRTC UDP are disabled as defense in depth. HTTP
proxy requests permit only GET/HEAD/OPTIONS. HTTPS CONNECT is opaque; HTTPS method
and request-count checks rely on Playwright and are **not an absolute read-only
network guarantee**. Even GET requests can have server-side effects. POST-backed
pages may not render completely.

### Output and prompt injection

- Active HTML, event handlers, unsafe links, remote images, comments and common
  hidden content are removed before extraction, consistently across output formats.
- The complete bounded extracted document, title and source URL are screened
  **before** the caller's output truncation. Unicode normalization precedes matching.
- Title and source URL exist only inside the random untrusted-content envelope.
  Structured metadata outside it contains server-generated fields, not page strings.
- Blocked results and errors do not echo hostile content or suggest disabling the
  filter. Enabled detector failures withhold content, including in lenient mode.
- `FILTER_MODE=lenient` is explicitly weaker: risky text may still be returned.
  Random markers are a labeling aid, not a model-enforced trust boundary.
- The optional ML tier is required to initialize when enabled. It has explicit
  processing limits (512 overlapping 256-byte windows, approximately 98 KB of
  normalized content, and 10 seconds per screening call) and fails closed rather
  than silently skipping oversized text.
- Screenshots are opt-in. Text preflight cannot detect all visual instructions or
  text added after the snapshot. Cookie cleanup does not modify screenshots.

**No filter guarantees immunity to prompt injection.** A downstream agent must not
interpret fetched content as authorization to use unrelated tools, disclose secrets,
change its policy or execute code. Keep privileged/write-capable connectors behind
separate approvals. This server cannot enforce another client's tool permissions.

### Cookie cleanup

`cookie_banner=hide` removes recognized cookie overlays from a **detached snapshot**.
It does not click buttons, reject/accept tracking, change browser cookies, run event
handlers or bypass login/paywall/CAPTCHA controls. Only banners present when the
snapshot is taken can be detected. Unsupported iframe/shadow content may remain.
Use `off` when exact page content matters.

### Access control

MCP requires OAuth with `mcp:fetch` or an explicitly configured static bearer.
Authorization uses S256 PKCE, audience/type/claim-validated JWTs, bounded client
registration and one-use consent stored in SQLite. Redirect URIs must match the
claude.ai callback or an `EXTRA_REDIRECT_URIS` entry exactly, except loopback hosts
(`localhost`, `127.0.0.1`, `[::1]`), which are accepted over HTTP or HTTPS on any
port and path for native clients (RFC 8252). Unauthenticated registrations that
never obtain a token are pruned after `OAUTH_UNUSED_CLIENT_TTL`; a client that
retries an abandoned flow later must register again. Browser
origins are checked explicitly. Consent responses are no-store and protected against framing. Valid forms use
`Referrer-Policy: same-origin` (no cross-origin token leakage) so Chromium preserves
a usable same-origin POST Origin. Other consent responses use no-referrer.

Sessions bind to authentication kind, user and client, not token bytes. Refreshing
a token for the same identity works; another client cannot reuse the session.
Sessions have idle expiry and global/per-identity capacity limits. Rate limits use
stable identity rather than a rotating token.

Refresh tokens rotate atomically with fixed family expiry; replay revokes the
family. Rotation does not extend the original grant lifetime. Revocation is client-bound.
Existing surviving token chains are migrated; replay evidence already deleted by
older releases cannot be recovered. Reauthorize clients for a clean grant history. Access JWTs remain valid until expiry; rotate
`JWT_SECRET` for immediate global invalidation. SQLite data is sensitive: protect
its volume and backups, including registered client metadata.

## Deployment requirements and remaining risks

1. Terminate TLS at a trusted reverse proxy. Publish the container only on loopback.
   Behind a proxy, `TRUST_PROXY` is required: set the exact proxy IP/CIDR, never a
   generic hop count or arbitrary internet range. Without it, every caller shares
   the proxy's address and the IP-keyed limits on consent, `/authorize`, `/token`
   and `/register` become one global bucket. Only failed same-origin credential
   attempts with a valid signed request count toward the login limit, but anyone
   can obtain such a request, so an attacker can still keep the owner locked out
   and exhaust the `/token` limit that connectors need for refreshing. List browser
   MCP clients explicitly in `ALLOWED_ORIGINS`; absent Origin remains allowed for
   server clients.
2. Keep Chromium's sandbox enabled (the default). With all capabilities dropped,
   the stock container seccomp profile denies the `chroot` the sandbox performs
   inside its own user namespace, so Chromium cannot start sandboxed. The supplied
   Compose, Quadlet and `podman run` examples therefore load
   `deploy/seccomp-chromium.json`: the containers-common default profile with that
   single change, generated by `scripts/seccomp-chromium.mjs`. The kernel still
   refuses chroot without the capability, so it only works inside a user namespace
   the process created. Under Docker the profile replaces Docker's stricter default,
   so it also permits unprivileged user namespaces, the mount API and keyctl, among
   others, as Podman's default does. Verified with rootless Podman; Docker is untested, and
   hosts that forbid unprivileged user namespaces (for example via an AppArmor
   policy) cannot use the sandbox. `CHROMIUM_NO_SANDBOX=true` is a last resort.
   Do not disable TLS verification to make a site load.
3. **The single-container layout is not strong browser-compromise isolation.**
   Renderers are sandboxed, but the browser process, the GPU process and the network
   service are not. The network service parses every fetched HTTP/TLS response and
   decompresses bodies. All of them share a UID and filesystem with the server. An
   exploit in one of them, or a renderer exploit chained with a sandbox escape, can
   potentially read OAuth data or the parent environment and attempt direct egress.
   A minimal child environment reduces accidental exposure, not this compromise risk.
4. For high-assurance deployment, separate the browser into its own unprivileged
   worker/container with no auth data or secrets and a network namespace/firewall
   permitting only the guarded proxy. Drop private/link-local/metadata destinations
   at the network layer too. Chromium flags are not a substitute for that policy.
5. Use read-only rootfs, bounded tmpfs, CPU/memory/PID limits, dropped capabilities
   and no-new-privileges. The supplied Compose/Quadlet examples include these.
   Wire-byte limits cannot prevent every decompression or JavaScript memory bomb;
   DOM limits cannot interrupt all synchronous parsing work. Keep container limits.
6. Keep the lockfile and Chromium image current. Advisory audits cover known issues
   only; the npm audit does not scan browser binaries or OS packages. Dependabot
   proposes npm and GitHub Actions updates; bump the `playwright` package and the
   Containerfile base image tag together by hand.

## Verification

Run the full suite with `RUN_E2E=1 npm test` in the matching Playwright environment.
Network tests assert that blocked targets receive no connections, not merely that
a fetch reports an error. CI also builds and runs dependency advisory checks.
