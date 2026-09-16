# Security and browser improvement plan

## Scope

Harden the single-user remote MCP fetcher without adding arbitrary browser automation,
authenticated browsing, or write tools. Preserve page text in both MCP result channels.
No production deployment, secrets rotation, host package installation, or git push.

## Audit findings (2026-09-16)

1. **Critical: network enforcement is not at the connection boundary.** Playwright
   routing does not intercept every redirected request, service workers can bypass
   interception, and WebSockets use separate routing. Guard DNS lookups are separate
   from Chromium connections, permitting DNS rebinding. `src/fetch/browser.ts`,
   `src/fetch/guard.ts`.
2. **High: page-controlled output bypasses filtering.** Titles and URLs appear outside
   the boundary, including blocked results. Error strings can echo hostile content.
   Normalization happens after pattern matching. HTML/text extraction retains hidden
   or active content in some paths. `src/fetch/tool.ts`, `src/fetch/extract.ts`,
   `src/filter/patterns.ts`.
3. **High: incomplete MCP access boundaries.** Origin reflection, no required fetch
   scope, sessions not bound to clients, no session TTL/cap. `src/http.ts`,
   `src/auth/bearer.ts`, `src/mcp/transport.ts`.
4. **Medium: OAuth lifecycle gaps.** Revocation does not check client ownership;
   pruning removes replay evidence prematurely; consent lacks browser security
   headers and restart-safe one-use persistence. Redirect validation is broader than
   the advertised exact callback policy. `src/auth`, `src/store`.
5. **Medium: resource exhaustion.** Browser queue, rendered DOM and session storage
   lack explicit bounds. Configuration accepts invalid/negative numeric values and
   typoed booleans. `src/config.ts`, `src/fetch/browser.ts`.
6. **Usability/testing.** No cookie overlay handling. Real-browser tests are opt-in
   and absent from CI. Existing injection tests mostly cover obvious payloads.

## Implementation sequence and acceptance criteria

### 1. Connection-level SSRF protection and browser limits

- Add a loopback-only HTTP/CONNECT egress proxy. Resolve and validate all addresses,
  connect to the checked numeric IP, preserve HTTP Host and TLS validation, and
  revalidate every new target connection. Fail closed on malformed URLs, credentials,
  unsupported schemes, DNS failures and non-public IPs. Bound DNS/socket timeouts.
- Force Chromium through the proxy, remove implicit loopback bypass, block service
  workers and WebSockets, disable direct UDP/QUIC/WebRTC, respect page CSP, block
  downloads and extra pages. Routing remains only a secondary check.
- Bound queued work, overall render duration, requests and serialized DOM size.
- Test IP encodings, mixed DNS results, public-to-private redirects, proxy pinning,
  blocked private subresources, service workers, socket cleanup and queue recovery.
- Residual: Chromium compromise and non-HTTP egress require container/network controls.

### 2. Untrusted-output pipeline

- Normalize Unicode for detection before matching, scan original and normalized
  forms, keep random boundary markers. Fail closed if an enabled detector fails.
- Sanitize extraction consistently across Markdown/text/HTML: remove scripts,
  executable attributes, hidden content, unsafe URL schemes, auto-loading images
  and comments. Resolve safe relative links. Bound input before DOM parsing.
- Scan bounded complete extracted content before output truncation. Titles and source
  URLs must be screened and placed inside the untrusted boundary. Do not repeat raw
  page metadata in trusted headers or blocked/error results. Return only bounded,
  screened/encoded metadata with explicit untrusted provenance.
- Screenshots remain opt-in and explicitly untrusted, with text preflight; do not
  claim text detection covers visual injection.
- Add adversarial tests for titles, Unicode, boundaries, dangerous HTML/links,
  truncation, detector failures and both MCP result channels.

### 3. OAuth, transport and configuration

- Exact Origin allowlist (canonical server origin plus explicit configured browser
  client origins), allow absent Origin for non-browser clients. CORS only for allowed
  origins. Consent same-origin checks, CSP, no-store and no-referrer headers.
- Require mcp:fetch scope; default omitted authorization scopes to mcp:fetch for
  compatibility. Bind sessions to authenticated user/client, allow token refresh for
  the same identity, enforce session cap and idle TTL, close associated servers.
- Persist atomic consent-token consumption; client-bound token revocation; keep
  refresh-token replay tombstones until token expiry; tighten redirect URI and JWT
  claim validation. Bound client registrations/store growth where practical.
- Strict typed/ranged configuration with blank optional-token support and safe URL
  configuration. Explicit proxy trust configuration rather than a fixed hop count.
- Add negative and positive auth, session, origin, consent and configuration tests.

### 4. Cookie-banner handling

- Add `cookie_banner: hide | off` with privacy-preserving hide as default. Remove
  known CMP overlays and narrowly scoped cookie dialogs from the rendered snapshot
  without clicking accept/reject, changing consent cookies, or following links.
- Return deterministic cleanup metadata. Retain an off switch. Do not remove generic
  dialogs, paywalls, login controls, or article text merely mentioning cookies.
- Test common CMPs, delayed banners, generic cookie dialogs, false positives and off.

### 5. Verification and documentation

- Run dependency advisory audit, typecheck/build, unit/integration tests, and isolated
  Chromium tests in the existing Podman environment (no host package installs).
- Enable real-browser regression coverage in CI; document migration settings,
  operational container/egress limits, filter limitations and screenshot risks.
- Independent subagent reviews the plan before implementation and reviews the final
  security diff. Resolve actionable findings, then rerun the test suite.

## Explicit limitations

No regex, ML classifier, or delimiter can guarantee immunity to prompt injection.
Fetched data must never grant authority to invoke unrelated tools, expose secrets,
or change policy. This server cannot enforce another MCP client's tool permissions.
Cookie hiding is not a consent decision and does not bypass access controls. Local
process isolation and network egress policy remain operator responsibilities.

## Primary references

- [Playwright routing](https://playwright.dev/docs/api/class-browsercontext#browser-context-route)
- [Playwright Chromium redirect implementation (v1.60.0)](https://github.com/microsoft/playwright/blob/v1.60.0/packages/playwright-core/src/server/chromium/crNetworkManager.ts)
- [MCP transport security](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [OWASP prompt-injection guidance](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- [OWASP SSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

## Independent plan review (completed before implementation)

The independent security reviewer approved proceeding with these adjustments:

- Ports 80/443 by default, strict CONNECT authority parsing, per-job proxy sockets,
  transfer/time caps, and tests asserting zero connections to forbidden targets.
- Return no raw page strings outside the untrusted envelope; blocked/error output
  must use fixed diagnostics. Normalize and scan before user truncation.
- Hide cookie banners only in a detached output snapshot. Never click controls or
  mutate the live page. Screenshots retain the original page appearance.
- Session identity includes auth kind, user subject and client ID, not bearer token.
- Refresh families have absolute expiry; preserve replay evidence through expiry.
- Use targeted dependency upgrades, not forced bulk updates. Document no-sandbox,
  shared-UID browser compromise as a residual risk requiring stronger deployment
  isolation rather than claiming the container fully protects OAuth secrets.

## Implemented verification record

- Baseline: 43 unit/integration tests passed, one real-browser test skipped.
- Dependency audit: 15 advisory findings (including a critical development-server
  advisory), reduced to zero in both full and production-only registry audits by
  targeted updates. No forced dependency upgrade; Defender API and Playwright
  version retained. Node minimum is now 22.12.
- Independent implementation reviews cover network/proxy, auth/store, HTTP/session,
  and output/filter/deployment. Review fixes include initialization-notification
  capacity leakage and consent CSP redirect compatibility.
- Final build/test totals and residual release actions are recorded below after the
  last integrated run. No production deployment or credential rotation is performed.

### Browser-verified consent policy adjustment

Real Chromium integration exposed that `Referrer-Policy: no-referrer` causes form
POSTs to send `Origin: null`, and `form-action 'self'` alone can block the legitimate
OAuth callback redirect. Valid consent forms now use `same-origin` referrer policy
(no cross-origin leakage) and allow only the signed, validated callback origin in
form-action. Strict POST Origin validation and anti-framing remain enabled.

## Final result (2026-09-16)

Implemented all five tranches above. Independent implementation reviewers approved
network/proxy, output/config/deployment, and auth/store/HTTP/session scopes after
fixes. The final network review's non-blocking UTF-8 IPC-size finding was also fixed
and covered by a real multibyte-page regression.

### Verification completed

- `npm run build` and `npm run typecheck`: passed.
- `RUN_E2E=1 npm test`: **365 tests passed in 19 suites**, none skipped.
- Full `npm audit` and `npm audit --omit=dev`: **0 known vulnerabilities**.
- Render → extract → strict-filter smoke: passed in the Playwright container.
- The same smoke passed as `pwuser`, with read-only filesystem, limited tmpfs,
  2 GiB memory, 2 CPUs, 512 PIDs, dropped capabilities, no-new-privileges and no
  external container network. This validates runtime settings, not a rebuilt
  production image or an external deployment.
- `git diff --check`: passed.

All dependency installs and browser execution were confined to disposable Podman
containers. No host packages, production resources, real credentials, commits or
remote branches were changed. The existing stopped Podman VM was started for tests and restored to stopped
afterward. The disposable test container and temporary smoke image were removed.

### Release checklist and explicit deferred work

- Read README migration notes before rollout: Node >=22.12, stronger configuration
  validation, required fetch scope, explicit browser origins/proxy trust, default
  destination ports 80/443 and moved title/URL metadata.
- Back up the OAuth database before its automatic refresh-family migration. Old
  replay evidence already deleted by earlier releases is not recoverable.
- The unauthenticated DCR endpoint is rate-limited and capped; there is no admin UI
  for stale registrations. Operators must recover capacity deliberately, not delete
  active client grants indiscriminately.
- For high-assurance use, implement a separate browser worker without OAuth data and
  enforce proxy-only egress at network-namespace/firewall level. This is **not**
  implemented by this single-container patch.
- Real ONNX inference was not enabled/downloaded. Tier2 startup/failure/skip/timeout/
  concurrency behavior has deterministic mocked regression coverage; actual model
  quality and performance remain deployment-specific validation work.
- Browser-engine/OS CVE scanning, long-duration fuzz/load tests, and evaluation of
  unseen semantic/visual prompt injections are separate ongoing work. Regex/ML
  screening and random fences never confer authority or guarantee immunity.
