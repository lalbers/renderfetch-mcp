# renderfetch-mcp

Self-hosted remote [MCP](https://modelcontextprotocol.io) server: headless-browser web fetch with OAuth 2.1 and prompt-injection filtering. A [claude.ai](https://claude.ai) custom connector and Claude Code use the same `/mcp` endpoint.

[![CI](https://github.com/lalbers/renderfetch-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/lalbers/renderfetch-mcp/actions/workflows/ci.yml)
[![CodeQL](https://github.com/lalbers/renderfetch-mcp/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/lalbers/renderfetch-mcp/actions/workflows/github-code-scanning/codeql)
[![release](https://img.shields.io/github/v/release/lalbers/renderfetch-mcp)](https://github.com/lalbers/renderfetch-mcp/releases)
![license](https://img.shields.io/badge/license-MIT-blue) ![node](https://img.shields.io/badge/node-22.22.2%20%7C%2024.15%20%7C%2026-green)

## Why it exists

I noticed that Claude's built-in web fetch often fails on JavaScript-heavy and bot-protected pages. For research and briefings I use Claude to fetch news from a variety of sources.

Using the full built-in browser instead is slow or uses too much of the context window. renderfetch-mcp renders the page in a real browser and returns only the extracted text. claude.ai custom connectors authenticate only via OAuth (they cannot send a static bearer token), so the server brings its own OAuth 2.1 authorization server.

## Features

- **Real headless browser**: based on Chromium (Playwright); runs JavaScript and can wait for specific selectors.
- **Simple Markdown output**: to conserve more of the context window.
- **OAuth 2.1**: including dynamic client registration, PKCE, and refresh token rotation.
- **Defense in depth**: DNS-pinned per-render egress proxy, normalized injection screening, sanitized output, bounded rendering, and client-bound MCP sessions.
- **Cookie cleanup**: hides recognized consent overlays in the output snapshot (without clicking buttons or giving consent).
- **Single container**: runs as one rootless Podman container.
- **Single-user by design**: one login gates everything.

## How it works

```
Claude ──OAuth──▶ renderfetch-mcp ──▶ headless Chromium ──▶ page
                       │
       page text ◀── injection filter ◀── readability extraction
```

The tool is `fetch_url`. `screenshot` is registered only when `SCREENSHOT_ENABLED=true`.

## Quick start

### Prerequisites

You need rootless Podman and a public HTTPS hostname.

This example publishes `127.0.0.1:10120` to port 8080 in the container. The process itself binds `0.0.0.0` unless you change `BIND_HOST`. A reverse proxy terminates TLS.

> Replace `YOUR_HOST` with your hostname.

```bash
git clone https://github.com/lalbers/renderfetch-mcp.git
cd renderfetch-mcp
cp .env.example .env
```

- Edit `.env`.
  - Set `AUTH_USERNAME` and an `AUTH_PASSWORD` of at least 12 characters.
  - Set `PUBLIC_BASE_URL`, which must be an HTTPS origin. HTTP is accepted only for `localhost` and `127.0.0.1`.
  - Set `JWT_SECRET` (required) and, optionally, `STATIC_BEARER_TOKEN` to fresh random values:

```bash
openssl rand -base64 48   # JWT_SECRET
openssl rand -base64 32   # STATIC_BEARER_TOKEN
```

You can leave `STATIC_BEARER_TOKEN` empty to disable that path. `OAUTH_ONLY=true` disables it even if the variable is set.

Then start it in one of three ways.

### Start with Podman Compose (option 1)

```bash
podman compose up -d --build        # or, untested: docker compose up -d --build
```

### Start with plain Podman (option 2)

```bash
./build.sh
podman run -d --name renderfetch-mcp --restart unless-stopped \
  --env-file .env -v renderfetch-data:/data \
  --shm-size=2g --init --cap-drop=ALL --security-opt=no-new-privileges \
  --security-opt seccomp=deploy/seccomp-chromium.json \
  --read-only --memory=2g --cpus=2 --pids-limit=512 \
  --tmpfs=/tmp:rw,nosuid,nodev,size=1g \
  --tmpfs=/home/pwuser/.cache:rw,nosuid,nodev,size=128m \
  -p 127.0.0.1:10120:8080 localhost/renderfetch-mcp:latest
```

### Start with systemd and Podman Quadlet (option 3)

```bash
./build.sh
mkdir -p ~/.config/containers/systemd
cp deploy/renderfetch-mcp.container ~/.config/containers/systemd/
cp .env ~/.config/renderfetch-mcp.env
cp deploy/seccomp-chromium.json ~/.config/renderfetch-mcp-seccomp.json
systemctl --user daemon-reload && systemctl --user start renderfetch-mcp
```

To start it at boot without a login session, run `loginctl enable-linger` once.

### Set up the TLS reverse proxy

Proxy the whole host `https://YOUR_HOST` to `127.0.0.1:10120`, not just `/mcp`: OAuth also uses `/.well-known/*`, `/authorize`, `/token`, `/register`, `/revoke`, and `/consent`.
Nginx, Traefik, and Caddy snippets are in [`deploy/`](deploy/). Set `TRUST_PROXY` to the proxy's address as seen inside the container (exact IP or CIDR). If it is empty, forwarded addresses are ignored, so all clients share one rate-limit bucket and anyone can lock out the consent login.

```bash
curl https://YOUR_HOST/healthz        # {"status":"ok"} means the process is up
```

`/healthz` does not check the browser. With the sandbox left on and `deploy/seccomp-chromium.json` missing, it still returns ok and every fetch fails.

## Connect a client

In [claude.ai](https://claude.ai): Settings → Connectors → Add custom connector → `https://YOUR_HOST/mcp`. Approve the consent screen with `AUTH_USERNAME` and `AUTH_PASSWORD`.

**Claude Code**

```bash
claude mcp add --transport http renderfetch https://YOUR_HOST/mcp
```

For a script or CI job, send the static bearer instead of using the consent screen:

```bash
claude mcp add --transport http renderfetch https://YOUR_HOST/mcp \
  --header "Authorization: Bearer $STATIC_BEARER_TOKEN"
```

Example: *"Fetch https://example.com and summarize it."*

## The `fetch_url` tool

| param | meaning |
|---|---|
| `url` | the page to fetch (http/https) |
| `format` | `markdown` (default), `text`, or `html` |
| `wait_ms` | extra wait after load, for slow JavaScript |
| `wait_for_selector` | wait until this CSS selector appears |
| `css_selector` | extract just this part of the page |
| `max_chars` | cap page content after screening the full bounded extraction |
| `cookie_banner` | `hide` (default): remove recognized cookie overlays from the output snapshot; `off`: retain them |

### What comes back

The page text is returned twice: a text block in `content`, and the same text as `structuredContent.text`, next to server metadata (`http_status`, `truncated`, `format`, `filter`, `provenance`, `cookie_banner`). Title and source URL stay inside the untrusted text, not in those fields.

Some MCP clients render only `structuredContent` once that field is present. The claude.ai connector started doing so in early September 2026. A result that put only metadata there reached the model with no page text, while the server log showed a successful fetch. Clients that ignore `structuredContent` still read `content`, so both are sent.

Errors are fixed strings. They do not include raw browser errors, URLs, or titles. HTML is sanitized, not a raw page dump. An `img` is reduced to its alt text, and safe relative links are made absolute. Cookie cleanup is cosmetic only. It does not accept or reject consent, bypass access controls, or modify the live page.

`screenshot` stays off unless `SCREENSHOT_ENABLED=true`. The image is a viewport PNG, not a full-page capture. It is expensive in tokens, text screening does not catch every visual instruction, and cookie cleanup does not change the picture.

## Configuration

All settings are environment variables, documented in [`.env.example`](.env.example). The most important ones:

| variable | what it does |
|---|---|
| `PUBLIC_BASE_URL` | HTTPS origin, no path, query, credentials, or fragment, e.g. `https://mcp.example.com`. HTTP only for `localhost` and `127.0.0.1` (not `[::1]`) |
| `AUTH_USERNAME` / `AUTH_PASSWORD` | the consent-screen login. Password at least 12 characters |
| `JWT_SECRET` | signs access and consent tokens. At least 32 characters |
| `STATIC_BEARER_TOKEN` | optional bearer for headless clients. 32+ printable ASCII characters, no whitespace. Empty disables it. claude.ai does not use it |
| `OAUTH_ONLY` | `true` disables the static bearer |
| `FILTER_MODE` | `strict` blocks high and critical risk. `lenient` can return that text, labeled. A detector failure withholds content in both modes |
| `FETCH_ALLOWED_PORTS` | destination ports, default `80,443`. `FETCH_ALLOW_PRIVATE=true` does not open other ports or schemes. Leave private access off on a public server |
| `ALLOWED_ORIGINS` | extra exact browser origins (MCP Inspector, for example). This server's origin is always allowed. A missing `Origin` header is allowed for non-browser clients |
| `TRUST_PROXY` | exact trusted proxy IPs or CIDRs, as seen inside the container. Set it behind a reverse proxy. Empty: ignore forwarded client addresses |
| `CHROMIUM_NO_SANDBOX` | default `false`. The container examples keep the sandbox via [`deploy/seccomp-chromium.json`](deploy/seccomp-chromium.json). `true` is a last resort |

Registered clients and tokens sit in a SQLite file on the `renderfetch-data` volume (`renderfetch-mcp_renderfetch-data` under Compose; see `podman volume ls`). Remove the container, then `podman volume rm <volume>` deletes that file. It is recreated on the next start, and clients register again.

## Security

Treat every fetched page as hostile. The per-render proxy checks each destination and connects to a pinned numeric IP. Page text is sanitized, screened, and labeled before it is returned. Regex filters, the optional ML tier, and random boundary markers do not make prompt injection impossible.

In the supplied Podman setups, Chromium's renderers run in Chromium's sandbox. The browser process, the GPU process, and the network service do not. They share the container and the user ID with the OAuth store. A separate browser worker, with no auth data, plus egress control outside the process, is the stronger boundary. Docker is untested. Deployment rules: [SECURITY.md](SECURITY.md).

## Upgrading from 1.0.0

2.0.0 tightens defaults and needs configuration changes. Set `CHROMIUM_NO_SANDBOX=false` (the 1.0.0 example `.env` had `true`) only after the container loads `deploy/seccomp-chromium.json`. Otherwise Chromium stays unsandboxed. Read the [upgrade notes](CHANGELOG.md#upgrading-from-100) first.

## Develop and test

No host install required. The suite can run in a throwaway container:

```bash
tar -cf - src test package.json package-lock.json tsconfig.json vitest.config.ts | \
  podman run --rm -i --shm-size=1g --init mcr.microsoft.com/playwright:v1.64.1-noble sh -c '
    apt-get update -q && apt-get install -yq --no-install-recommends python3 make g++ >/dev/null &&
    mkdir -p /app && cd /app && tar -xf - &&
    npm ci && npm run build && RUN_E2E=1 npm test'
```

Locally with Node 22.22.2+, 24.15+, or 26+: `npm ci && npm run build && npm test`. `RUN_E2E=1` adds the real-browser security tests (after `npx playwright install --with-deps chromium`); CI runs them too.

After building the image, `scripts/container-smoke.mjs` runs a real render, extraction, and filter check inside it and verifies that Chromium's sandbox is active. Its header shows the `podman run` command.

## Tech

TypeScript · [`@modelcontextprotocol/sdk`](https://github.com/modelcontextprotocol/typescript-sdk) (Streamable HTTP) · Playwright · `@mozilla/readability` + Turndown · [`@stackone/defender`](https://github.com/StackOneHQ/defender) · better-sqlite3 · jose.

## License

[MIT](LICENSE).
