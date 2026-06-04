# renderfetch-mcp

**Give Claude a real browser.** A small, self-hosted [MCP](https://modelcontextprotocol.io)
server that fetches web pages with headless Chromium, returns clean Markdown, and
screens everything for prompt injection. With OAuth built in, so it works as a
claude.ai custom connector out of the box (and with Claude Code).

![license](https://img.shields.io/badge/license-MIT-blue) ![node](https://img.shields.io/badge/node-%E2%89%A520-green)

## Why this exists

Claude's built-in web fetch often fails on JavaScript heavy or bot protected
pages, and claude.ai connectors require OAuth 2.1. This server fixes both:

- **real Chromium browser**: to let modern pages actually render
- **own OAuth 2.1 server:** so no external auth provider needed
- **filter against prompt injections:** it treats every fetched page as untrusted and filters injection attempts
  before Claude ever sees them.

## Features

- 🌐 **Real headless browser** (Playwright/Chromium): Runs JavaScript, can wait for a selector.
- 📝 **Clean output:** main content extraction to Markdown (default), or text / HTML.
- 🔐 **Self-contained OAuth 2.1:** dynamic client registration, PKCE, refresh-token rotation. Plus an optional static token for headless/automation.
- 🛡️ **Safety built in:** prompt-injection filter with unguessable content boundaries, and an SSRF guard that blocks internal / loopback / cloud-metadata targets.
- 🧰 **One container:** rootless-Podman (or Docker) friendly, sits behind any reverse proxy.
- 👤 **Single-user by design:** one login gates everything. Perfect for a personal connector.

## How it works

```
Claude ──OAuth──▶ renderfetch-mcp ──▶ headless Chromium ──▶ page
                       │
        Markdown ◀── injection filter ◀── readability extraction
```

It exposes one tool: **`fetch_url`**.

## Quick start

You need rootless Podman (or Docker) and a public HTTPS hostname pointing
at your machine (any reverse proxy that terminates TLS).

> Throughout this README, replace `YOUR_HOST` with your own domain.

```bash
git clone https://github.com/lalbers/renderfetch-mcp.git
cd renderfetch-mcp
cp .env.example .env
```

Edit `.env`, set a username + a strong password, your public URL, and generate
the secrets:

```bash
openssl rand -base64 48   # -> JWT_SECRET
openssl rand -base64 32   # -> STATIC_BEARER_TOKEN (optional, for headless use)
# PUBLIC_BASE_URL=https://mcp.example.com
```

Run it, pick one:

```bash
# Compose (Podman or Docker)
podman compose up -d --build        # or: docker compose up -d --build
```

```bash
# Plain Podman
./build.sh
podman run -d --name renderfetch-mcp --restart unless-stopped \
  --env-file .env -v renderfetch-data:/data \
  --shm-size=2g --init --cap-drop=ALL --security-opt=no-new-privileges \
  -p 127.0.0.1:10120:8080 localhost/renderfetch-mcp:latest
```

```bash
# systemd (Podman Quadlet)
cp deploy/renderfetch-mcp.container ~/.config/containers/systemd/
cp .env ~/.config/renderfetch-mcp.env
systemctl --user daemon-reload && systemctl --user start renderfetch-mcp
```

Then point your reverse proxy so `https://YOUR_HOST/mcp` reaches
`127.0.0.1:10120`. Ready-made snippets for nginx, Traefik, and Caddy are in
[`deploy/`](deploy/). Check it's alive:

```bash
curl https://YOUR_HOST/healthz        # {"status":"ok"}
```

## Connect a client

Go to [claude.ai](https://claude.ai), then Settings → Connectors → Add custom connector → paste
`https://YOUR_HOST/mcp`. Approve the consent screen with your `.env` username and
password. That's it.

**Claude Code**

```bash
claude mcp add --transport http renderfetch https://YOUR_HOST/mcp
```

For headless / CI, use the static token instead of the browser login:

```bash
claude mcp add --transport http renderfetch https://YOUR_HOST/mcp \
  --header "Authorization: Bearer $STATIC_BEARER_TOKEN"
```

Then just ask: *"Fetch https://example.com and summarize it."*

## The `fetch_url` tool

| param | meaning |
|---|---|
| `url` | the page to fetch (http/https) |
| `format` | `markdown` (default), `text`, or `html` |
| `wait_ms` | extra wait after load, for slow JS pages |
| `wait_for_selector` | wait until this CSS selector appears |
| `css_selector` | extract just this part of the page |
| `max_chars` | cap the returned length |

An optional `screenshot` tool can be turned on with `SCREENSHOT_ENABLED=true`
(off by default because images are token-expensive).

## Configuration

Everything is set via environment variables, see [`.env.example`](.env.example)
for the full list. The essentials:

| variable | what it does |
|---|---|
| `PUBLIC_BASE_URL` | your public URL, e.g. `https://mcp.example.com` (no trailing slash) |
| `AUTH_USERNAME` / `AUTH_PASSWORD` | the single login that gates the consent screen |
| `JWT_SECRET` | signs access tokens (use a long random value) |
| `STATIC_BEARER_TOKEN` | optional bearer for headless clients; leave empty to disable |
| `OAUTH_ONLY` | set `true` to allow OAuth only (disables the static token) |
| `FILTER_MODE` | `strict` (block risky pages) or `lenient` (sanitize only) |

Data (registered clients + tokens) lives in a SQLite DB inside the `renderfetch-data`
volume. Reset everything with `podman volume rm renderfetch-data` (it re-creates on
next start; clients simply re-register).

## Security

In short: every fetched page is untrusted data, wrapped in an unguessable
boundary and screened for injection; the fetcher can only reach the public
internet (no LAN / loopback / cloud-metadata); and access requires OAuth or a
static token. Full model and how to report issues: [SECURITY.md](SECURITY.md).

## Develop & test

No host installs needed, run the suite in a throwaway container:

```bash
tar -cf - src test package.json package-lock.json tsconfig.json vitest.config.ts | \
  podman run --rm -i mcr.microsoft.com/playwright:v1.60.0-noble sh -c '
    apt-get update -q && apt-get install -yq --no-install-recommends python3 make g++ >/dev/null &&
    mkdir -p /app && cd /app && tar -xf - &&
    npm ci && npm run build && RUN_E2E=1 npm test'
```

Or locally with Node ≥ 20: `npm install && npm run build && npm test`.
After building the image, `scripts/container-smoke.mjs` (run inside the image)
does a real render → extract → filter check.

## Tech

TypeScript · [`@modelcontextprotocol/sdk`](https://github.com/modelcontextprotocol/typescript-sdk)
(Streamable HTTP) · Playwright · `@mozilla/readability` + Turndown ·
[`@stackone/defender`](https://github.com/StackOneHQ/defender) · better-sqlite3 · jose.

## License

[MIT](LICENSE).
