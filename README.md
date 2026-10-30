# renderfetch-mcp

Self-hosted remote [MCP](https://modelcontextprotocol.io) server: headless-browser web fetch with OAuth 2.1 and prompt-injection filtering. A [claude.ai](https://claude.ai) custom connector and Claude Code use the same `/mcp` endpoint.

[![CI](https://github.com/lalbers/renderfetch-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/lalbers/renderfetch-mcp/actions/workflows/ci.yml)
[![CodeQL](https://github.com/lalbers/renderfetch-mcp/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/lalbers/renderfetch-mcp/actions/workflows/github-code-scanning/codeql)
[![release](https://img.shields.io/github/v/release/lalbers/renderfetch-mcp)](https://github.com/lalbers/renderfetch-mcp/releases)
![license](https://img.shields.io/badge/license-MIT-blue) ![node](https://img.shields.io/badge/node-22.22.2%20%7C%2024.15%20%7C%2026-green)

## Why it exists

I use Claude to fetch news from many sources for research and briefings. Its built-in web fetch often fails on JavaScript-heavy and bot-protected pages, and its full built-in browser is slow and spends too much of the context window. renderfetch-mcp renders the page in a real browser and returns extracted, sanitized page content (Markdown by default).

claude.ai custom connectors authenticate only via OAuth. They cannot send a static bearer token, so this server includes its own OAuth 2.1 authorization server.

## Features

- Headless Chromium, through Playwright, runs page JavaScript and can wait for a CSS selector.
- `fetch_url` returns Markdown by default, or text or HTML.
- OAuth 2.1, with dynamic client registration, PKCE, and refresh-token rotation.
- Egress checks the DNS answer, output is sanitized and screened, and rendering is bounded.
- Each MCP session is bound to its auth kind, user, and client.
- Recognized consent overlays are removed from the output snapshot, without a click.
- One rootless Podman container, and one login. The server is single-user.

## How it works

```
Claude ──OAuth──▶ renderfetch-mcp ──▶ headless Chromium ──▶ page
                       │
       page text ◀── injection filter ◀── readability extraction
```

Each render uses its own loopback egress proxy, which checks the DNS answer and connects to a pinned numeric IP. The HTML is then sanitized, extracted, and screened for prompt injection.

## Quick start

### Prerequisites

Run the commands below as a rootless user. The sandbox needs a user namespace the process creates. You also need a TLS reverse proxy and, for a claude.ai connector, a publicly reachable HTTPS hostname.

### Configure

```bash
git clone https://github.com/lalbers/renderfetch-mcp.git
cd renderfetch-mcp
cp .env.example .env
```

Edit `.env`. Startup rejects the `change-me…` placeholders in `.env.example`, even when the string is long enough. Set `AUTH_USERNAME`, `AUTH_PASSWORD`, and `PUBLIC_BASE_URL`. Generate `JWT_SECRET` and, if you want it, `STATIC_BEARER_TOKEN`:

```bash
openssl rand -base64 48   # JWT_SECRET
openssl rand -base64 32   # STATIC_BEARER_TOKEN
```

Leave `STATIC_BEARER_TOKEN` empty to disable that path. `OAUTH_ONLY=true` disables it even when the variable is set.

Each command below publishes `127.0.0.1:10120` to container port 8080. Keep `PORT` at 8080 while that mapping stays. The process binds `0.0.0.0` unless you change `BIND_HOST`.

### Podman Compose

```bash
podman compose up -d --build        # or, untested: docker compose up -d --build
```

### Plain Podman

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

### systemd and Podman Quadlet

```bash
./build.sh
mkdir -p ~/.config/containers/systemd
cp deploy/renderfetch-mcp.container ~/.config/containers/systemd/
cp .env ~/.config/renderfetch-mcp.env
cp deploy/seccomp-chromium.json ~/.config/renderfetch-mcp-seccomp.json
systemctl --user daemon-reload && systemctl --user start renderfetch-mcp
```

`daemon-reload` enables the unit because `[Install]` sets `WantedBy=default.target`. Run `loginctl enable-linger` once so the user manager, and this service, keep running after logout and start at boot.

### TLS reverse proxy

Replace `YOUR_HOST` with your hostname. Proxy the whole origin `https://YOUR_HOST` to `127.0.0.1:10120`, not only `/mcp`. OAuth also uses `/.well-known/*`, `/authorize`, `/token`, `/register`, `/revoke`, and `/consent`. Snippets for Nginx, Traefik, and Caddy are in [`deploy/`](deploy/).

Set `TRUST_PROXY` to the address the container actually sees. It depends on the Podman network mode: the host's own address on the default rootless network, or an address from the container network when Compose uses a bridge. If it is empty, every caller shares that address on each IP-keyed limiter ([SECURITY.md](SECURITY.md)).

```bash
curl https://YOUR_HOST/healthz        # {"status":"ok"} means the process is up
```

## Connect a client

In [claude.ai](https://claude.ai), open Settings → Connectors → Add custom connector and enter `https://YOUR_HOST/mcp`. Approve the consent screen with `AUTH_USERNAME` and `AUTH_PASSWORD`.

For Claude Code, register the same endpoint:

```bash
claude mcp add --transport http renderfetch https://YOUR_HOST/mcp
```

For a script or CI job, send the static bearer:

```bash
claude mcp add --transport http renderfetch https://YOUR_HOST/mcp \
  --header "Authorization: Bearer $STATIC_BEARER_TOKEN"
```

## The `fetch_url` tool

| Parameter | Meaning |
|---|---|
| `url` | the page to fetch (http/https) |
| `format` | `markdown` (default), `text`, or `html` |
| `wait_ms` | extra wait after load, capped at 60000 ms by the tool schema, inside `FETCH_TIMEOUT_MS` |
| `wait_for_selector` | wait until this CSS selector appears |
| `css_selector` | extract just this part of the page |
| `max_chars` | caps page text after the whole bounded extraction was screened; trust warning, source URL, title (cut to 1000 characters), and boundary fence are added on top. Default 50000 |
| `cookie_banner` | `hide` (default): remove recognized cookie overlays from the output snapshot; `off`: retain them |

### What comes back

Page text is returned in `content` and again as `structuredContent.text`. Some clients, including the claude.ai connector, show only `structuredContent`. Others read `content`. Metadata beside that text is `http_status`, `truncated`, `format`, `filter`, `provenance`, and `cookie_banner`. The title and the source URL stay inside the untrusted text.

Errors are fixed strings, with no raw browser errors, URLs, or titles. HTML is sanitized, not a raw dump: an `img` becomes its alt text, and safe relative links are made absolute.

### `screenshot`

The tool stays off unless `SCREENSHOT_ENABLED=true`. The image is a viewport PNG, not a full-page capture, and it is expensive in tokens.

## Configuration

All settings are environment variables, documented in [`.env.example`](.env.example).

| Variable | What it does |
|---|---|
| `PUBLIC_BASE_URL` | HTTPS origin, no path, query, credentials, or fragment, e.g. `https://mcp.example.com`. HTTP only for `localhost` and `127.0.0.1` (not `[::1]`) |
| `AUTH_USERNAME` / `AUTH_PASSWORD` | the consent-screen login. Password at least 12 characters |
| `JWT_SECRET` | signs access and consent tokens. At least 32 characters |
| `STATIC_BEARER_TOKEN` | optional bearer for headless clients. 32+ printable ASCII characters, no whitespace. Empty disables it. claude.ai does not use it |
| `OAUTH_ONLY` | `true` disables the static bearer |
| `FILTER_MODE` | `strict` blocks high and critical risk. `lenient` returns that text in the same untrusted envelope; risk level is only in `structuredContent.filter.risk_level`. Medium-risk matches return in both modes. A detector failure withholds content in both modes |
| `FILTER_TIER2` | optional ML classifier, off by default. If initialization fails, the server does not start |
| `FETCH_ALLOWED_PORTS` | destination ports, default `80,443` |
| `FETCH_ALLOW_PRIVATE` | relaxes the address check only. Schemes, URL credentials, and ports still apply. Leave it off on a public server |
| `ALLOWED_ORIGINS` | extra exact browser origins (MCP Inspector, for example). This origin is always allowed. A missing `Origin` is allowed for non-browser clients |
| `TRUST_PROXY` | proxy IP or CIDR the container sees. Empty ignores forwarded addresses |
| `CHROMIUM_NO_SANDBOX` | default `false`. `true` leaves Chromium unsandboxed. See [SECURITY.md](SECURITY.md) |

Clients and tokens are in SQLite on the `renderfetch-data` volume (`renderfetch-mcp_renderfetch-data` under Compose; `podman volume ls`). Remove the container, then `podman volume rm <volume>` deletes the file. The next start creates a new one, and clients register again.

## Security

Treat every fetched page as hostile. Filtering does not make prompt injection impossible. The browser, GPU, and utility processes, such as the network service, run outside the sandbox and share the OAuth store's user. See [SECURITY.md](SECURITY.md).

## Upgrading from 1.0.0

Add `deploy/seccomp-chromium.json` and set `CHROMIUM_NO_SANDBOX=false` before you replace the container. 1.0.0's code default, used when unset, and example `.env` were `true`. [SECURITY.md](SECURITY.md) explains the profile. Other steps: [upgrade notes](CHANGELOG.md#upgrading-from-100).

## Develop and test

The suite can run in a throwaway container:

```bash
tar -cf - src test package.json package-lock.json tsconfig.json vitest.config.ts | \
  podman run --rm -i --shm-size=1g --init mcr.microsoft.com/playwright:v1.64.1-noble sh -c '
    apt-get update -q && apt-get install -yq --no-install-recommends python3 make g++ >/dev/null &&
    mkdir -p /app && cd /app && tar -xf - &&
    npm ci && npm run build && RUN_E2E=1 npm test'
```

Locally, use Node 22 (22.22.2 or later), Node 24 (24.15 or later), or Node 26 and later. Node 23 and 25 are not supported. Run `npm ci && npm run build && npm test`. `RUN_E2E=1` adds the real-browser tests after `npx playwright install --with-deps chromium`. Build the image with `./build.sh` first. The header comment of `scripts/container-smoke.mjs` gives the `podman run` command for the built image.

## Tech

TypeScript · [`@modelcontextprotocol/sdk`](https://github.com/modelcontextprotocol/typescript-sdk) (Streamable HTTP) · Playwright · `@mozilla/readability` + Turndown · [`@stackone/defender`](https://github.com/StackOneHQ/defender) · better-sqlite3 · jose.

## License

[MIT](LICENSE). `deploy/seccomp-chromium.json` is Apache-2.0 derived (see [NOTICE](NOTICE)).
