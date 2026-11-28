# Build + run the web-fetch MCP server on the official Playwright image
# (Ubuntu 24.04 "noble" / glibc). This base provides the system libraries for
# Chromium (the browser itself is the pinned build below) AND a glibc runtime, which the native modules (better-sqlite3,
# onnxruntime-node) require. Alpine/musl is not viable for Playwright Chromium
# or onnxruntime-node. The tag is pinned to match the `playwright` npm version
# and also fixes the image's Node.js major (26 for v1.65.0).

FROM mcr.microsoft.com/playwright:v1.65.0-noble AS build
WORKDIR /app
ENV NODE_ENV=development
# Build tools so any native module without a matching prebuilt binary can compile.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ ca-certificates curl unzip \
 && rm -rf /var/lib/apt/lists/*
# Playwright's bundled Chromium trails Chrome's security releases: 1.65.0
# bundles 158.0.8127.18, while NVD names 158.0.8127.36 as the first fixed
# version for the Chrome 158 security fixes (see CHANGELOG). The image
# therefore runs the stable Chrome for Testing headless shell, pinned by
# version and SHA-256.
# .github/workflows/chrome-pin.yml fails when Chrome stable moves past the pin;
# bump both ARGs then. CI fails when the bundled build is at least the pinned
# version. Remove the override only if the bundled build is a stable-channel
# build at least as new as Chrome stable; otherwise keep it and hold the
# Playwright bump (1.65.1 was skipped because it bundles beta 159). Removing
# means: this block and `curl unzip` above, the ENV and the rm/ls check in the
# runtime stage, chrome-pin.yml, and in ci.yml the two Chrome for Testing steps
# and PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD (go back to
# `npx playwright install --with-deps chromium`).
ARG CHROME_VERSION=158.0.8127.88
ARG CHROME_SHA256=63401333cc587645bfaeea7f0c90958b327d249251e23954a47f30112ca23d5b
RUN curl -fsSL -o /tmp/chrome-headless-shell.zip \
      "https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VERSION}/linux64/chrome-headless-shell-linux64.zip" \
 && echo "${CHROME_SHA256}  /tmp/chrome-headless-shell.zip" | sha256sum -c - \
 && unzip -q /tmp/chrome-headless-shell.zip -d /opt/chrome-for-testing \
 && rm /tmp/chrome-headless-shell.zip
COPY package.json package-lock.json ./
# Reproducible install from the committed lockfile.
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
RUN npm run build \
 && npm prune --omit=dev

FROM mcr.microsoft.com/playwright:v1.65.0-noble AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NODE_OPTIONS=--enable-source-maps \
    DB_PATH=/data/renderfetch.db \
    CHROMIUM_EXECUTABLE_PATH=/opt/chrome-for-testing/chrome-headless-shell-linux64/chrome-headless-shell
COPY --from=build /opt/chrome-for-testing /opt/chrome-for-testing
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
# Persistent OAuth/token store lives under /data (a mounted volume at runtime).
# The bundled Chromium is deleted so a lost override fails at browser launch
# instead of silently running the unpatched build.
RUN mkdir -p /data && chown pwuser:pwuser /data \
 && rm -rf /ms-playwright/chromium* \
 && ! ls -d /ms-playwright/chromium* >/dev/null 2>&1
USER pwuser
EXPOSE 8080
CMD ["node", "dist/index.js"]
