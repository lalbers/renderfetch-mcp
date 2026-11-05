# Build + run the web-fetch MCP server on the official Playwright image
# (Ubuntu 24.04 "noble" / glibc). This base provides the system libraries for
# Chromium (the browser itself is the pinned build below) AND a glibc runtime, which the native modules (better-sqlite3,
# onnxruntime-node) require. Alpine/musl is not viable for Playwright Chromium
# or onnxruntime-node. The tag is pinned to match the `playwright` npm version.

FROM mcr.microsoft.com/playwright:v1.64.1-noble AS build
WORKDIR /app
ENV NODE_ENV=development
# Build tools so any native module without a matching prebuilt binary can compile.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ ca-certificates curl unzip \
 && rm -rf /var/lib/apt/lists/*
# Playwright 1.64.1 bundles Chromium 156.0.8078.4. It lacks the security fixes
# Chrome shipped since then: CVE-2026-118306 and three others in 156.0.8078.73,
# and those in 157.0.8103.38 (2026-11-03); Chrome for Testing publishes no 156
# build with the latter (latest 156.0.8078.80). Until a Playwright release
# bundles a current build, the image runs the stable Chrome for Testing
# headless shell, pinned by version and SHA-256.
# .github/workflows/chrome-pin.yml fails when Chrome stable moves past the pin;
# bump both ARGs then. CI fails when the bundled build is at least the pinned
# version. If Chrome stable is no newer than the bundled build at that point,
# remove the override: this block and `curl unzip` above, the ENV and the
# rm/ls check in the runtime stage, chrome-pin.yml, and in ci.yml the two
# Chrome for Testing steps and PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD (go back to
# `npx playwright install --with-deps chromium`).
ARG CHROME_VERSION=157.0.8103.38
ARG CHROME_SHA256=deafffa74660b34853a4119c361fd427ac8c9fcb62db51ddb8a797cd83a4ba2d
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

FROM mcr.microsoft.com/playwright:v1.64.1-noble AS runtime
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
