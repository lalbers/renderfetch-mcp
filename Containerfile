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
# Playwright 1.64.1 bundles Chromium 156.0.8078.4, which lacks the fixes for
# CVE-2026-118306, -118331, -118344 and -118348 (Chrome 156.0.8078.73). Until a
# Playwright release bundles a fixed build, the image runs the Chrome for
# Testing headless shell of the same milestone, pinned by version and SHA-256.
# CI fails once the bundled build catches up; then drop this block, the
# override in the runtime stage, and the two Chrome for Testing steps in
# .github/workflows/ci.yml.
ARG CHROME_VERSION=156.0.8078.80
ARG CHROME_SHA256=547dcd374e02961bf998f6046a267644f8502225c36bb78ca307dab32a0b3eb4
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
