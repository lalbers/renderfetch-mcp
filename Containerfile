# Build + run the web-fetch MCP server on the official Playwright image
# (Ubuntu 24.04 "noble" / glibc). This base provides Chromium + all system
# libraries AND a glibc runtime, which the native modules (better-sqlite3,
# onnxruntime-node) require. Alpine/musl is not viable for Playwright Chromium
# or onnxruntime-node. The tag is pinned to match the `playwright` npm version.

FROM mcr.microsoft.com/playwright:v1.60.0-noble AS build
WORKDIR /app
ENV NODE_ENV=development
# Build tools so any native module without a matching prebuilt binary can compile.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
# Reproducible install from the committed lockfile.
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
RUN npm run build \
 && npm prune --omit=dev

FROM mcr.microsoft.com/playwright:v1.60.0-noble AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NODE_OPTIONS=--enable-source-maps \
    DB_PATH=/data/renderfetch.db
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
# Persistent OAuth/token store lives under /data (a mounted volume at runtime).
RUN mkdir -p /data && chown -R pwuser:pwuser /app /data
USER pwuser
EXPOSE 8080
CMD ["node", "dist/index.js"]
