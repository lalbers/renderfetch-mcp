import { defineConfig } from 'vitest/config';

// Test-time configuration. Required env is injected here so importing src/config
// doesn't exit. Tier-2 (ONNX) is disabled for fast, dependency-light unit tests.
export default defineConfig({
  test: {
    environment: 'node',
    testTimeout: 30000,
    hookTimeout: 30000,
    env: {
      PUBLIC_BASE_URL: 'https://mcp.test.example',
      AUTH_USERNAME: 'tester',
      AUTH_PASSWORD: 'test-pass-phrase',
      JWT_SECRET: 'test-secret-test-secret-test-secret-0123456789',
      DB_PATH: ':memory:',
      FILTER_TIER2: 'false',
      CHROMIUM_NO_SANDBOX: 'true',
      LOG_LEVEL: 'silent',
    },
  },
});
