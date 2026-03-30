const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests/e2e',
  timeout: 60_000,
  use: {
    baseURL: 'http://127.0.0.1:3100',
    headless: true,
  },
  webServer: {
    command: 'node src/server.js',
    port: 3100,
    timeout: 120_000,
    reuseExistingServer: true,
    env: {
      PORT: '3100',
      JWT_SECRET: 'e2e-jwt-secret',
      AUDIT_SIGNING_SECRET: 'e2e-audit-secret',
      ADMIN_REQUIRE_MFA: 'false',
    },
  },
});
