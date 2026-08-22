import { defineConfig, devices } from '@playwright/test';

/**
 * E2E runs against the production build served by `vite preview`, so what
 * passes here is what ships. Two suites:
 *
 *   a11y.spec.ts    the axe WCAG A/AA gate, Chromium only (deterministic).
 *   claims.spec.ts  the claims suite: does the page tell the truth?
 *
 * Port 4699 is unique to this lab across the fleet, and is never the Vite
 * default 4173 — with 170+ labs side by side, a shared port means
 * `reuseExistingServer` silently scans a different lab's preview.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  timeout: 180_000, // the axe driver walks every panel and disclosure before scanning
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:4699/crypto-lab-rekey-relay/',
  },
  projects: [
    {
      name: 'a11y',
      testMatch: /a11y\.spec\.ts/,
      use: { ...devices['Desktop Chrome'], colorScheme: 'dark' },
    },
    {
      name: 'claims',
      testMatch: /claims\.spec\.ts/,
      use: { ...devices['Desktop Chrome'], colorScheme: 'dark' },
    },
  ],
  webServer: {
    // Build before serving: `vite preview` only serves whatever is already in
    // dist/, so without this a source change that fails to compile leaves the
    // last good bundle in place and the suite passes green against code that
    // no longer builds — which silently invalidates mutation checking.
    command: 'npm run build && npm run preview -- --port 4699 --strictPort',
    url: 'http://localhost:4699/crypto-lab-rekey-relay/',
    reuseExistingServer: !process.env.CI,
    timeout: 180_000,
  },
});
