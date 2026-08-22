import { defineConfig } from 'vitest/config';

export default defineConfig({
  base: '/crypto-lab-rekey-relay/',
  // Scope vitest to the unit suite. `e2e/*.spec.ts` belongs to Playwright and
  // would otherwise be swept up by vitest's default include glob.
  test: {
    include: ['test/**/*.test.ts'],
  },
});
