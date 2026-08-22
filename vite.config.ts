import { defineConfig } from 'vitest/config';

export default defineConfig({
  base: '/crypto-lab-rekey-relay/',
  // Scope vitest to the unit suite. `e2e/*.spec.ts` belongs to Playwright and
  // would otherwise be swept up by vitest's default include glob.
  test: {
    include: ['test/**/*.test.ts'],
    // A single AFGH keygen computes Z^a1, a full 255-bit exponentiation in
    // Fp12, and several suites generate dozens of key pairs. Vitest's 5s
    // default is a wall-clock allowance, not a correctness threshold, and it
    // is the only thing raised here — no assertion is relaxed.
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
