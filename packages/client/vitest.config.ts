import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: { '@prosa/crypto': fileURLToPath(new URL('../crypto/src/index.ts', import.meta.url)) },
  },
  test: { testTimeout: 30_000, hookTimeout: 120_000 },
});
