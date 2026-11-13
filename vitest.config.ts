import path from 'path';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { '@': path.resolve(__dirname, './src') } },
  test: {
    environment: 'jsdom',
    setupFiles: ['./tests/setup.ts'],
    // Screens with Radix selects and typed input take several seconds under a
    // loaded machine or CI runner; the default 5 s made them flaky.
    testTimeout: 20000,
  },
});
