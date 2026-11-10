import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';
import { clearDrafts } from '@/lib/drafts';

// Drafts live in module memory for the whole test file; each test starts clean.
afterEach(() => {
  cleanup();
  clearDrafts();
});
