import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';
import { clearDrafts } from '@/lib/drafts';

// jsdom has no pointer capture or scrolling; Radix Select calls both when it
// opens, so tests that pick from a select need these stand-ins.
Object.assign(Element.prototype, {
  hasPointerCapture: () => false,
  releasePointerCapture: () => undefined,
  scrollIntoView: () => undefined,
});

// Drafts live in module memory for the whole test file; each test starts clean.
afterEach(() => {
  cleanup();
  clearDrafts();
});
