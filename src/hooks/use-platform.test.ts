import { afterEach, describe, expect, it } from 'vitest';
import { detectAndroid } from './use-platform';

describe('detectAndroid', () => {
  afterEach(() => localStorage.clear());

  it('defaults to desktop under a non-Android user agent', () => {
    expect(detectAndroid()).toBe(false);
  });

  it('honors the android override used for desktop-side development', () => {
    localStorage.setItem('dfir-platform-override', 'android');
    expect(detectAndroid()).toBe(true);
  });

  it('honors an explicit desktop override', () => {
    localStorage.setItem('dfir-platform-override', 'desktop');
    expect(detectAndroid()).toBe(false);
  });
});
