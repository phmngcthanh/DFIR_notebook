import { useEffect, useState } from 'react';

const OVERRIDE_KEY = 'dfir-platform-override';

/**
 * Android detection for the mobile shell. Deliberately NOT width-based:
 * the desktop window can shrink below tablet breakpoints and must never
 * switch shells. A localStorage override ('android' | 'desktop') exists so
 * the mobile UI can be exercised inside the desktop build during development.
 */
export function detectAndroid(): boolean {
  try {
    const forced = window.localStorage.getItem(OVERRIDE_KEY);
    if (forced === 'android') return true;
    if (forced === 'desktop') return false;
  } catch {
    // localStorage unavailable — fall through to user agent detection
  }
  return /android/i.test(window.navigator.userAgent);
}

export function useIsAndroid(): boolean {
  const [isAndroid] = useState(detectAndroid);
  return isAndroid;
}

export function useIsPortrait(): boolean {
  const [isPortrait, setIsPortrait] = useState(
    () => window.matchMedia('(orientation: portrait)').matches,
  );
  useEffect(() => {
    const query = window.matchMedia('(orientation: portrait)');
    const onChange = () => setIsPortrait(query.matches);
    query.addEventListener('change', onChange);
    return () => query.removeEventListener('change', onChange);
  }, []);
  return isPortrait;
}
