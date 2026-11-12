/**
 * Unsaved investigator input — an open form, pasted text, a half-reviewed
 * import or merge — survives switching screens.
 *
 * Every feature view unmounts when the investigator navigates away, which used
 * to throw that work away. `useDraft` is a drop-in for `useState` whose value
 * is kept in this module's memory under a key, so the view picks it up again
 * when it mounts.
 *
 * Drafts are scoped to the open case (`draftScope`, provided by `App`) and are
 * held in memory only: they never reach `localStorage`, `sessionStorage`, or
 * the case file, and `pruneDrafts` drops every other case's drafts when the
 * open case changes or is locked. Passwords must never be kept in a draft.
 */
import { createContext, useCallback, useContext, useEffect, useState, type Dispatch, type SetStateAction } from 'react';

const store = new Map<string, unknown>();
const SEPARATOR = '\u0000';

/** The open case id. Drafts written under one case are invisible to another. */
export const draftScope = createContext('');

function slotFor(scope: string, key: string): string {
  return `${scope}${SEPARATOR}${key}`;
}

/**
 * `useState`, except the latest value is remembered under `key` for the open
 * case and restored when the component mounts again.
 */
export function useDraft<T>(key: string, initial: T | (() => T)): [T, Dispatch<SetStateAction<T>>] {
  const slot = slotFor(useContext(draftScope), key);
  const [value, setValue] = useState<T>(() => {
    if (store.has(slot)) return store.get(slot) as T;
    return typeof initial === 'function' ? (initial as () => T)() : initial;
  });
  useEffect(() => {
    store.set(slot, value);
  }, [slot, value]);
  return [value, setValue];
}

/**
 * For forms that close by unmounting rather than by resetting their fields:
 * returns a function that forgets every draft of the open case whose key
 * starts with `prefix`. Call it on Save and Cancel; leaving the screen keeps
 * the draft.
 */
export function useDraftDiscard(): (prefix: string) => void {
  const scope = useContext(draftScope);
  return useCallback((prefix: string) => {
    const start = slotFor(scope, prefix);
    for (const slot of [...store.keys()]) {
      if (slot.startsWith(start)) store.delete(slot);
    }
  }, [scope]);
}

/** Keep only the drafts of `caseId`; `null` (no case open) drops them all. */
export function pruneDrafts(caseId: string | null): void {
  const keep = caseId === null ? null : `${caseId}${SEPARATOR}`;
  for (const slot of [...store.keys()]) {
    if (keep === null || !slot.startsWith(keep)) store.delete(slot);
  }
}

/** Forget every draft. */
export function clearDrafts(): void {
  store.clear();
}
