/**
 * Unsaved investigator input — an open form, pasted text, a half-reviewed
 * import or merge — survives switching screens, and selected input survives
 * a restart too.
 *
 * Every feature view unmounts when the investigator navigates away. `useDraft`
 * is a drop-in for `useState` whose value is kept in this module's memory
 * under a key, so the view picks it up again when it mounts.
 *
 * Drafts are scoped to the open case and expert (`draftScope`, provided by
 * `App`); `pruneDrafts` drops every other scope when either changes or the
 * case is locked. Drafts opted in with `{ persist: true }` are also written,
 * debounced, to the case file through `configureDraftPersistence` — for the
 * expert who typed them, never into history, snapshots, or bundles — and
 * restored by `hydrateDrafts` on the next unlock. Passwords never go in a
 * draft.
 */
import {
  createContext, useCallback, useContext, useEffect, useRef, useState, type Dispatch, type SetStateAction,
} from 'react';

const store = new Map<string, unknown>();
const SEPARATOR = '\u0000';

/** Persisted drafts larger than this stay in memory only (mirrors MAX_DRAFT_BYTES in db.rs). */
export const MAX_PERSISTED_DRAFT_BYTES = 256 * 1024;
const FLUSH_DELAY_MS = 800;

/** The open case and expert. Drafts written under one scope are invisible to another. */
export const draftScope = createContext('');

interface Persistence {
  scope: string;
  save: (drafts: Record<string, unknown>) => Promise<void>;
}

let persistence: Persistence | null = null;
/** Slots whose last saved JSON is known, to skip saves that would change nothing. */
const persistedJson = new Map<string, string>();
/** Slot → value to save, or null to delete. */
const pending = new Map<string, unknown>();
let flushTimer: ReturnType<typeof setTimeout> | null = null;

function slotFor(scope: string, key: string): string {
  return `${scope}${SEPARATOR}${key}`;
}

function inScope(slot: string, scope: string): boolean {
  return slot.startsWith(`${scope}${SEPARATOR}`);
}

function schedule(slot: string, value: unknown): void {
  if (!persistence || !inScope(slot, persistence.scope)) return;
  if (value !== null) {
    let json: string;
    try {
      json = JSON.stringify(value) ?? 'null';
    } catch {
      return;
    }
    if (json.length > MAX_PERSISTED_DRAFT_BYTES) {
      // Too large to keep: forget any older saved copy rather than restore a stale one.
      if (!persistedJson.has(slot)) return;
      value = null;
    } else if (persistedJson.get(slot) === json) {
      pending.delete(slot);
      return;
    }
  } else if (!persistedJson.has(slot)) {
    pending.delete(slot);
    return;
  }
  pending.set(slot, value);
  if (flushTimer) clearTimeout(flushTimer);
  flushTimer = setTimeout(() => {
    flushTimer = null;
    void flushDrafts();
  }, FLUSH_DELAY_MS);
}

/**
 * `useState`, except the latest value is remembered under `key` for the open
 * case and expert, and restored when the component mounts again. With
 * `persist`, it is also saved to the case so it survives a restart.
 */
export function useDraft<T>(
  key: string,
  initial: T | (() => T),
  options?: { persist?: boolean },
): [T, Dispatch<SetStateAction<T>>] {
  const slot = slotFor(useContext(draftScope), key);
  const persist = Boolean(options?.persist);
  const [value, setValue] = useState<T>(() => {
    if (store.has(slot)) return store.get(slot) as T;
    return typeof initial === 'function' ? (initial as () => T)() : initial;
  });
  const firstValue = useRef(value);
  const edited = useRef(false);
  useEffect(() => {
    store.set(slot, value);
    // The value the view mounted with needs no save: it is either the default
    // or exactly what was just restored. After the first edit every value is
    // scheduled, including a return to the restored one, which cancels the
    // edit still waiting to be saved.
    if (value !== firstValue.current) edited.current = true;
    if (persist && edited.current) schedule(slot, value);
  }, [slot, value, persist]);
  return [value, setValue];
}

/**
 * For forms that close by unmounting rather than by resetting their fields:
 * returns a function that forgets every draft of the open scope whose key
 * starts with `prefix`, saved copies included. Call it on Save and Cancel;
 * leaving the screen keeps the draft.
 */
export function useDraftDiscard(): (prefix: string) => void {
  const scope = useContext(draftScope);
  return useCallback((prefix: string) => {
    const start = slotFor(scope, prefix);
    for (const slot of [...store.keys(), ...persistedJson.keys()]) {
      if (!slot.startsWith(start)) continue;
      store.delete(slot);
      schedule(slot, null);
    }
  }, [scope]);
}

/** Put a value into a draft before its view mounts (used to open search results). */
export function setDraftValue(scope: string, key: string, value: unknown): void {
  store.set(slotFor(scope, key), value);
}

/** Load drafts saved for this scope. Values already in memory win. */
export function hydrateDrafts(scope: string, drafts: Record<string, unknown>): void {
  for (const [key, value] of Object.entries(drafts)) {
    const slot = slotFor(scope, key);
    if (!store.has(slot)) store.set(slot, value);
    try {
      persistedJson.set(slot, JSON.stringify(value) ?? 'null');
    } catch {
      // A value that cannot be serialized was never saved by this module.
    }
  }
}

/** Start saving persistent drafts of `scope` through `save`. */
export function configureDraftPersistence(scope: string, save: Persistence['save']): void {
  persistence = { scope, save };
}

/** Save anything still waiting, now. */
export async function flushDrafts(): Promise<void> {
  if (flushTimer) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }
  const target = persistence;
  if (!target || pending.size === 0) return;
  const batch: Record<string, unknown> = {};
  const slots: [string, unknown][] = [];
  for (const [slot, value] of pending) {
    if (!inScope(slot, target.scope)) continue;
    batch[slot.slice(target.scope.length + SEPARATOR.length)] = value;
    slots.push([slot, value]);
  }
  for (const [slot] of slots) pending.delete(slot);
  if (!slots.length) return;
  try {
    await target.save(batch);
    for (const [slot, value] of slots) {
      if (value === null) persistedJson.delete(slot);
      else persistedJson.set(slot, JSON.stringify(value) ?? 'null');
    }
  } catch {
    // Keep the values in memory; the next change retries the save.
    for (const [slot, value] of slots) if (!pending.has(slot)) pending.set(slot, value);
  }
}

/** Flush, then stop saving drafts (on lock, case switch, or session end). */
export async function endDraftPersistence(): Promise<void> {
  const ending = persistence;
  await flushDrafts();
  // A new case or expert may have started saving while this flush ran.
  if (persistence === ending) persistence = null;
}

/** Keep only the drafts of `scope`; `null` (no case open) drops them all. */
export function pruneDrafts(scope: string | null): void {
  const keep = (slot: string) => scope !== null && inScope(slot, scope);
  for (const slot of [...store.keys()]) if (!keep(slot)) store.delete(slot);
  for (const slot of [...persistedJson.keys()]) if (!keep(slot)) persistedJson.delete(slot);
  for (const slot of [...pending.keys()]) if (!keep(slot)) pending.delete(slot);
}

/** Forget every draft (tests and full sign-out). */
export function clearDrafts(): void {
  store.clear();
  persistedJson.clear();
  pending.clear();
  if (flushTimer) clearTimeout(flushTimer);
  flushTimer = null;
  persistence = null;
}
