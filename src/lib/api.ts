/**
 * The one module in `src/` that knows which shell it is running in.
 *
 * Every feature component imports `invoke` from here and never branches on
 * platform itself. Two transports sit behind the same signature — Tauri IPC for
 * the desktop and mobile builds, `POST /api/cmd/{name}` for the browser talking
 * to the case server — with identical command names, camelCase argument
 * objects, and `{ success, data, error }` envelopes.
 *
 * `downloadText` and `pickTextFile` are the file-capability half of the seam:
 * a native dialog on Tauri, a blob download / file input in the browser.
 *
 * The session token lives in `sessionStorage`, so closing the tab ends the
 * session on that machine even if the server-side idle timeout has not elapsed.
 */
import { invoke as tauriInvoke } from '@tauri-apps/api/core';
import type { ApiResponse, Case, ExpertIdentity } from '@/types';

const TOKEN_KEY = 'dfir-session-token';

export type PlatformKind = 'desktop' | 'server';

/**
 * Tauri injects `__TAURI_INTERNALS__` into the webview before any app code
 * runs, so this is settled at module load and never changes for the lifetime of
 * the page. A plain browser — including `npm run dev` against the case server —
 * falls through to the HTTP transport.
 */
function detectPlatform(): PlatformKind {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window ? 'desktop' : 'server';
}

export const platform: PlatformKind = detectPlatform();
/** True in the Tauri desktop and Android shells: one local case, native dialogs. */
export const isDesktop = platform === 'desktop';
/** True in the browser shell: many cases, bearer tokens, revision polling. */
export const isServer = platform === 'server';

/** Fired when the server rejects our token so `App` can return to the login screen. */
export const SESSION_EXPIRED_EVENT = 'dfir-session-expired';

export interface CaseListing {
  cases: string[];
  allowCreate: boolean;
}

export interface SessionPayload {
  token: string;
  caseId: string;
  case?: Case | null;
  expert: ExpertIdentity;
  revision: number;
}

export interface ServerState {
  caseId: string;
  revision: number;
  activeExperts: string[];
}

export interface UnlockRequest {
  caseId: string;
  password: string;
  expertName: string;
  scopeLabel?: string | null;
  scopeNetworkIds?: string[];
}

export interface CreateCaseRequest {
  name: string;
  description: string;
  clientName: string;
  expertName: string;
  databasePassword: string;
}

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null): void {
  if (token) sessionStorage.setItem(TOKEN_KEY, token);
  else sessionStorage.removeItem(TOKEN_KEY);
}

/**
 * Highest case revision this browser has already seen — through the header on
 * its own command responses, through unlock, and through each poll. The poll
 * only announces a teammate's edit when the server has moved *past* this value,
 * so a browser never mistakes the bump from its own write for someone else's.
 * `-1` means "no baseline yet" (fresh load), which seeds silently.
 */
let observedRevision = -1;

export function getObservedRevision(): number {
  return observedRevision;
}

/** Advance the baseline; never moves backwards (writes and polls may race). */
export function noteRevision(revision: number): void {
  if (Number.isFinite(revision) && (observedRevision < 0 || revision > observedRevision)) {
    observedRevision = revision;
  }
}

/** Set the baseline for a new session, or clear it (`-1`) on logout. */
export function resetRevision(revision = -1): void {
  observedRevision = revision;
}

async function request<T>(path: string, body: unknown, authenticated: boolean): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (authenticated) {
    const token = getToken();
    if (!token) throw new Error('Unlock a case before using it');
    headers.Authorization = `Bearer ${token}`;
  }

  let response: globalThis.Response;
  try {
    response = await fetch(path, { method: 'POST', headers, body: JSON.stringify(body ?? {}) });
  } catch {
    throw new Error('The case server is unreachable. Check the connection and try again');
  }

  if (response.status === 401) {
    setToken(null);
    window.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
    const payload = (await response.json().catch(() => null)) as ApiResponse<never> | null;
    throw new Error(payload?.error || 'This session has expired. Unlock the case again');
  }
  if (!response.ok) {
    throw new Error(`The case server returned ${response.status}`);
  }
  const revision = response.headers.get('x-case-revision');
  if (revision) noteRevision(Number(revision));
  return (await response.json()) as T;
}

/**
 * Call a case command. Returns the full `ApiResponse` envelope on both shells,
 * so callers keep checking `response.success` themselves and never learn which
 * transport carried it.
 */
export function invoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (isDesktop) return tauriInvoke<T>(command, args ?? {});
  return request<T>(`/api/cmd/${command}`, args ?? {}, true);
}

export async function listCases(): Promise<CaseListing> {
  const response = await fetch('/api/cases').catch(() => null);
  if (!response) throw new Error('The case server is unreachable');
  const payload = (await response.json()) as ApiResponse<CaseListing>;
  if (!payload.success || !payload.data) throw new Error(payload.error || 'Could not list cases');
  return payload.data;
}

/**
 * Session capability, modelled explicitly rather than hidden behind a flag.
 *
 * The server shell holds many cases behind bearer tokens and a polled revision
 * counter. The desktop and mobile shells hold exactly one case in process state
 * and have no notion of a session at all — `hasSessions` is what `App.tsx`
 * branches on, so neither shell carries the other's ceremony.
 */
export const session = {
  hasSessions: isServer,
  /** Only the server shell can show other experts working in the same case. */
  hasLiveCollaboration: isServer,
  /** Only Tauri shells can open a case file through a native dialog. */
  hasLocalCaseFiles: isDesktop,
} as const;

export async function unlockCase(input: UnlockRequest): Promise<SessionPayload> {
  const payload = await request<ApiResponse<SessionPayload>>('/api/auth/unlock', input, false);
  if (!payload.success || !payload.data) throw new Error(payload.error || 'Could not unlock the case');
  setToken(payload.data.token);
  resetRevision(payload.data.revision);
  return payload.data;
}

export async function createCase(input: CreateCaseRequest): Promise<SessionPayload> {
  const payload = await request<ApiResponse<SessionPayload>>('/api/cases', input, false);
  if (!payload.success || !payload.data) throw new Error(payload.error || 'Could not create the case');
  setToken(payload.data.token);
  resetRevision(payload.data.revision);
  return payload.data;
}

export async function logout(): Promise<void> {
  try {
    if (getToken()) await request<ApiResponse<boolean>>('/api/auth/logout', {}, true);
  } finally {
    setToken(null);
    resetRevision();
  }
}

/** Polled to notice a teammate's edit. Reads server memory only — never the case file. */
export async function getServerState(): Promise<ServerState> {
  const token = getToken();
  if (!token) throw new Error('No session');
  const response = await fetch('/api/state', { headers: { Authorization: `Bearer ${token}` } });
  if (response.status === 401) {
    setToken(null);
    window.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
    throw new Error('This session has expired');
  }
  const payload = (await response.json()) as ApiResponse<ServerState>;
  if (!payload.success || !payload.data) throw new Error(payload.error || 'Could not read server state');
  return payload.data;
}

/**
 * Write text out under a name the investigator chooses. On Tauri this opens the
 * native save dialog; in the browser the server has already handed back the
 * text and this writes it wherever downloads go.
 */
export async function downloadText(filename: string, contents: string): Promise<void> {
  if (isDesktop) {
    const response = await tauriInvoke<ApiResponse<string>>('save_text_download', { filename, contents });
    // A cancelled dialog is a normal outcome, not an error worth surfacing.
    if (!response.success && !String(response.error ?? '').toLowerCase().includes('cancel')) {
      throw new Error(response.error || 'Could not save the file');
    }
    return;
  }
  browserDownload(filename, contents);
}

function browserDownload(filename: string, contents: string): void {
  const url = URL.createObjectURL(new Blob([contents], { type: 'application/octet-stream' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

/**
 * Read a file the investigator picks. Native dialog on Tauri, file input in the
 * browser. Resolves to null when the dialog is cancelled on either shell.
 */
export async function pickTextFile(accept: string): Promise<{ name: string; text: string } | null> {
  if (isDesktop) {
    const response = await tauriInvoke<ApiResponse<{ name: string; text: string } | null>>('open_text_upload');
    if (!response.success) throw new Error(response.error || 'Could not read the selected file');
    return response.data ?? null;
  }
  return browserPickFile(accept);
}

function browserPickFile(accept: string): Promise<{ name: string; text: string } | null> {
  return new Promise((resolve, reject) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = accept;
    input.style.display = 'none';
    const finish = (value: { name: string; text: string } | null) => {
      input.remove();
      resolve(value);
    };
    input.addEventListener('cancel', () => finish(null));
    input.addEventListener('change', () => {
      const file = input.files?.[0];
      if (!file) return finish(null);
      file
        .text()
        .then((text) => finish({ name: file.name, text }))
        .catch(() => {
          input.remove();
          reject(new Error('Could not read the selected file'));
        });
    });
    document.body.appendChild(input);
    input.click();
  });
}
