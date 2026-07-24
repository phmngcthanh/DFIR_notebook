/**
 * HTTP transport for the centralized case server.
 *
 * `invoke` is a drop-in replacement for the Tauri `invoke` this project used as
 * a desktop app: same command names, same camelCase argument objects, same
 * `{ success, data, error }` envelope. Every feature component keeps its call
 * sites unchanged and only swaps the import.
 *
 * The session token lives in `sessionStorage`, so closing the tab ends the
 * session on that machine even if the server-side idle timeout has not elapsed.
 */
import type { ApiResponse, Case, ExpertIdentity } from '@/types';

const TOKEN_KEY = 'dfir-session-token';

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
 * Call a case command. Returns the full `ApiResponse` envelope, exactly as the
 * desktop `invoke` did, so callers keep checking `response.success` themselves.
 */
export function invoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  return request<T>(`/api/cmd/${command}`, args ?? {}, true);
}

export async function listCases(): Promise<CaseListing> {
  const response = await fetch('/api/cases').catch(() => null);
  if (!response) throw new Error('The case server is unreachable');
  const payload = (await response.json()) as ApiResponse<CaseListing>;
  if (!payload.success || !payload.data) throw new Error(payload.error || 'Could not list cases');
  return payload.data;
}

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
 * Browser stand-in for the desktop save dialog: the server hands back the text
 * and the browser writes the file wherever it saves downloads.
 */
export function downloadText(filename: string, contents: string): void {
  const url = URL.createObjectURL(new Blob([contents], { type: 'application/octet-stream' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

/** Browser stand-in for the desktop open dialog. Resolves to null when cancelled. */
export function pickTextFile(accept: string): Promise<{ name: string; text: string } | null> {
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
