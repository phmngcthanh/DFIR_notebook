import { useCallback, useEffect, useMemo, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { GitMerge, RefreshCw, SquareKanban, UserRound } from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import type { ApiResponse, HistoryChange, HistoryCommit, JsonValue } from '@/types';

interface Props { refreshTrigger: number }

interface SessionGroup {
  sessionId: string;
  commits: HistoryCommit[];
  firstAt: Date;
  lastAt: Date;
}

interface ExpertColumn {
  name: string;
  sessions: SessionGroup[];
  changeCount: number;
  lastAt: Date;
}

const ENTITY_COLORS: Record<string, string> = {
  asset: 'bg-emerald-100 text-emerald-800',
  network: 'bg-sky-100 text-sky-800',
  network_interface: 'bg-sky-100 text-sky-800',
  network_connection: 'bg-indigo-100 text-indigo-800',
  firewall: 'bg-orange-100 text-orange-800',
  firewall_interface: 'bg-orange-100 text-orange-800',
  firewall_nat_rule: 'bg-orange-100 text-orange-800',
  timeline_event: 'bg-violet-100 text-violet-800',
  clock_profile: 'bg-violet-100 text-violet-800',
  ioc: 'bg-red-100 text-red-800',
  note: 'bg-amber-100 text-amber-800',
  topology_view: 'bg-cyan-100 text-cyan-800',
  case: 'bg-slate-200 text-slate-700',
};

const IGNORED_DIFF_FIELDS = new Set(['id', 'created_at', 'updated_at', 'case_id']);

export default function ActivityBoard({ refreshTrigger }: Props) {
  const [commits, setCommits] = useState<HistoryCommit[]>([]);
  const [entityFilter, setEntityFilter] = useState('all');
  const [loading, setLoading] = useState(false);

  const loadHistory = useCallback(async () => {
    setLoading(true);
    try {
      const response = await invoke<ApiResponse<HistoryCommit[]>>('list_case_history', { limit: 1000 });
      if (!response.success) throw new Error(response.error || 'Could not load case history');
      setCommits((response.data ?? []).filter((commit) => commit.author_name !== 'system'));
    } catch (reason) {
      toast.error(String(reason));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void loadHistory(); }, [loadHistory, refreshTrigger]);

  const entityTypes = useMemo(() => {
    const types = new Set<string>();
    for (const commit of commits) for (const change of commit.changes) types.add(change.entity_type);
    return [...types].sort();
  }, [commits]);

  const columns = useMemo(
    () => buildColumns(entityFilter === 'all' ? commits : commits
      .map((commit) => ({ ...commit, changes: commit.changes.filter((change) => change.entity_type === entityFilter) }))
      .filter((commit) => commit.changes.length > 0 || commit.parent_ids.length > 1)),
    [commits, entityFilter],
  );

  const sessionCount = columns.reduce((total, column) => total + column.sessions.length, 0);
  const changeCount = columns.reduce((total, column) => total + column.changeCount, 0);

  return (
    <div className="flex h-full flex-col p-6">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-2xl font-bold text-slate-800"><SquareKanban className="text-cyan-700" size={24} />Activity Board</h2>
          <p className="mt-1 text-sm text-slate-500">
            Every recorded change grouped by expert and work session — including work merged in from other experts' bundles.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Select value={entityFilter} onValueChange={setEntityFilter}>
            <SelectTrigger className="w-44"><SelectValue placeholder="All record types" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All record types</SelectItem>
              {entityTypes.map((type) => <SelectItem key={type} value={type}>{humanEntity(type)}</SelectItem>)}
            </SelectContent>
          </Select>
          <Button variant="outline" size="sm" disabled={loading} onClick={() => void loadHistory()}>
            <RefreshCw size={14} className={loading ? 'mr-1 animate-spin' : 'mr-1'} />Refresh
          </Button>
        </div>
      </div>

      <div className="mb-4 flex flex-wrap gap-2 text-xs text-slate-600">
        <Badge variant="outline">{columns.length} expert{columns.length === 1 ? '' : 's'}</Badge>
        <Badge variant="outline">{sessionCount} session{sessionCount === 1 ? '' : 's'}</Badge>
        <Badge variant="outline">{changeCount} change{changeCount === 1 ? '' : 's'}</Badge>
      </div>

      {columns.length === 0 ? (
        <div className="flex flex-1 items-center justify-center text-sm text-slate-500">
          No recorded activity yet. Changes appear here as experts edit the case or merge bundles.
        </div>
      ) : (
        <div className="flex flex-1 gap-4 overflow-x-auto pb-2">
          {columns.map((column) => <ExpertLane key={column.name} column={column} />)}
        </div>
      )}
    </div>
  );
}

function ExpertLane({ column }: { column: ExpertColumn }) {
  return (
    <div className="flex w-80 flex-shrink-0 flex-col rounded-lg border bg-slate-100/70">
      <div className="flex items-center justify-between gap-2 border-b bg-white px-3 py-2.5 rounded-t-lg">
        <div className="flex min-w-0 items-center gap-2">
          <span className="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-full bg-cyan-600 text-xs font-semibold text-white">
            {initials(column.name)}
          </span>
          <span className="truncate text-sm font-semibold text-slate-800">{column.name}</span>
        </div>
        <Badge variant="outline" className="flex-shrink-0">{column.changeCount}</Badge>
      </div>
      <div className="flex-1 space-y-4 overflow-y-auto p-3">
        {column.sessions.map((session) => (
          <div key={session.sessionId}>
            <p className="mb-2 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-slate-500">
              <UserRound size={12} />{sessionLabel(session)}
            </p>
            <div className="space-y-2">
              {session.commits.map((commit) => <CommitCard key={commit.id} commit={commit} />)}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function CommitCard({ commit }: { commit: HistoryCommit }) {
  const isMerge = commit.parent_ids.length > 1;
  const counts = new Map<string, { entityType: string; label: string; count: number }>();
  for (const change of commit.changes) {
    const key = `${change.operation}|${change.entity_type}`;
    const entry = counts.get(key) ?? { entityType: change.entity_type, label: `${change.operation} ${humanEntity(change.entity_type)}`, count: 0 };
    entry.count += 1;
    counts.set(key, entry);
  }
  return (
    <details className="rounded-md border bg-white shadow-sm">
      <summary className="cursor-pointer list-none p-2.5">
        <div className="flex items-start justify-between gap-2">
          <p className="min-w-0 flex-1 text-sm font-medium text-slate-800">{commit.message}</p>
          {isMerge && <Badge className="flex-shrink-0 bg-purple-100 text-purple-800"><GitMerge size={11} className="mr-1" />merge</Badge>}
        </div>
        <p className="mt-1 text-[11px] text-slate-400">{localTime(commit.created_at)}</p>
        {counts.size > 0 && (
          <div className="mt-2 flex flex-wrap gap-1">
            {[...counts.entries()].map(([key, entry]) => (
              <span key={key} className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${ENTITY_COLORS[entry.entityType] ?? 'bg-slate-100 text-slate-600'}`}>
                {entry.count > 1 ? `${entry.count} × ` : ''}{entry.label}
              </span>
            ))}
          </div>
        )}
      </summary>
      <div className="space-y-2 border-t bg-slate-50/60 p-2.5">
        {commit.changes.length === 0 && <p className="text-xs text-slate-500">No record changes (merge bookkeeping only).</p>}
        {commit.changes.map((change) => <ChangeDetail key={change.id} change={change} />)}
      </div>
    </details>
  );
}

function ChangeDetail({ change }: { change: HistoryChange }) {
  const diffs = fieldDiffs(change);
  return (
    <div className="rounded border bg-white p-2 text-xs">
      <p className="font-medium text-slate-700">
        <OperationWord operation={change.operation} /> {humanEntity(change.entity_type)}
        <span className="text-slate-500"> — {changeTitle(change)}</span>
      </p>
      {change.operation === 'update' && diffs.length > 0 && (
        <div className="mt-1.5 space-y-1">
          {diffs.map((diff) => (
            <p key={diff.field} className="break-words text-[11px] text-slate-600">
              <span className="font-medium">{humanEntity(diff.field)}:</span>{' '}
              <span className="text-red-700 line-through decoration-red-300">{displayValue(diff.before)}</span>
              {' → '}
              <span className="text-emerald-700">{displayValue(diff.after)}</span>
            </p>
          ))}
        </div>
      )}
    </div>
  );
}

function OperationWord({ operation }: { operation: string }) {
  const color = operation === 'create' ? 'text-emerald-700' : operation === 'delete' ? 'text-red-700' : 'text-blue-700';
  const word = operation === 'create' ? 'Added' : operation === 'delete' ? 'Removed' : 'Updated';
  return <span className={color}>{word}</span>;
}

function buildColumns(commits: HistoryCommit[]): ExpertColumn[] {
  const byExpert = new Map<string, Map<string, HistoryCommit[]>>();
  for (const commit of commits) {
    const sessions = byExpert.get(commit.author_name) ?? new Map<string, HistoryCommit[]>();
    const group = sessions.get(commit.session_id) ?? [];
    group.push(commit);
    sessions.set(commit.session_id, group);
    byExpert.set(commit.author_name, sessions);
  }
  const columns: ExpertColumn[] = [];
  for (const [name, sessions] of byExpert) {
    const groups: SessionGroup[] = [...sessions.entries()].map(([sessionId, list]) => {
      const sorted = [...list].sort((a, b) => commitTime(b) - commitTime(a));
      return {
        sessionId,
        commits: sorted,
        firstAt: new Date(commitTime(sorted[sorted.length - 1])),
        lastAt: new Date(commitTime(sorted[0])),
      };
    }).sort((a, b) => b.lastAt.valueOf() - a.lastAt.valueOf());
    columns.push({
      name,
      sessions: groups,
      changeCount: [...sessions.values()].flat().reduce((total, commit) => total + commit.changes.length, 0),
      lastAt: groups[0].lastAt,
    });
  }
  return columns.sort((a, b) => b.lastAt.valueOf() - a.lastAt.valueOf());
}

function fieldDiffs(change: HistoryChange): { field: string; before?: JsonValue; after?: JsonValue }[] {
  if (!isObject(change.before) || !isObject(change.after)) return [];
  const before = change.before;
  const after = change.after;
  const fields = new Set([...Object.keys(before), ...Object.keys(after)]);
  const diffs: { field: string; before?: JsonValue; after?: JsonValue }[] = [];
  for (const field of fields) {
    if (IGNORED_DIFF_FIELDS.has(field)) continue;
    if (JSON.stringify(before[field]) !== JSON.stringify(after[field])) {
      diffs.push({ field, before: before[field], after: after[field] });
    }
  }
  return diffs;
}

function changeTitle(change: HistoryChange): string {
  for (const value of [change.after, change.before]) {
    if (isObject(value)) {
      for (const key of ['name', 'title', 'value', 'description', 'ip_address']) {
        const item = value[key];
        if (typeof item === 'string' && item) return item;
      }
    }
  }
  return change.entity_id.slice(0, 8);
}

function sessionLabel(session: SessionGroup): string {
  const sameDay = session.firstAt.toDateString() === session.lastAt.toDateString();
  const day = session.lastAt.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  if (sameDay) {
    const from = session.firstAt.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    const to = session.lastAt.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    return from === to ? `${day} · ${to}` : `${day} · ${from}–${to}`;
  }
  const firstDay = session.firstAt.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  return `${firstDay} – ${day}`;
}

function initials(name: string): string {
  const parts = name.trim().split(/\s+/u).filter(Boolean);
  if (parts.length === 0) return '?';
  const letters = parts.length === 1 ? parts[0].slice(0, 2) : `${parts[0][0]}${parts[parts.length - 1][0]}`;
  return letters.toUpperCase();
}

function commitTime(commit: HistoryCommit): number {
  const time = new Date(commit.created_at).valueOf();
  return Number.isNaN(time) ? 0 : time;
}

function humanEntity(value: string) { return value.replaceAll('_', ' '); }
function localTime(value: string) { const date = new Date(value); return Number.isNaN(date.valueOf()) ? value : date.toLocaleString(); }
function isObject(value: JsonValue | undefined): value is Record<string, JsonValue> { return Boolean(value) && typeof value === 'object' && !Array.isArray(value); }
function displayValue(value: JsonValue | undefined) { if (value === undefined) return '∅'; if (value === null) return 'null'; return typeof value === 'string' ? value || '""' : JSON.stringify(value); }
