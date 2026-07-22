import { useCallback, useEffect, useMemo, useState } from 'react';
import { downloadText, invoke, pickTextFile } from '@/lib/api';
import {
  AlertTriangle, CheckCircle2, Clock3, Database, GitCompare,
  FileOutput, History, LockKeyhole, Network, RefreshCw, Trash2, Upload,
} from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import PartialImportPanel from '@/components/PartialImportPanel';
import type {
  ApiResponse, FieldDiff, HistoryCommit, JsonValue, MergeApplySummary,
  ImportSummary, MergeDecision, MergePreview, MergePreviewChange,
} from '@/types';

interface Props { refreshTrigger: number; onImport: () => void }

type ToggleState = Record<string, boolean>;
type ResolutionState = Record<string, JsonValue>;

const TOPOLOGY_ENTITIES = new Set(['network', 'asset', 'network_interface', 'firewall', 'firewall_interface', 'firewall_nat_rule', 'network_connection']);

export default function ExportImport({ refreshTrigger, onImport }: Props) {
  const [previews, setPreviews] = useState<MergePreview[]>([]);
  const [selected, setSelected] = useState<ToggleState>({});
  const [resolutions, setResolutions] = useState<ResolutionState>({});
  const [resolvedFields, setResolvedFields] = useState<Record<string, string[]>>({});
  const [history, setHistory] = useState<HistoryCommit[]>([]);
  const [importSummary, setImportSummary] = useState<ImportSummary | null>(null);
  const [busy, setBusy] = useState(false);
  const [encryptExports, setEncryptExports] = useState(false);
  const [exportPassword, setExportPassword] = useState('');
  const [exportPasswordConfirmation, setExportPasswordConfirmation] = useState('');
  const [importPassword, setImportPassword] = useState('');

  const loadHistory = useCallback(async () => {
    try {
      const response = await invoke<ApiResponse<HistoryCommit[]>>('list_case_history', { limit: 100 });
      if (!response.success) throw new Error(response.error || 'Could not load case history');
      setHistory(response.data ?? []);
    } catch (reason) { toast.error(String(reason)); }
  }, []);

  useEffect(() => { void loadHistory(); }, [loadHistory, refreshTrigger]);

  const addPreview = (preview: MergePreview) => {
    setPreviews((current) => [...current.filter((item) => item.bundle_id !== preview.bundle_id), preview]);
    setSelected((current) => {
      const next = { ...current };
      for (const change of preview.changes) next[changeKey(preview, change)] = defaultSelected(change);
      return next;
    });
  };

  // The browser reads the file the expert picked and posts its text; the server
  // never sees a filesystem path.
  const loadBundle = async () => {
    setBusy(true);
    try {
      const file = await pickTextFile('.json,.dfirx');
      if (!file) return;
      const response = await invoke<ApiResponse<MergePreview>>('load_change_bundle_text', { contents: file.text, password: importPassword || null });
      if (!response.success || !response.data) throw new Error(response.error || 'Could not load change bundle');
      addPreview(response.data);
      setImportPassword('');
      toast.success(`Loaded changes from ${response.data.exported_by}`);
    } catch (reason) { toast.error(String(reason)); }
    finally { setBusy(false); }
  };

  // The server returns the text and the browser downloads it, which is the web
  // half of the desktop save dialog.
  const saveSnapshot = async () => {
    setBusy(true);
    try {
      const password = selectedExportPassword(encryptExports, exportPassword, exportPasswordConfirmation);
      const response = await invoke<ApiResponse<string>>('export_case_json', { password });
      if (!response.success || response.data === undefined) throw new Error(response.error || 'Export failed');
      downloadText(password ? 'case-backup.dfirx' : 'case-backup.json', response.data);
      setExportPassword(''); setExportPasswordConfirmation('');
      toast.success('Case snapshot downloaded');
    } catch (reason) { toast.error(String(reason)); }
    finally { setBusy(false); }
  };

  const loadLegacySnapshot = async () => {
    setBusy(true);
    try {
      const file = await pickTextFile('.json,.dfirx');
      if (!file) return;
      const response = await invoke<ApiResponse<ImportSummary>>('import_case_json', { jsonData: file.text, password: importPassword || null });
      if (!response.success || !response.data) throw new Error(response.error || 'Snapshot import failed');
      setImportPassword('');
      setImportSummary(response.data); onImport(); await loadHistory();
      toast.success('Snapshot imported');
    } catch (reason) { toast.error(String(reason)); }
    finally { setBusy(false); }
  };

  const saveTextReport = async () => {
    setBusy(true);
    try {
      const file = await pickTextFile('.json,.dfirx');
      if (!file) return;
      const response = await invoke<ApiResponse<string>>('render_export_report', { contents: file.text, password: importPassword || null });
      if (!response.success || response.data === undefined) throw new Error(response.error || 'Could not render export as text');
      downloadText('dfir-export-report.txt', response.data);
      setImportPassword('');
      toast.success('Plain-text report downloaded');
    } catch (reason) { toast.error(String(reason)); }
    finally { setBusy(false); }
  };

  const chooseField = (preview: MergePreview, change: MergePreviewChange, field: FieldDiff, side: 'local' | 'incoming') => {
    const key = changeKey(preview, change);
    const seed = resolutions[key] ?? change.suggested ?? change.local ?? change.incoming;
    if (!isObject(seed)) return;
    const next: Record<string, JsonValue> = { ...seed };
    const value = side === 'local' ? field.local : field.incoming;
    if (value === undefined) delete next[field.field]; else next[field.field] = value;
    setResolutions((current) => ({ ...current, [key]: next }));
    setResolvedFields((current) => ({ ...current, [key]: [...new Set([...(current[key] ?? []), field.field])] }));
    setSelected((current) => ({ ...current, [key]: true }));
  };

  const applyPreview = async (preview: MergePreview) => {
    const decisions: MergeDecision[] = preview.changes.map((change) => {
      const key = changeKey(preview, change);
      const decision: MergeDecision = { change_id: change.id, selected: Boolean(selected[key]) };
      if (Object.prototype.hasOwnProperty.call(resolutions, key)) decision.resolved_after = resolutions[key];
      return decision;
    });
    setBusy(true);
    try {
      const response = await invoke<ApiResponse<MergeApplySummary>>('apply_pending_change_bundle', { bundleId: preview.bundle_id, decisions });
      if (!response.success || !response.data) throw new Error(response.error || 'Merge failed');
      toast.success(`Merged ${response.data.applied} change${response.data.applied === 1 ? '' : 's'}; skipped ${response.data.skipped}`);
      setPreviews((current) => current.filter((item) => item.bundle_id !== preview.bundle_id));
      onImport();
      await loadHistory();
      await refreshRemaining(preview.bundle_id);
    } catch (reason) { toast.error(String(reason)); }
    finally { setBusy(false); }
  };

  const setExpertSectionPolicy = (preview: MergePreview, entityType: 'timeline_event' | 'note', policy: 'skip' | 'add' | 'incoming') => {
    const changes = preview.changes.filter((change) => change.entity_type === entityType);
    setSelected((current) => {
      const next = { ...current };
      for (const change of changes) {
        const selectable = change.classification !== 'already_applied' && change.operation !== 'delete';
        next[changeKey(preview, change)] = selectable && (policy === 'incoming' || (policy === 'add' && change.operation === 'create'));
      }
      return next;
    });
    if (policy === 'incoming') {
      setResolutions((current) => {
        const next = { ...current };
        for (const change of changes) {
          if (change.operation !== 'delete' && change.incoming !== undefined) next[changeKey(preview, change)] = change.incoming;
        }
        return next;
      });
      setResolvedFields((current) => {
        const next = { ...current };
        for (const change of changes) next[changeKey(preview, change)] = change.fields.filter((field) => field.conflict).map((field) => field.field);
        return next;
      });
    }
  };

  const refreshRemaining = async (appliedBundleId: string) => {
    const remaining = previews.filter((item) => item.bundle_id !== appliedBundleId);
    for (const item of remaining) {
      const response = await invoke<ApiResponse<MergePreview>>('refresh_pending_change_bundle', { bundleId: item.bundle_id });
      if (response.success && response.data) addPreview(response.data);
    }
  };

  const discard = async (preview: MergePreview) => {
    try {
      const response = await invoke<ApiResponse<boolean>>('discard_pending_change_bundle', { bundleId: preview.bundle_id });
      if (!response.success) throw new Error(response.error || 'Could not discard the loaded bundle');
      setPreviews((current) => current.filter((item) => item.bundle_id !== preview.bundle_id));
    } catch (reason) { toast.error(String(reason)); }
  };

  const pendingCount = useMemo(() => previews.reduce((sum, item) => sum + item.changes.length, 0), [previews]);

  return (
    <div className="space-y-6 p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div><h2 className="flex items-center gap-2 text-2xl font-bold text-slate-800"><GitCompare className="text-cyan-600" />Case Transfer</h2>
          <p className="mt-1 max-w-3xl text-sm text-slate-500">Everyone on this server edits the same case, so routine work needs no merging. Use this page to take a backup out, bring an offline expert's bundle in, and read the audit history.</p></div>
        <Badge variant="outline">{pendingCount} pending changes</Badge>
      </div>

      <Card className="border-slate-200"><CardHeader><CardTitle className="flex items-center gap-2 text-base"><LockKeyhole size={18} />Portable-file protection</CardTitle></CardHeader><CardContent className="grid gap-5 lg:grid-cols-2">
        <div className="space-y-3"><div><p className="text-sm font-medium text-slate-800">New exports</p><p className="text-xs text-slate-500">Plain JSON stays readable by other tools. Encrypted `.dfirx` files keep the exact JSON payload inside a portable password envelope.</p></div>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={encryptExports} onChange={(event) => setEncryptExports(event.target.checked)} />Encrypt downloaded snapshots</label>
          {encryptExports && <div className="grid gap-3 sm:grid-cols-2"><PasswordField label="Export password" value={exportPassword} onChange={setExportPassword} /><PasswordField label="Confirm password" value={exportPasswordConfirmation} onChange={setExportPasswordConfirmation} /></div>}
          <p className="text-xs text-slate-500">Minimum 6 characters. This password is independent of the session expert name and is never stored.</p>
        </div>
        <div className="space-y-3"><div><p className="text-sm font-medium text-slate-800">Encrypted imports and text rendering</p><p className="text-xs text-slate-500">Enter the file password before loading an encrypted snapshot or expert bundle. Leave blank for unencrypted JSON.</p></div>
          <PasswordField label="Import / decrypt password" value={importPassword} onChange={setImportPassword} />
          <p className="text-xs text-slate-500">The password applies only to the next selected file and is cleared after success.</p>
        </div>
      </CardContent></Card>

      <PartialImportPanel disabled={busy} onApplied={() => { onImport(); void loadHistory(); }} />

      <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-4">
        <ActionCard icon={<Database />} title="Backup snapshot" description="Download the full case as interoperable JSON or an encrypted portable export." action="Download snapshot" disabled={busy} onClick={() => void saveSnapshot()} />
        <ActionCard icon={<Upload />} title="Review expert bundle" description="Upload a plain or encrypted bundle from an expert who worked offline. Loading only creates a preview." action="Load for review" disabled={busy} onClick={() => void loadBundle()} />
        <ActionCard icon={<Database />} title="Add-only snapshot import" description="Password-aware path: add missing UUIDs only. For selective sections or overwrites, use Plain structured partial import above." action="Import add-only" disabled={busy} onClick={() => void loadLegacySnapshot()} />
        <ActionCard icon={<FileOutput />} title="Text parser" description="Read a snapshot or change bundle and download a display-only plain-text report. The case is not changed." action="Create text report" disabled={busy} onClick={() => void saveTextReport()} />
      </div>

      {importSummary && <ImportSummaryPanel summary={importSummary} onClose={() => setImportSummary(null)} />}

      {previews.map((preview) => <BundleReview key={preview.bundle_id} preview={preview} selected={selected} resolutions={resolutions} resolvedFields={resolvedFields}
        busy={busy} setSelected={setSelected} chooseField={chooseField} setEntityPolicy={(entityType, policy) => setExpertSectionPolicy(preview, entityType, policy)} onApply={() => void applyPreview(preview)} onDiscard={() => void discard(preview)} />)}

      {previews.length === 0 && <Card className="border-dashed"><CardContent className="py-12 text-center text-sm text-slate-500">No expert bundles are loaded. Loading a bundle creates a preview only; the case changes only after the team accepts and applies selections.</CardContent></Card>}

      <HistoryPanel commits={history} onRefresh={() => void loadHistory()} />
    </div>
  );
}

function BundleReview({ preview, selected, resolutions, resolvedFields, busy, setSelected, chooseField, setEntityPolicy, onApply, onDiscard }: {
  preview: MergePreview; selected: ToggleState; resolutions: ResolutionState; resolvedFields: Record<string, string[]>; busy: boolean;
  setSelected: React.Dispatch<React.SetStateAction<ToggleState>>;
  chooseField: (preview: MergePreview, change: MergePreviewChange, field: FieldDiff, side: 'local' | 'incoming') => void;
  setEntityPolicy: (entityType: 'timeline_event' | 'note', policy: 'skip' | 'add' | 'incoming') => void;
  onApply: () => void; onDiscard: () => void;
}) {
  const topology = preview.changes.filter((change) => TOPOLOGY_ENTITIES.has(change.entity_type));
  const timeline = preview.changes.filter((change) => change.entity_type === 'timeline_event');
  const notes = preview.changes.filter((change) => change.entity_type === 'note');
  const selectedCount = preview.changes.filter((change) => selected[changeKey(preview, change)]).length;
  const conflicts = preview.changes.filter((change) => change.classification.includes('conflict')).length;
  const unresolvedConflicts = preview.changes.filter((change) => {
    const key = changeKey(preview, change);
    return selected[key] && change.classification === 'conflict'
      && change.fields.some((field) => field.conflict && !(resolvedFields[key] ?? []).includes(field.field));
  }).length;
  return <Card className="overflow-hidden">
    <CardHeader className="border-b bg-slate-50"><div className="flex flex-wrap items-start justify-between gap-3">
      <div><CardTitle className="text-base">{preview.exported_by}</CardTitle><p className="mt-1 text-xs text-slate-500">Exported {localTime(preview.exported_at)} · {preview.changes.length} entity changes</p></div>
      <div className="flex items-center gap-2">{!preview.common_base && <Badge variant="destructive">Unknown baseline</Badge>}{conflicts > 0 && <Badge className="bg-amber-100 text-amber-800">{conflicts} conflicts</Badge>}<Badge variant="outline">{selectedCount} selected</Badge></div>
    </div></CardHeader>
    <CardContent className="space-y-5 p-4">
      {!preview.common_base && <div className="flex gap-2 rounded border border-red-200 bg-red-50 p-3 text-sm text-red-800"><AlertTriangle size={18} className="shrink-0" />This bundle does not share a known baseline with the open case. All edits require explicit review.</div>}
      {topology.length > 0 && <ChangeStrip icon={<Network size={16} />} title="Topology and PC configuration" changes={topology} />}
      {timeline.length > 0 && <MergeSectionPolicy icon={<Clock3 size={16} />} title="Expert timeline" changes={timeline} onPolicy={(policy) => setEntityPolicy('timeline_event', policy)} />}
      {notes.length > 0 && <MergeSectionPolicy icon={<FileOutput size={16} />} title="Expert notes" changes={notes} onPolicy={(policy) => setEntityPolicy('note', policy)} />}
      <div className="space-y-3">{preview.changes.map((change) => {
        const key = changeKey(preview, change);
        return <ChangeReview key={change.id} change={change} checked={Boolean(selected[key])} resolution={resolutions[key]} resolvedFieldNames={resolvedFields[key] ?? []}
          onChecked={(checked) => setSelected((current) => ({ ...current, [key]: checked }))}
          chooseField={(field, side) => chooseField(preview, change, field, side)} />;
      })}</div>
      {unresolvedConflicts > 0 && <p className="rounded bg-amber-50 p-2 text-xs text-amber-800">Choose current or incoming for every highlighted conflicting field before applying.</p>}
      <div className="flex justify-end gap-2 border-t pt-4"><Button variant="ghost" onClick={onDiscard} disabled={busy}><Trash2 size={15} className="mr-2" />Discard preview</Button><Button onClick={onApply} disabled={busy || selectedCount === 0 || unresolvedConflicts > 0} className="bg-cyan-700 hover:bg-cyan-800"><CheckCircle2 size={15} className="mr-2" />Apply {selectedCount} selected</Button></div>
    </CardContent>
  </Card>;
}

function ChangeReview({ change, checked, resolution, resolvedFieldNames, onChecked, chooseField }: { change: MergePreviewChange; checked: boolean; resolution?: JsonValue; resolvedFieldNames: string[]; onChecked: (checked: boolean) => void; chooseField: (field: FieldDiff, side: 'local' | 'incoming') => void }) {
  const conflicting = change.classification.includes('conflict');
  return <details className={`rounded border ${conflicting ? 'border-amber-300' : 'border-slate-200'}`}>
    <summary className="flex cursor-pointer list-none items-center gap-3 p-3">
      <input type="checkbox" checked={checked} disabled={change.classification === 'already_applied'} onClick={(event) => event.stopPropagation()} onChange={(event) => onChecked(event.target.checked)} />
      <OperationBadge operation={change.operation} /><div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{entityTitle(change)}</p><p className="truncate text-xs text-slate-500">{humanEntity(change.entity_type)} · {change.message} · {change.author_name}{scopeText(change.scope)}</p></div>
      <ClassificationBadge value={change.classification} />
    </summary>
    <div className="border-t bg-white p-3">
      {change.fields.length === 0 ? <p className="text-xs text-slate-500">The complete entity is {change.operation === 'delete' ? 'removed' : 'added'}.</p> : <div className="overflow-x-auto"><table className="w-full table-fixed text-left text-xs"><thead><tr className="text-slate-500"><th className="w-36 p-2">Field</th><th className="p-2">Before</th><th className="p-2">Current master</th><th className="p-2">Incoming</th><th className="w-44 p-2">Decision</th></tr></thead><tbody>{change.fields.map((field) => <tr key={field.field} className={field.conflict ? 'bg-amber-50' : 'border-t'}><td className="break-all p-2 font-medium">{field.field}</td><ValueCell value={field.base} /><ValueCell value={field.local} /><ValueCell value={field.incoming} /><td className="p-2">{field.conflict ? <div className="flex gap-1"><Button type="button" variant="outline" size="sm" onClick={() => chooseField(field, 'local')}>Keep current</Button><Button type="button" variant="outline" size="sm" onClick={() => chooseField(field, 'incoming')}>Use incoming</Button></div> : <span className="text-slate-400">Auto</span>}</td></tr>)}</tbody></table></div>}
      {resolution !== undefined && <p className="mt-2 text-xs text-cyan-700">Manual choices recorded for {resolvedFieldNames.length} conflicting field{resolvedFieldNames.length === 1 ? '' : 's'}.</p>}
      {change.classification === 'delete_conflict' && <p className="mt-2 text-xs text-amber-700">Select this change to accept deletion, or leave it unselected to keep the current master record.</p>}
    </div>
  </details>;
}

function ChangeStrip({ icon, title, changes }: { icon: React.ReactNode; title: string; changes: MergePreviewChange[] }) {
  return <div><div className="mb-2 flex items-center gap-2 text-sm font-medium text-slate-700">{icon}{title}</div><div className="flex flex-wrap gap-2">{changes.map((change) => <div key={change.id} className={`rounded border-l-4 px-3 py-2 text-xs ${operationColor(change.operation)}`}><p className="max-w-64 truncate font-medium">{entityTitle(change)}</p><p className="text-slate-500">{change.operation} · {humanEntity(change.entity_type)}</p></div>)}</div></div>;
}

function MergeSectionPolicy({ icon, title, changes, onPolicy }: {
  icon: React.ReactNode; title: string; changes: MergePreviewChange[];
  onPolicy: (policy: 'skip' | 'add' | 'incoming') => void;
}) {
  return <div className="rounded border border-cyan-100 bg-cyan-50/40 p-3"><div className="flex flex-wrap items-center justify-between gap-2"><div className="flex items-center gap-2 text-sm font-medium text-slate-700">{icon}{title} <Badge variant="outline">{changes.length}</Badge></div><div className="flex flex-wrap gap-1"><Button type="button" size="sm" variant="outline" onClick={() => onPolicy('skip')}>Keep current only</Button><Button type="button" size="sm" variant="outline" onClick={() => onPolicy('add')}>Add expert records</Button><Button type="button" size="sm" variant="outline" onClick={() => onPolicy('incoming')}>Use expert versions</Button></div></div><p className="mt-2 text-xs text-slate-500">Add expert records keeps the master version of matching UUIDs. Use expert versions also overwrites matching UUIDs; differently identified records are retained together.</p><div className="mt-3"><ChangeStrip icon={null} title="" changes={changes} /></div></div>;
}

function HistoryPanel({ commits, onRefresh }: { commits: HistoryCommit[]; onRefresh: () => void }) {
  return <Card><CardHeader><div className="flex items-center justify-between"><CardTitle className="flex items-center gap-2 text-base"><History size={18} />Audit history</CardTitle><Button variant="ghost" size="sm" onClick={onRefresh}><RefreshCw size={14} /></Button></div></CardHeader><CardContent>
    {commits.length === 0 ? <p className="text-sm text-slate-500">No recorded edits.</p> : <div className="max-h-96 space-y-2 overflow-auto">{commits.map((commit) => <details key={commit.id} className="rounded border p-3"><summary className="cursor-pointer list-none"><div className="flex items-start justify-between gap-2"><div><p className="text-sm font-medium">{commit.message}</p><p className="text-xs text-slate-500">{commit.author_name} · {localTime(commit.created_at)}{scopeText(commit.scope)}</p></div><Badge variant="outline">{commit.changes.length}</Badge></div></summary><div className="mt-2 space-y-1 border-t pt-2">{commit.changes.map((change) => <p key={change.id} className="text-xs text-slate-600"><span className="font-medium">{change.operation}</span> {humanEntity(change.entity_type)} <span className="font-mono text-[10px] text-slate-400">{change.entity_id}</span></p>)}</div></details>)}</div>}
  </CardContent></Card>;
}

function ImportSummaryPanel({ summary, onClose }: { summary: ImportSummary; onClose: () => void }) {
  return <Card><CardHeader><div className="flex items-center justify-between"><CardTitle className="text-sm">Legacy snapshot result</CardTitle><Button variant="ghost" size="sm" onClick={onClose}>Close</Button></div></CardHeader><CardContent><div className="flex flex-wrap gap-2">{Object.entries(summary.entities).map(([entity, counts]) => <Badge key={entity} variant="outline">{humanEntity(entity)}: {counts.inserted} inserted, {counts.skipped} skipped</Badge>)}</div></CardContent></Card>;
}

function ActionCard({ icon, title, description, action, disabled, onClick }: { icon: React.ReactNode; title: string; description: string; action: string; disabled: boolean; onClick: () => void }) {
  return <Card><CardContent className="space-y-3 p-4"><div className="flex items-center gap-2 font-medium text-slate-800"><span className="text-cyan-700">{icon}</span>{title}</div><p className="min-h-10 text-xs text-slate-500">{description}</p><Button variant="outline" className="w-full" disabled={disabled} onClick={onClick}>{action}</Button></CardContent></Card>;
}

function PasswordField({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  const id = `password-${label.toLowerCase().replaceAll(/[^a-z0-9]+/g, '-')}`;
  return <div className="space-y-1"><Label htmlFor={id}>{label}</Label><Input id={id} type="password" autoComplete="new-password" value={value} onChange={(event) => onChange(event.target.value)} /></div>;
}

function selectedExportPassword(encrypted: boolean, password: string, confirmation: string): string | null {
  if (!encrypted) return null;
  if ([...password].length < 6) throw new Error('Encrypted export passwords must contain at least 6 characters');
  if (password !== confirmation) throw new Error('Export password confirmation does not match');
  return password;
}

function ValueCell({ value }: { value?: JsonValue }) { return <td className="break-words p-2 font-mono text-[11px] text-slate-600">{displayValue(value)}</td>; }
function OperationBadge({ operation }: { operation: string }) { return <Badge className={operation === 'create' ? 'bg-emerald-100 text-emerald-800' : operation === 'delete' ? 'bg-red-100 text-red-800' : 'bg-blue-100 text-blue-800'}>{operation}</Badge>; }
function ClassificationBadge({ value }: { value: string }) { const label = value.replace('_', ' '); return <Badge variant={value.includes('conflict') ? 'destructive' : 'outline'}>{label}</Badge>; }
function operationColor(operation: string) { return operation === 'create' ? 'border-emerald-500 bg-emerald-50' : operation === 'delete' ? 'border-red-500 bg-red-50' : 'border-amber-500 bg-amber-50'; }
function defaultSelected(change: MergePreviewChange) { return change.classification === 'clean' || change.classification === 'auto_mergeable'; }
function changeKey(preview: MergePreview, change: MergePreviewChange) { return `${preview.bundle_id}:${change.id}`; }
function humanEntity(value: string) { return value.replaceAll('_', ' '); }
function localTime(value: string) { const date = new Date(value); return Number.isNaN(date.valueOf()) ? value : date.toLocaleString(); }
function isObject(value: JsonValue | undefined): value is Record<string, JsonValue> { return Boolean(value) && typeof value === 'object' && !Array.isArray(value); }
function displayValue(value: JsonValue | undefined) { if (value === undefined) return '∅'; if (value === null) return 'null'; return typeof value === 'string' ? value || '""' : JSON.stringify(value); }
function entityTitle(change: MergePreviewChange) { const values = [change.incoming, change.local, change.before]; for (const value of values) { if (isObject(value)) { for (const key of ['name', 'title', 'value', 'description', 'ip_address']) { const item = value[key]; if (typeof item === 'string' && item) return item; } } } return change.entity_id; }
function scopeText(scope?: JsonValue) { if (!isObject(scope)) return ''; const label = scope.label; return typeof label === 'string' && label ? ` · scope: ${label}` : ''; }
