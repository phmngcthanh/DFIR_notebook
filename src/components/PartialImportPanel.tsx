import { useMemo, useState } from 'react';
import { downloadText, invoke, pickTextFile } from '@/lib/api';
import { AlertTriangle, CheckCircle2, FileJson2, FileUp, ListChecks, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Textarea } from '@/components/ui/textarea';
import type {
  ApiResponse, JsonValue, PartialApplySummary, PartialImportPreview,
  PartialImportPreviewChange, PartialSelectionValidation,
} from '@/types';

interface Props { disabled: boolean; onApplied: () => void }
type Selection = Record<string, boolean>;
type SectionPolicy = 'skip' | 'add' | 'incoming';

const SECTION_ORDER = [
  'case', 'network', 'asset', 'network_interface', 'clock_profile', 'firewall',
  'network_connection', 'timeline_event', 'ioc', 'note',
];

export default function PartialImportPanel({ disabled, onApplied }: Props) {
  const [jsonText, setJsonText] = useState('');
  const [preview, setPreview] = useState<PartialImportPreview | null>(null);
  const [selected, setSelected] = useState<Selection>({});
  const [validation, setValidation] = useState<PartialSelectionValidation | null>(null);
  const [busy, setBusy] = useState(false);

  const groups = useMemo(() => {
    const values = new Map<string, PartialImportPreviewChange[]>();
    for (const change of preview?.changes ?? []) {
      values.set(change.entity_type, [...(values.get(change.entity_type) ?? []), change]);
    }
    return [...values].sort(([left], [right]) => SECTION_ORDER.indexOf(left) - SECTION_ORDER.indexOf(right));
  }, [preview]);
  const selectedIds = useMemo(
    () => (preview?.changes ?? []).filter((change) => selected[change.id] && change.valid && !['unchanged', 'invalid'].includes(change.operation)).map((change) => change.id),
    [preview, selected],
  );

  const initializePreview = (value: PartialImportPreview) => {
    const initial: Selection = {};
    for (const change of value.changes) initial[change.id] = change.recommended_selected;
    setPreview(value);
    setSelected(initial);
    setValidation(null);
  };

  const loadTemplate = async () => {
    try {
      const response = await invoke<ApiResponse<string>>('get_partial_import_template');
      if (!response.success || !response.data) throw new Error(response.error || 'Could not generate template');
      setJsonText(response.data);
      setPreview(null);
      toast.success('Template loaded into the editor');
    } catch (reason) { toast.error(String(reason)); }
  };

  const saveTemplate = async () => {
    try {
      const response = await invoke<ApiResponse<string>>('get_partial_import_template');
      if (!response.success || !response.data) throw new Error(response.error || 'Could not save template');
      downloadText('dfir-partial-import-template.json', response.data);
      toast.success('Plain partial-import template downloaded');
    } catch (reason) { toast.error(String(reason)); }
  };

  const previewText = async () => {
    if (!jsonText.trim()) { toast.error('Paste or load JSON first'); return; }
    setBusy(true);
    try {
      const response = await invoke<ApiResponse<PartialImportPreview>>('preview_partial_import_text', { jsonData: jsonText });
      if (!response.success || !response.data) throw new Error(response.error || 'Could not parse partial import');
      initializePreview(response.data);
      toast.success(`Verified ${response.data.changes.length} proposed record(s)`);
    } catch (reason) { toast.error(String(reason)); }
    finally { setBusy(false); }
  };

  const loadFile = async () => {
    setBusy(true);
    try {
      const file = await pickTextFile('.json');
      if (!file) return;
      const response = await invoke<ApiResponse<PartialImportPreview>>('preview_partial_import_text', { jsonData: file.text });
      if (!response.success || !response.data) throw new Error(response.error || 'Could not load plain JSON');
      setJsonText('');
      initializePreview(response.data);
      toast.success(`Verified ${response.data.changes.length} proposed record(s)`);
    } catch (reason) { toast.error(String(reason)); }
    finally { setBusy(false); }
  };

  const setPolicy = (entityType: string, policy: SectionPolicy) => {
    if (!preview) return;
    setSelected((current) => {
      const next = { ...current };
      for (const change of preview.changes.filter((item) => item.entity_type === entityType)) {
        next[change.id] = change.valid && (
          policy === 'incoming' ? ['create', 'update'].includes(change.operation)
            : policy === 'add' ? change.operation === 'create' : false
        );
      }
      return next;
    });
    setValidation(null);
  };

  const apply = async () => {
    if (!preview || selectedIds.length === 0) { toast.error('Select at least one valid change'); return; }
    setBusy(true);
    try {
      const check = await invoke<ApiResponse<PartialSelectionValidation>>('validate_pending_partial_import', {
        previewId: preview.preview_id, selectedChangeIds: selectedIds,
      });
      if (!check.success || !check.data) throw new Error(check.error || 'Selection validation failed');
      setValidation(check.data);
      if (!check.data.valid) throw new Error(check.data.errors.join('\n'));
      const accepted = confirm(
        `Apply ${check.data.selected_count} reviewed change(s)?\n\n` +
        `${check.data.create_count} new record(s) will be added.\n` +
        `${check.data.update_count} matching record(s) will use incoming values.\n\n` +
        'The complete selection is transactional and will be attributed to the active expert.',
      );
      if (!accepted) return;
      const response = await invoke<ApiResponse<PartialApplySummary>>('apply_pending_partial_import', {
        previewId: preview.preview_id, selectedChangeIds: selectedIds,
      });
      if (!response.success || !response.data) throw new Error(response.error || 'Partial import failed');
      toast.success(`Partial import applied: ${response.data.created} created, ${response.data.updated} updated`);
      setPreview(null);
      setSelected({});
      setValidation(null);
      onApplied();
    } catch (reason) { toast.error(String(reason)); }
    finally { setBusy(false); }
  };

  const discard = async () => {
    try {
      if (preview) {
        const response = await invoke<ApiResponse<boolean>>('discard_pending_partial_import', { previewId: preview.preview_id });
        if (!response.success) throw new Error(response.error || 'Could not discard the pending preview');
      }
    } catch (reason) { toast.error(String(reason)); }
    setPreview(null);
    setSelected({});
    setValidation(null);
  };

  return <Card className="border-indigo-200">
    <CardHeader><CardTitle className="flex items-center gap-2 text-base"><FileJson2 size={18} />Plain structured partial import</CardTitle></CardHeader>
    <CardContent className="space-y-4">
      <div className="rounded border border-indigo-100 bg-indigo-50/60 p-3 text-sm text-slate-700">
        <p className="font-medium">For LLM extraction, scripts, and information received from other teams</p>
        <p className="mt-1 text-xs">Generate a case-aware JSON template containing valid fields and an ID catalog. Give it to an LLM/person, then paste or open the returned plain JSON. A normal unencrypted case snapshot is also accepted. Parsing and preview never change the case.</p>
      </div>
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" onClick={() => void loadTemplate()} disabled={disabled || busy}><FileJson2 size={15} className="mr-2" />Load template into editor</Button>
        <Button variant="outline" onClick={() => void saveTemplate()} disabled={disabled || busy}>Save template file</Button>
        <Button variant="outline" onClick={() => void loadFile()} disabled={disabled || busy}><FileUp size={15} className="mr-2" />Open plain JSON</Button>
      </div>
      <Textarea className="min-h-48 font-mono text-xs" value={jsonText} onChange={(event) => setJsonText(event.target.value)} placeholder="Paste dfir-investigator-partial JSON, a fenced JSON block returned by an LLM, or a plain case snapshot…" />
      <div className="flex items-center justify-between gap-3"><p className="text-xs text-slate-500">Encrypted files continue through Snapshot import or Expert bundle review.</p><Button onClick={() => void previewText()} disabled={disabled || busy || !jsonText.trim()} className="bg-indigo-600 hover:bg-indigo-700"><ListChecks size={15} className="mr-2" />Parse, verify, and preview</Button></div>

      {preview && <div className="space-y-4 border-t pt-4">
        <div className="flex flex-wrap items-start justify-between gap-3"><div><p className="font-medium">{preview.source}</p><p className="text-xs text-slate-500">{preview.source_kind === 'snapshot' ? 'Plain snapshot converted to selective changes' : 'Structured partial document'} · {preview.changes.length} proposed record(s)</p></div><div className="flex gap-2"><Badge variant="outline">{selectedIds.length} selected</Badge>{preview.changes.some((change) => !change.valid) && <Badge variant="destructive">{preview.changes.filter((change) => !change.valid).length} invalid</Badge>}</div></div>
        {preview.warnings.map((warning) => <div key={warning} className="flex gap-2 rounded border border-amber-200 bg-amber-50 p-2 text-xs text-amber-800"><AlertTriangle size={15} />{warning}</div>)}
        <div className="space-y-4">{groups.map(([entityType, changes]) => <SectionReview key={entityType} entityType={entityType} changes={changes} selected={selected} setSelected={(id, value) => { setSelected((current) => ({ ...current, [id]: value })); setValidation(null); }} setPolicy={(policy) => setPolicy(entityType, policy)} />)}</div>
        {validation && <div className={`rounded p-3 text-sm ${validation.valid ? 'bg-emerald-50 text-emerald-800' : 'bg-red-50 text-red-800'}`}>{validation.valid ? <span className="flex items-center gap-2"><CheckCircle2 size={16} />Selection verified: {validation.create_count} create, {validation.update_count} update.</span> : validation.errors.join(' ')}</div>}
        <div className="flex justify-end gap-2 border-t pt-3"><Button variant="ghost" onClick={() => void discard()} disabled={busy}><Trash2 size={15} className="mr-2" />Discard preview</Button><Button onClick={() => void apply()} disabled={busy || selectedIds.length === 0} className="bg-indigo-700 hover:bg-indigo-800"><CheckCircle2 size={15} className="mr-2" />Validate and confirm {selectedIds.length}</Button></div>
      </div>}
    </CardContent>
  </Card>;
}

function SectionReview({ entityType, changes, selected, setSelected, setPolicy }: {
  entityType: string; changes: PartialImportPreviewChange[]; selected: Selection;
  setSelected: (id: string, value: boolean) => void; setPolicy: (policy: SectionPolicy) => void;
}) {
  const creates = changes.filter((change) => change.operation === 'create').length;
  const updates = changes.filter((change) => change.operation === 'update').length;
  return <div className="overflow-hidden rounded border border-slate-200">
    <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-50 p-3"><div><p className="text-sm font-semibold">{humanEntity(entityType)}</p><p className="text-xs text-slate-500">{creates} new · {updates} matching update · {changes.length - creates - updates} unchanged/invalid</p></div><div className="flex flex-wrap gap-1"><PolicyButton text="Skip section" onClick={() => setPolicy('skip')} /><PolicyButton text="Add missing only" onClick={() => setPolicy('add')} /><PolicyButton text="Use incoming versions" onClick={() => setPolicy('incoming')} /></div></div>
    <div className="divide-y">{changes.map((change) => <details key={change.id} className={change.valid ? '' : 'bg-red-50/50'}><summary className="flex cursor-pointer list-none items-center gap-3 p-3"><input type="checkbox" checked={Boolean(selected[change.id])} disabled={!change.valid || ['unchanged','invalid'].includes(change.operation)} onClick={(event) => event.stopPropagation()} onChange={(event) => setSelected(change.id, event.target.checked)} /><Operation value={change.operation} /><div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{change.title}</p><p className="truncate font-mono text-xs text-slate-500">{change.entity_id || 'ID will be generated'}</p></div>{change.error && <Badge variant="destructive">Invalid</Badge>}</summary><div className="border-t bg-white p-3">{change.error ? <p className="text-sm text-red-700">{change.error}</p> : change.fields.length ? <div className="overflow-x-auto"><table className="w-full table-fixed text-left text-xs"><thead><tr className="text-slate-500"><th className="w-44 p-2">Field</th><th className="p-2">Current</th><th className="p-2">Incoming</th></tr></thead><tbody>{change.fields.map((field) => <tr key={field.field} className="border-t"><td className="break-all p-2 font-medium">{field.field}</td><ValueCell value={field.current} /><ValueCell value={field.incoming} /></tr>)}</tbody></table></div> : <p className="text-xs text-slate-500">No field difference.</p>}</div></details>)}</div>
  </div>;
}

function PolicyButton({ text, onClick }: { text: string; onClick: () => void }) { return <Button type="button" size="sm" variant="outline" onClick={onClick}>{text}</Button>; }
function Operation({ value }: { value: string }) { const style = value === 'create' ? 'bg-emerald-100 text-emerald-800' : value === 'update' ? 'bg-blue-100 text-blue-800' : value === 'invalid' ? 'bg-red-100 text-red-800' : 'bg-slate-100 text-slate-600'; return <span className={`rounded px-2 py-1 text-xs ${style}`}>{value}</span>; }
function ValueCell({ value }: { value?: JsonValue }) { return <td className="break-words p-2 font-mono text-[11px]">{displayValue(value)}</td>; }
function displayValue(value?: JsonValue) { if (value === undefined) return '—'; if (value === null) return 'null'; if (typeof value === 'string') return value || '""'; return JSON.stringify(value); }
function humanEntity(value: string) { const labels: Record<string, string> = { case: 'Case metadata', network: 'Networks / zones', asset: 'Assets / computers', network_interface: 'Network interfaces / NICs', clock_profile: 'Server clock profiles', firewall: 'Firewalls', network_connection: 'Network connections', timeline_event: 'Expert timeline', ioc: 'IOCs', note: 'Expert notes' }; return labels[value] ?? value.replaceAll('_', ' '); }
