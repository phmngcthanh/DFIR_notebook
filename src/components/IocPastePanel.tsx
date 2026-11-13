/**
 * Paste indicators: a reverse-engineering report, a list from the log team,
 * or defanged values straight from a chat. Each value is refanged, typed,
 * and checked against the case; only the ticked new ones are added, in one
 * reviewed, attributed commit.
 */
import { useMemo, useState } from 'react';
import { v4 as uuidv4 } from 'uuid';
import { ClipboardPaste, Loader2, X } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { invoke } from '@/lib/api';
import { useDraft } from '@/lib/drafts';
import { extractIocCandidates, IOC_TYPES, iocKey, iocTypeLabel, normalizeIocValue, type IocType } from '@/lib/ioc-detect';
import { applyReviewed, discardPreview, partialDocument, previewDocument, type PartialChange } from '@/lib/reviewed-import';
import type { ApiResponse, Case, Ioc } from '@/types';

interface Props {
  iocs: Ioc[];
  onApplied: () => Promise<void> | void;
  onClose: () => void;
}

interface PasteRow {
  id: string;
  value: string;
  type: IocType | '';
  include: boolean;
  defanged: boolean;
}

const NO_TYPE = '__choose__';

export default function IocPastePanel({ iocs, onApplied, onClose }: Props) {
  const [text, setText] = useDraft('iocs.pasteText', '', { persist: true });
  const [threat, setThreat] = useDraft('iocs.pasteThreat', 'medium', { persist: true });
  const [description, setDescription] = useDraft('iocs.pasteDescription', '', { persist: true });
  const [rows, setRows] = useState<PasteRow[] | null>(null);
  const [errors, setErrors] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const recorded = useMemo(() => new Set(iocs.map((ioc) => iocKey(ioc.ioc_type, ioc.value))), [iocs]);

  const isRecorded = (row: PasteRow) => Boolean(row.type) && recorded.has(iocKey(row.type, row.value));
  const addable = (rows ?? []).filter((row) => row.include && row.type && row.value.trim() && !isRecorded(row));

  const detect = () => {
    const candidates = extractIocCandidates(text);
    if (!candidates.length) {
      toast.info('No values found. Put one indicator per line, or paste the report text.');
      setRows(null);
      return;
    }
    setErrors([]);
    setRows(candidates.map((candidate, index) => ({
      id: String(index),
      value: candidate.value,
      type: candidate.type ?? '',
      include: Boolean(candidate.type) && !recorded.has(iocKey(candidate.type ?? '', candidate.value)),
      defanged: candidate.defanged,
    })));
  };

  const updateRow = (id: string, patch: Partial<PasteRow>) => {
    setRows((current) => current?.map((row) => (row.id === id ? { ...row, ...patch } : row)) ?? null);
    setErrors([]);
  };

  const add = async () => {
    if (!addable.length) return;
    setBusy(true);
    try {
      const caseResponse = await invoke<ApiResponse<Case | null>>('get_current_case_info');
      if (!caseResponse.success || !caseResponse.data) throw new Error(caseResponse.error || 'No case is open');
      const seen = new Set<string>();
      const changes: PartialChange[] = [];
      for (const row of addable) {
        const type = row.type as IocType;
        const value = normalizeIocValue(type, row.value);
        const key = iocKey(type, value);
        if (seen.has(key)) continue;
        seen.add(key);
        changes.push({
          change_id: `paste-ioc-${changes.length}`,
          entity_type: 'ioc',
          operation: 'upsert',
          target_id: uuidv4(),
          values: { ioc_type: type, value, description: description.trim(), threat_level: threat },
        });
      }
      const preview = await previewDocument(partialDocument(caseResponse.data.id, 'Pasted indicator list', changes));
      const invalid = preview.changes.filter((change) => !change.valid);
      if (invalid.length) {
        await discardPreview(preview.preview_id);
        setErrors(invalid.map((change) => `${change.title}: ${change.error ?? 'invalid'}`));
        throw new Error(`${invalid.length} value${invalid.length === 1 ? ' is' : 's are'} not valid for the chosen type. Fix or untick them.`);
      }
      const summary = await applyReviewed(preview);
      toast.success(`Added ${summary.created} indicator${summary.created === 1 ? '' : 's'}`);
      setText('');
      setRows(null);
      await onApplied();
    } catch (reason) {
      toast.error(String(reason));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="border-cyan-200 bg-cyan-50/30">
      <CardHeader className="flex flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2 text-base"><ClipboardPaste size={18} />Paste indicators</CardTitle>
          <p className="mt-1 text-xs text-slate-500">Paste a list or a report, defanged or not (hxxp, [.]). Values are refanged, typed, and checked against the case; nothing is added until you confirm.</p>
        </div>
        <Button size="sm" variant="ghost" aria-label="Close indicator paste" onClick={onClose}><X size={16} /></Button>
      </CardHeader>
      <CardContent className="space-y-3">
        <Textarea
          rows={6}
          className="font-mono text-xs"
          aria-label="Indicators to paste"
          value={text}
          onChange={(event) => { setText(event.target.value); setRows(null); }}
          placeholder={'evil[.]example\n44d88612fea8a8f36de82e1278abb02f\nhxxps://cdn.bad[.]site/stage2.ps1\nC:\\Users\\Public\\svc.exe'}
        />
        <div className="grid gap-3 md:grid-cols-[160px_1fr_auto]">
          <div className="space-y-1">
            <Label>Threat level</Label>
            <Select value={threat} onValueChange={setThreat}>
              <SelectTrigger aria-label="Threat level for added indicators"><SelectValue /></SelectTrigger>
              <SelectContent>{['low', 'medium', 'high', 'critical'].map((level) => <SelectItem key={level} value={level}>{level}</SelectItem>)}</SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="ioc-paste-description">Description for every added indicator</Label>
            <Input id="ioc-paste-description" value={description} onChange={(event) => setDescription(event.target.value)} placeholder="e.g. Reverse team, sample A report" />
          </div>
          <div className="flex items-end"><Button variant="outline" onClick={detect} disabled={!text.trim() || busy}>Detect</Button></div>
        </div>
        {rows && (
          <div className="space-y-1 rounded-md border bg-white p-2">
            {rows.map((row) => (
              <div key={row.id} className="grid grid-cols-[auto_150px_1fr_130px] items-center gap-2">
                <input type="checkbox" aria-label={`Add ${row.value}`} checked={row.include} disabled={isRecorded(row)} onChange={(event) => updateRow(row.id, { include: event.target.checked })} />
                <Select value={row.type || NO_TYPE} onValueChange={(value) => updateRow(row.id, { type: value === NO_TYPE ? '' : value as IocType, include: value !== NO_TYPE })}>
                  <SelectTrigger aria-label={`Type of ${row.value}`}><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value={NO_TYPE}>Choose a type…</SelectItem>
                    {IOC_TYPES.map((type) => <SelectItem key={type} value={type}>{iocTypeLabel(type)}</SelectItem>)}
                  </SelectContent>
                </Select>
                <Input className="font-mono text-xs" aria-label="Indicator value" value={row.value} onChange={(event) => updateRow(row.id, { value: event.target.value })} />
                <span className="text-xs text-slate-500">{isRecorded(row) ? 'already recorded' : !row.type ? 'needs a type' : row.defanged ? 'new · refanged' : 'new'}</span>
              </div>
            ))}
          </div>
        )}
        {errors.length > 0 && <ul className="list-disc space-y-0.5 pl-5 text-xs text-red-700">{errors.map((error) => <li key={error}>{error}</li>)}</ul>}
        {rows && (
          <div className="flex justify-end">
            <Button onClick={() => void add()} disabled={busy || addable.length === 0} className="bg-cyan-600 hover:bg-cyan-700">
              {busy && <Loader2 size={15} className="mr-1 animate-spin" />}Add {addable.length} indicator{addable.length === 1 ? '' : 's'}
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
