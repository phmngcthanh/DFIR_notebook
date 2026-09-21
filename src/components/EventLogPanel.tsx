import { useCallback, useEffect, useState } from 'react';
import { invoke, isDesktop, pickTextFile } from '@/lib/api';
import { useIsAndroid } from '@/hooks/use-platform';
import { ArrowUpFromLine, FileInput, LockKeyhole, Search, ScrollText, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Textarea } from '@/components/ui/textarea';
import type {
  ApiResponse, Asset, EventLogBatch, EventLogSearchOutcome, EventLogStoreStatus,
} from '@/types';

interface Props { refreshTrigger: number; onChanged?: () => void }

type ImportKind = 'syslog' | 'windows-json';

const KIND_LABELS: Record<string, string> = {
  syslog: 'Syslog / Unix',
  'windows-json': 'Windows event JSON',
  evtx: 'Windows EVTX',
};

/**
 * Raw event-log evidence lives in an encrypted sidecar next to the case file,
 * outside snapshots and merges. This panel imports offline copies (pasted
 * text, or .evtx through the native dialog on desktop), searches them, and
 * promotes the records that matter into attributed timeline events.
 */
export default function EventLogPanel({ refreshTrigger, onChanged }: Props) {
  const android = useIsAndroid();
  const [status, setStatus] = useState<EventLogStoreStatus | null>(null);
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);

  const [kind, setKind] = useState<ImportKind>('syslog');
  const [timezone, setTimezone] = useState('UTC');
  const [hostHint, setHostHint] = useState('');
  const [note, setNote] = useState('');
  const [text, setText] = useState('');

  const [batches, setBatches] = useState<EventLogBatch[]>([]);
  const [query, setQuery] = useState('');
  const [batchFilter, setBatchFilter] = useState('all');
  const [hostFilter, setHostFilter] = useState('');
  const [eventIdFilter, setEventIdFilter] = useState('');
  const [outcome, setOutcome] = useState<EventLogSearchOutcome>({ rows: [], total: 0 });
  const [selected, setSelected] = useState<number[]>([]);

  const [assets, setAssets] = useState<Asset[]>([]);
  const [assetId, setAssetId] = useState('none');
  const [severity, setSeverity] = useState('medium');
  const [eventType, setEventType] = useState('event_log');

  const refreshStatus = useCallback(async () => {
    try {
      const response = await invoke<ApiResponse<EventLogStoreStatus>>('get_event_log_store_status');
      if (!response.success) throw new Error(response.error || 'Could not read the event-log store status');
      setStatus(response.data ?? null);
    } catch (reason) { toast.error(String(reason)); }
  }, []);

  const loadBatches = useCallback(async () => {
    try {
      const response = await invoke<ApiResponse<EventLogBatch[]>>('list_event_log_batches');
      if (!response.success) throw new Error(response.error || 'Could not load event-log batches');
      setBatches(response.data ?? []);
    } catch (reason) { toast.error(String(reason)); }
  }, []);

  const loadAssets = useCallback(async () => {
    try {
      const response = await invoke<ApiResponse<Asset[]>>('list_assets');
      if (response.success) setAssets(response.data ?? []);
    } catch { /* the promote dropdown simply stays empty */ }
  }, []);

  useEffect(() => { void refreshStatus(); }, [refreshStatus, refreshTrigger]);
  useEffect(() => {
    if (status?.open) { void loadBatches(); void loadAssets(); }
    else { setBatches([]); setOutcome({ rows: [], total: 0 }); setSelected([]); }
  }, [status?.open, loadBatches, loadAssets, refreshTrigger]);

  const openStore = async () => {
    if (!password) { toast.error('Enter the case password to open the event-log store'); return; }
    setBusy(true);
    try {
      const response = await invoke<ApiResponse<unknown>>('open_event_log_store', { password });
      if (!response.success) throw new Error(response.error || 'Could not open the event-log store');
      setPassword('');
      toast.success('Event-log store opened');
      await refreshStatus();
    } catch (reason) { toast.error(String(reason)); }
    finally { setBusy(false); }
  };

  const runImport = async (command: string, args: Record<string, unknown>, label: string) => {
    setBusy(true);
    try {
      const response = await invoke<ApiResponse<{ batchId: string; imported: number; skipped: number }>>(command, args);
      if (!response.success || !response.data) throw new Error(response.error || 'Import failed');
      const { imported, skipped } = response.data;
      toast.success(`Imported ${imported} ${label} record${imported === 1 ? '' : 's'}${skipped ? ` (${skipped} skipped)` : ''}`);
      setText('');
      await loadBatches();
      await runSearch();
    } catch (reason) { toast.error(String(reason)); }
    finally { setBusy(false); }
  };

  const importPasted = () => {
    if (!text.trim()) { toast.error('Paste log text first'); return; }
    void runImport('import_event_log_text', {
      kind, text, timezone: timezone || 'UTC',
      hostHint: hostHint || null, note: note || null,
    }, KIND_LABELS[kind] ?? kind);
  };

  const importTextFile = async () => {
    const file = await pickTextFile('.log,.txt,.json');
    if (!file) return;
    setText(file.text);
    const inferred = file.name.toLowerCase().endsWith('.json') ? 'windows-json' : 'syslog';
    setKind(inferred);
    toast.info(`File loaded as ${KIND_LABELS[inferred]}. Review and press Import`);
  };

  // EVTX is binary: only the desktop dialog command can hand Rust a real
  // file path to parse.
  const importEvtxFile = () => void runImport('import_event_log_file', {
    timezone: timezone || 'UTC', hostHint: hostHint || null, note: note || null,
  }, 'EVTX');

  const deleteBatch = async (id: string) => {
    if (!confirm('Delete this event-log batch and its raw records? Promoted timeline events stay.')) return;
    try {
      const response = await invoke<ApiResponse<boolean>>('delete_event_log_batch', { batchId: id });
      if (!response.success) throw new Error(response.error || 'Could not delete the batch');
      toast.success('Batch deleted');
      await loadBatches();
      await runSearch();
    } catch (reason) { toast.error(String(reason)); }
  };

  const runSearch = useCallback(async () => {
    try {
      const response = await invoke<ApiResponse<EventLogSearchOutcome>>('search_event_log_records', {
        query: query || null,
        batchId: batchFilter === 'all' ? null : batchFilter,
        host: hostFilter || null,
        eventId: eventIdFilter || null,
        limit: 200,
      });
      if (!response.success) throw new Error(response.error || 'Search failed');
      setOutcome(response.data ?? { rows: [], total: 0 });
      setSelected([]);
    } catch (reason) { toast.error(String(reason)); }
  }, [query, batchFilter, hostFilter, eventIdFilter]);

  useEffect(() => {
    if (status?.open) { const timer = setTimeout(() => { void runSearch(); }, 250); return () => clearTimeout(timer); }
  }, [status?.open, runSearch]);

  const toggle = (id: number) =>
    setSelected((current) => current.includes(id) ? current.filter((value) => value !== id) : [...current, id]);
  const allVisibleSelected = outcome.rows.length > 0 && outcome.rows.every((row) => selected.includes(row.id));

  const promote = async () => {
    if (selected.length === 0) { toast.error('Select records to promote first'); return; }
    setBusy(true);
    try {
      const response = await invoke<ApiResponse<{ created: number }>>('promote_event_logs_to_timeline', {
        recordIds: selected,
        assetId: assetId === 'none' ? null : assetId,
        severity,
        eventType: eventType || 'event_log',
      });
      if (!response.success || !response.data) throw new Error(response.error || 'Promotion failed');
      toast.success(`Promoted ${response.data.created} record${response.data.created === 1 ? '' : 's'} to the timeline`);
      setSelected([]);
      onChanged?.();
    } catch (reason) { toast.error(String(reason)); }
    finally { setBusy(false); }
  };

  if (status && !status.open) {
    return <div className="space-y-4 p-6">
      <h2 className="flex items-center gap-2 text-2xl font-bold text-slate-800"><ScrollText className="text-cyan-600" />Event Logs</h2>
      <Card className="max-w-xl"><CardHeader><CardTitle className="flex items-center gap-2 text-sm"><LockKeyhole size={15} />Open the event-log evidence store</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-slate-500">
            Raw Windows and Unix event logs are kept in a second encrypted file
            (<span className="font-mono text-xs">{status.fileName ?? 'beside the case'}</span>) that shares the case
            password and stays out of snapshots and merges. Enter the case password to open or create it.
          </p>
          <div className="flex items-end gap-2">
            <div className="flex-1 space-y-1"><Label htmlFor="event-log-password">Case password</Label>
              <Input id="event-log-password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} onKeyDown={(event) => event.key === 'Enter' && void openStore()} placeholder="Case password" /></div>
            <Button onClick={() => void openStore()} disabled={busy} className="bg-cyan-600 hover:bg-cyan-700">Open store</Button>
          </div>
        </CardContent></Card>
    </div>;
  }

  return <div className="space-y-4 p-6">
    <div className="flex items-center justify-between">
      <div><h2 className="flex items-center gap-2 text-2xl font-bold text-slate-800"><ScrollText className="text-cyan-600" />Event Logs</h2>
        <p className="text-sm text-slate-500">Raw evidence sidecar — {status?.fileName}{status?.batches ? ` · ${status.batches.batchCount} batch${status.batches.batchCount === 1 ? '' : 'es'}, ${status.batches.recordCount} records` : ''}</p></div>
    </div>

    <Card><CardHeader><CardTitle className="text-sm">Import an offline copy</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-wrap gap-3">
          <div className="w-56 space-y-1"><Label>Format</Label>
            <Select value={kind} onValueChange={(value) => setKind(value as ImportKind)}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="syslog">Syslog / Unix (RFC 3164/5424)</SelectItem>
                <SelectItem value="windows-json">Windows event JSON (Get-WinEvent)</SelectItem>
              </SelectContent>
            </Select></div>
          <div className="w-56 space-y-1"><Label htmlFor="event-log-tz">Timezone for undated times</Label>
            <Input id="event-log-tz" value={timezone} onChange={(event) => setTimezone(event.target.value)} placeholder="UTC, +07:00, or Asia/Ho_Chi_Minh" /></div>
          <div className="w-48 space-y-1"><Label htmlFor="event-log-host">Host hint</Label>
            <Input id="event-log-host" value={hostHint} onChange={(event) => setHostHint(event.target.value)} placeholder="Optional" /></div>
          <div className="flex-1 space-y-1"><Label htmlFor="event-log-note">Note</Label>
            <Input id="event-log-note" value={note} onChange={(event) => setNote(event.target.value)} placeholder="Where this copy came from" /></div>
        </div>
        <Textarea rows={6} value={text} onChange={(event) => setText(event.target.value)} className="font-mono text-xs"
          placeholder={kind === 'syslog'
            ? 'Jul 19 14:25:30 fw-01 sshd[4321]: Accepted publickey for root…'
            : '[{"TimeCreated":"2026-07-19T09:00:01.5Z","Id":4624,"ProviderName":"Microsoft-Windows-Security-Auditing","LogName":"Security","Message":"…"}]'} />
        <div className="flex flex-wrap gap-2">
          <Button onClick={importPasted} disabled={busy} className="bg-cyan-600 hover:bg-cyan-700"><ArrowUpFromLine size={15} className="mr-1" />Import pasted text</Button>
          <Button variant="outline" onClick={() => void importTextFile()} disabled={busy}><FileInput size={15} className="mr-1" />Load text file</Button>
          {isDesktop && !android && <Button variant="outline" onClick={importEvtxFile} disabled={busy} title="Parse a .evtx file directly in the app"><FileInput size={15} className="mr-1" />Import EVTX file…</Button>}
        </div>
      </CardContent></Card>

    <Card><CardHeader><CardTitle className="text-sm">Imported batches</CardTitle></CardHeader>
      <CardContent className="p-0"><Table><TableHeader><TableRow>
        <TableHead>Kind</TableHead><TableHead>Source</TableHead><TableHead>Host</TableHead><TableHead>Records</TableHead><TableHead>Range (UTC)</TableHead><TableHead>Imported</TableHead><TableHead />
      </TableRow></TableHeader><TableBody>
        {batches.length === 0 ? <TableRow><TableCell colSpan={7} className="py-6 text-center text-slate-400">No batches imported yet.</TableCell></TableRow>
          : batches.map((batch) => <TableRow key={batch.id}>
            <TableCell className="text-xs">{KIND_LABELS[batch.kind] ?? batch.kind}</TableCell>
            <TableCell className="max-w-xs truncate text-xs">{batch.fileName || batch.note || '—'}</TableCell>
            <TableCell className="text-xs">{batch.host || '—'}</TableCell>
            <TableCell className="text-xs">{batch.recordCount}{batch.skippedCount ? <span className="text-slate-400"> (+{batch.skippedCount} skipped)</span> : null}</TableCell>
            <TableCell className="text-xs">{batch.firstTimeUtc ? `${shortTime(batch.firstTimeUtc)} → ${shortTime(batch.lastTimeUtc)}` : '—'}</TableCell>
            <TableCell className="text-xs">{shortTime(batch.importedAt)}</TableCell>
            <TableCell><Button variant="ghost" size="sm" onClick={() => void deleteBatch(batch.id)}><Trash2 size={14} className="text-red-500" /></Button></TableCell>
          </TableRow>)}
      </TableBody></Table></CardContent></Card>

    <Card><CardContent className="flex flex-wrap gap-3 p-3">
      <div className="relative min-w-56 flex-1"><Search size={15} className="absolute left-3 top-2.5 text-slate-400" />
        <Input className="pl-9" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search message, provider, host, or raw content…" /></div>
      <div className="w-52"><Select value={batchFilter} onValueChange={setBatchFilter}>
        <SelectTrigger><SelectValue /></SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All batches</SelectItem>
          {batches.map((batch) => <SelectItem key={batch.id} value={batch.id}>{batch.fileName || batch.id.slice(0, 8)}</SelectItem>)}
        </SelectContent></Select></div>
      <div className="w-40"><Input value={hostFilter} onChange={(event) => setHostFilter(event.target.value)} placeholder="Host" /></div>
      <div className="w-32"><Input value={eventIdFilter} onChange={(event) => setEventIdFilter(event.target.value)} placeholder="Event ID" /></div>
      <Button variant="outline" onClick={() => void runSearch()} disabled={busy}>Search</Button>
    </CardContent></Card>

    <Card><CardContent className="p-0"><Table><TableHeader><TableRow>
      <TableHead className="w-8"><input type="checkbox" checked={allVisibleSelected} onChange={(event) => setSelected(event.target.checked ? outcome.rows.map((row) => row.id) : [])} /></TableHead>
      <TableHead>Time (UTC)</TableHead><TableHead>Host</TableHead><TableHead>Source</TableHead><TableHead>ID</TableHead><TableHead>Level</TableHead><TableHead>Message</TableHead>
    </TableRow></TableHeader><TableBody>
      {outcome.rows.length === 0 ? <TableRow><TableCell colSpan={7} className="py-6 text-center text-slate-400">No matching records.</TableCell></TableRow>
        : outcome.rows.map((row) => <TableRow key={row.id} className={selected.includes(row.id) ? 'bg-cyan-50' : ''}>
          <TableCell><input type="checkbox" checked={selected.includes(row.id)} onChange={() => toggle(row.id)} /></TableCell>
          <TableCell className="whitespace-nowrap text-xs">{row.eventTimeUtc || '—'}</TableCell>
          <TableCell className="text-xs">{row.host || '—'}</TableCell>
          <TableCell className="max-w-40 truncate text-xs" title={[row.provider, row.channel].filter(Boolean).join(' / ')}>{row.provider || row.channel || '—'}</TableCell>
          <TableCell className="font-mono text-xs">{row.eventId || '—'}</TableCell>
          <TableCell className="text-xs">{row.level || '—'}</TableCell>
          <TableCell className="max-w-md truncate text-xs" title={row.message ?? undefined}>{row.message || '—'}</TableCell>
        </TableRow>)}
    </TableBody></Table>
      <div className="flex flex-wrap items-center gap-3 border-t p-3">
        <span className="text-xs text-slate-500">{outcome.total} record{outcome.total === 1 ? '' : 's'} · {selected.length} selected</span>
        <div className="ml-auto flex flex-wrap items-end gap-2">
          <div className="w-52 space-y-1"><Label className="text-xs">Link to asset</Label>
            <Select value={assetId} onValueChange={setAssetId}><SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="none">No asset link</SelectItem>
                {assets.map((asset) => <SelectItem key={asset.id} value={asset.id}>{asset.name}</SelectItem>)}
              </SelectContent></Select></div>
          <div className="w-32 space-y-1"><Label className="text-xs">Severity</Label>
            <Select value={severity} onValueChange={setSeverity}><SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>{['info', 'low', 'medium', 'high', 'critical'].map((value) => <SelectItem key={value} value={value}>{value}</SelectItem>)}</SelectContent></Select></div>
          <div className="w-36 space-y-1"><Label className="text-xs">Event type</Label>
            <Input value={eventType} onChange={(event) => setEventType(event.target.value)} /></div>
          <Button onClick={() => void promote()} disabled={busy || selected.length === 0} className="bg-cyan-600 hover:bg-cyan-700"><ArrowUpFromLine size={15} className="mr-1" />Promote to timeline</Button>
        </div>
      </div>
    </CardContent></Card>
  </div>;
}

function shortTime(value: string | null | undefined): string {
  if (!value) return '—';
  return value.replace('T', ' ').replace('Z', '').slice(0, 19);
}
