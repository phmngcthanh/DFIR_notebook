/**
 * Capture inbox: everything recorded with Capture (Alt+C), word for word,
 * until someone sorts it out. Processing proposes the assets and indicators
 * the text mentions and applies only what the investigator ticks, through
 * the same reviewed, attributed import as every other bulk entry. The
 * original text always stays as captured.
 */
import { useCallback, useEffect, useMemo, useState } from 'react';
import { v4 as uuidv4 } from 'uuid';
import { CheckCircle2, FileText, Inbox, Loader2, RotateCcw, Search, Sparkles, Trash2, XCircle } from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { invoke } from '@/lib/api';
import {
  captureAssetChanges, suggestFromCapture, type AssetSuggestion, type IocSuggestion, type PlannedAsset,
} from '@/lib/capture-suggest';
import { useDraft } from '@/lib/drafts';
import { IOC_TYPES, iocKey, iocTypeLabel, type IocType } from '@/lib/ioc-detect';
import {
  applicableChangeIds, applyReviewed, discardPreview, firstLine, partialDocument, previewDocument, type PartialChange,
} from '@/lib/reviewed-import';
import type {
  ApiResponse, Asset, Capture, CaptureLink, CaptureStatus, Case, Ioc, Network, NetworkInterface, Note, PartialImportPreview,
} from '@/types';

interface Props {
  refreshTrigger: number;
  onCapture: () => void;
}

type Filter = CaptureStatus | 'all';

const FILTERS: { value: Filter; label: string }[] = [
  { value: 'open', label: 'Open' },
  { value: 'processed', label: 'Processed' },
  { value: 'dismissed', label: 'Dismissed' },
  { value: 'all', label: 'All' },
];

export default function CaptureInbox({ refreshTrigger, onCapture }: Props) {
  const [captures, setCaptures] = useState<Capture[]>([]);
  const [filter, setFilter] = useDraft<Filter>('inbox.filter', 'open');
  const [search, setSearch] = useDraft('inbox.search', '');
  const [focusId, setFocusId] = useDraft<string | null>('inbox.focusId', null);
  const [processingId, setProcessingId] = useDraft<string | null>('inbox.processingId', null);

  const load = useCallback(async () => {
    try {
      const response = await invoke<ApiResponse<Capture[]>>('list_captures');
      if (!response.success) throw new Error(response.error || 'Could not load captures');
      setCaptures(response.data ?? []);
    } catch (reason) { toast.error(String(reason)); }
  }, []);
  useEffect(() => { void load(); }, [load, refreshTrigger]);

  useEffect(() => {
    if (!focusId) return;
    document.getElementById(`capture-${focusId}`)?.scrollIntoView({ block: 'center' });
  }, [focusId, captures]);

  const counts = useMemo(() => ({
    open: captures.filter((item) => item.status === 'open').length,
    processed: captures.filter((item) => item.status === 'processed').length,
    dismissed: captures.filter((item) => item.status === 'dismissed').length,
    all: captures.length,
  }), [captures]);
  const visible = useMemo(() => {
    const term = search.trim().toLowerCase();
    return captures.filter((item) => (filter === 'all' || item.status === filter || item.id === focusId)
      && (!term || [item.content, item.source, item.captured_by, item.team ?? '', item.resolution].some((value) => value.toLowerCase().includes(term))));
  }, [captures, filter, search, focusId]);

  const update = async (capture: Capture, patch: Partial<Pick<Capture, 'status' | 'links' | 'resolution'>>) => {
    const next = { ...capture, ...patch };
    const response = await invoke<ApiResponse<Capture>>('update_existing_capture', {
      id: capture.id, content: next.content, source: next.source, status: next.status, links: next.links, resolution: next.resolution,
    });
    if (!response.success) throw new Error(response.error || 'Could not update the capture');
    await load();
  };
  const run = (action: () => Promise<void>) => { void action().catch((reason) => toast.error(String(reason))); };

  const saveAsNote = (capture: Capture) => run(async () => {
    const meta = [capture.source && `Source: ${capture.source}`, `Captured by ${capture.captured_by}${capture.team ? ` (${capture.team})` : ''} on ${localTime(capture.created_at)}`].filter(Boolean).join('\n');
    const response = await invoke<ApiResponse<Note>>('create_new_note', { title: firstLine(capture.content) || 'Captured note', content: `${capture.content}\n\n---\n${meta}` });
    if (!response.success || !response.data) throw new Error(response.error || 'Could not create the note');
    await update(capture, { status: 'processed', links: mergeLinks(capture.links, [{ entity_type: 'note', entity_id: response.data.id, title: response.data.title }]) });
    if (processingId === capture.id) setProcessingId(null);
    toast.success('Saved as a note and marked processed');
  });
  const setStatus = (capture: Capture, status: CaptureStatus) => run(async () => {
    await update(capture, { status });
    if (processingId === capture.id) setProcessingId(null);
  });
  const remove = (capture: Capture) => run(async () => {
    if (!confirm('Delete this capture? The deletion stays visible in case history.')) return;
    const response = await invoke<ApiResponse<boolean>>('remove_capture', { id: capture.id });
    if (!response.success) throw new Error(response.error || 'Could not delete the capture');
    if (focusId === capture.id) setFocusId(null);
    await load();
  });

  return (
    <div className="space-y-4 p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-2xl font-bold text-slate-800"><Inbox className="text-cyan-600" />Capture inbox</h2>
          <p className="max-w-3xl text-sm text-slate-500">Everything captured with Alt+C lands here word for word. Process it into assets and indicators, keep it as a note, or dismiss it.</p>
        </div>
        <Button onClick={onCapture} className="bg-cyan-600 hover:bg-cyan-700"><Inbox size={16} className="mr-2" />Capture <span className="ml-2 text-xs opacity-80">Alt+C</span></Button>
      </div>

      <Card><CardContent className="flex flex-wrap items-center gap-2 p-3">
        {FILTERS.map((item) => (
          <Button key={item.value} size="sm" variant={filter === item.value ? 'default' : 'outline'} onClick={() => { setFilter(item.value); setFocusId(null); }}>
            {item.label} <span className="ml-1 opacity-70">{counts[item.value]}</span>
          </Button>
        ))}
        <div className="relative ml-auto min-w-64 flex-1 sm:max-w-sm">
          <Search size={15} className="absolute left-3 top-2.5 text-slate-400" />
          <Input className="pl-9" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search captured text, source, or expert…" />
        </div>
      </CardContent></Card>

      {visible.length === 0 ? (
        <div className="rounded-md border border-dashed bg-white p-10 text-center text-sm text-slate-500">
          {captures.length === 0 ? 'Nothing captured yet. Press Alt+C anywhere to record what you just learned.' : 'No captures match this view.'}
        </div>
      ) : visible.map((capture) => (
        <Card key={capture.id} id={`capture-${capture.id}`} className={focusId === capture.id ? 'ring-2 ring-cyan-500' : ''}>
          <CardContent className="space-y-2 p-4">
            <div className="flex items-start justify-between gap-3">
              <p className="min-w-0 flex-1 whitespace-pre-wrap break-words text-sm text-slate-800">{capture.content}</p>
              <StatusBadge status={capture.status} />
            </div>
            <p className="text-xs text-slate-500">
              {capture.source ? <><span className="font-medium text-slate-600">{capture.source}</span> · </> : null}
              captured by {capture.captured_by || 'unknown'}{capture.team ? ` (${capture.team})` : ''} · {localTime(capture.created_at)}
            </p>
            {capture.links.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {capture.links.map((link) => <Badge key={`${link.entity_type}:${link.entity_id}`} variant="outline" className="font-normal">{humanEntity(link.entity_type)}: {link.title || link.entity_id.slice(0, 8)}</Badge>)}
              </div>
            )}
            {capture.resolution && <p className="text-xs text-slate-600">Resolution: {capture.resolution}</p>}
            <div className="flex flex-wrap gap-2 pt-1">
              {capture.status === 'open' && (
                // Stays in place (disabled) while processing is open: if it vanished, the
                // next button would slide under the cursor and a double-click would hit it.
                <Button size="sm" onClick={() => setProcessingId(capture.id)} disabled={processingId === capture.id} className="bg-cyan-600 hover:bg-cyan-700"><Sparkles size={14} className="mr-1" />Process</Button>
              )}
              <Button size="sm" variant="outline" onClick={() => saveAsNote(capture)}><FileText size={14} className="mr-1" />Save as note</Button>
              {capture.status === 'open' ? (
                <>
                  <Button size="sm" variant="outline" onClick={() => setStatus(capture, 'processed')}><CheckCircle2 size={14} className="mr-1" />Mark processed</Button>
                  <Button size="sm" variant="outline" onClick={() => setStatus(capture, 'dismissed')}><XCircle size={14} className="mr-1" />Dismiss</Button>
                </>
              ) : (
                <Button size="sm" variant="outline" onClick={() => setStatus(capture, 'open')}><RotateCcw size={14} className="mr-1" />Reopen</Button>
              )}
              <Button size="sm" variant="ghost" onClick={() => remove(capture)} aria-label="Delete capture"><Trash2 size={14} className="text-red-500" /></Button>
            </div>
            {processingId === capture.id && (
              <ProcessPanel
                capture={capture}
                onCancel={() => setProcessingId(null)}
                onApplied={async (links) => {
                  await update(capture, { status: 'processed', links: mergeLinks(capture.links, links) });
                  setProcessingId(null);
                }}
              />
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

interface CaseInventory {
  caseId: string;
  assets: Asset[];
  networks: Network[];
  networkInterfaces: NetworkInterface[];
}

function ProcessPanel({ capture, onApplied, onCancel }: {
  capture: Capture;
  onApplied: (links: CaptureLink[]) => Promise<void>;
  onCancel: () => void;
}) {
  const [inventory, setInventory] = useState<CaseInventory | null>(null);
  const [assets, setAssets] = useState<AssetSuggestion[]>([]);
  const [iocs, setIocs] = useState<IocSuggestion[]>([]);
  const [preview, setPreview] = useState<PartialImportPreview | null>(null);
  const [planned, setPlanned] = useState<PlannedAsset[]>([]);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const [caseResponse, assetResponse, networkResponse, interfaceResponse, iocResponse] = await Promise.all([
          invoke<ApiResponse<Case | null>>('get_current_case_info'),
          invoke<ApiResponse<Asset[]>>('list_assets'),
          invoke<ApiResponse<Network[]>>('list_networks'),
          invoke<ApiResponse<NetworkInterface[]>>('list_network_interfaces', { assetId: null }),
          invoke<ApiResponse<Ioc[]>>('list_iocs'),
        ]);
        for (const response of [caseResponse, assetResponse, networkResponse, interfaceResponse, iocResponse]) {
          if (!response.success) throw new Error(response.error || 'Could not load the case');
        }
        if (cancelled || !caseResponse.data) return;
        const caseAssets = assetResponse.data ?? [];
        setInventory({ caseId: caseResponse.data.id, assets: caseAssets, networks: networkResponse.data ?? [], networkInterfaces: interfaceResponse.data ?? [] });
        const suggestions = suggestFromCapture(capture.content, {
          existingAssetNames: caseAssets.map((asset) => asset.name),
          existingIocKeys: (iocResponse.data ?? []).map((ioc) => iocKey(ioc.ioc_type, ioc.value)),
        });
        setAssets(suggestions.assets);
        setIocs(suggestions.iocs);
      } catch (reason) {
        if (!cancelled) toast.error(String(reason));
      }
    })();
    return () => { cancelled = true; };
  }, [capture.content]);

  const resetPreview = () => {
    if (preview) void discardPreview(preview.preview_id);
    setPreview(null);
  };
  const selectedCount = assets.filter((item) => item.selected && item.name.trim()).length + iocs.filter((item) => item.selected && item.value.trim()).length;

  const review = async () => {
    if (!inventory) return;
    setBusy(true);
    try {
      resetPreview();
      const plan = captureAssetChanges(assets.filter((item) => item.selected && item.name.trim()), inventory);
      const changes: PartialChange[] = [...plan.changes];
      const description = `From capture: ${firstLine(capture.content, 120)}${capture.source ? ` (source: ${capture.source})` : ''}`;
      iocs.filter((item) => item.selected && item.value.trim()).forEach((item, index) => {
        changes.push({
          change_id: `capture-ioc-${index}`,
          entity_type: 'ioc',
          operation: 'upsert',
          target_id: uuidv4(),
          values: { ioc_type: item.type, value: item.value.trim(), description, threat_level: 'medium' },
        });
      });
      if (!changes.length) {
        throw new Error(plan.planned.length
          ? 'Everything ticked is already in the case. Mark the capture processed instead.'
          : 'Tick at least one asset or indicator to add');
      }
      const result = await previewDocument(partialDocument(inventory.caseId, `Capture: ${firstLine(capture.content, 60)}`, changes));
      setWarnings(plan.warnings);
      setPlanned(plan.planned);
      setPreview(result);
    } catch (reason) {
      toast.error(String(reason));
    } finally {
      setBusy(false);
    }
  };

  const apply = async () => {
    if (!preview) return;
    setBusy(true);
    try {
      const summary = await applyReviewed(preview);
      const applied = new Set(applicableChangeIds(preview));
      // Assets already in the case are linked as the capture's subject even when
      // nothing about them changed; new ones only once they exist.
      const links: CaptureLink[] = [
        ...planned
          .filter((item) => item.existing || applied.has(item.changeIds[0]))
          .map((item) => ({ entity_type: 'asset', entity_id: item.assetId, title: item.name })),
        ...preview.changes
          .filter((change) => applied.has(change.id) && change.entity_type === 'ioc')
          .map((change) => ({ entity_type: 'ioc', entity_id: change.entity_id, title: change.title })),
      ];
      setPreview(null);
      await onApplied(links);
      toast.success(`Added ${summary.created} and updated ${summary.updated} record${summary.created + summary.updated === 1 ? '' : 's'}; capture marked processed`);
    } catch (reason) {
      toast.error(String(reason));
    } finally {
      setBusy(false);
    }
  };

  if (!inventory) {
    return <div className="flex items-center gap-2 rounded-md border bg-slate-50 p-3 text-xs text-slate-500"><Loader2 size={14} className="animate-spin" />Reading the capture…</div>;
  }

  return (
    <div className="space-y-3 rounded-md border border-cyan-200 bg-cyan-50/40 p-3">
      {assets.length === 0 && iocs.length === 0 && (
        <p className="text-sm text-slate-600">No hostnames, addresses, or indicators were recognized. Save it as a note or mark it processed.</p>
      )}
      {assets.length > 0 && (
        <div className="space-y-1">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Assets</p>
          {assets.map((item, index) => (
            <div key={item.key} className="grid grid-cols-[auto_1fr_1fr_auto] items-center gap-2">
              <input type="checkbox" aria-label={`Add asset ${item.name}`} checked={item.selected} onChange={(event) => { resetPreview(); setAssets((rows) => rows.map((row, at) => at === index ? { ...row, selected: event.target.checked } : row)); }} />
              <Input value={item.name} aria-label="Asset name" onChange={(event) => { resetPreview(); setAssets((rows) => rows.map((row, at) => at === index ? { ...row, name: event.target.value } : row)); }} />
              <Input value={item.ipAddress} aria-label="Asset IP" placeholder="IP (optional)" onChange={(event) => { resetPreview(); setAssets((rows) => rows.map((row, at) => at === index ? { ...row, ipAddress: event.target.value } : row)); }} />
              <span className="text-xs text-slate-500">{item.existing ? 'already in the case' : item.reason}</span>
            </div>
          ))}
        </div>
      )}
      {iocs.length > 0 && (
        <div className="space-y-1">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Indicators</p>
          {iocs.map((item, index) => (
            <div key={item.key} className="grid grid-cols-[auto_150px_1fr_auto] items-center gap-2">
              <input type="checkbox" aria-label={`Add indicator ${item.value}`} checked={item.selected} onChange={(event) => { resetPreview(); setIocs((rows) => rows.map((row, at) => at === index ? { ...row, selected: event.target.checked } : row)); }} />
              <Select value={item.type} onValueChange={(type: IocType) => { resetPreview(); setIocs((rows) => rows.map((row, at) => at === index ? { ...row, type } : row)); }}>
                <SelectTrigger aria-label="Indicator type"><SelectValue /></SelectTrigger>
                <SelectContent>{IOC_TYPES.map((type) => <SelectItem key={type} value={type}>{iocTypeLabel(type)}</SelectItem>)}</SelectContent>
              </Select>
              <Input className="font-mono text-xs" value={item.value} aria-label="Indicator value" onChange={(event) => { resetPreview(); setIocs((rows) => rows.map((row, at) => at === index ? { ...row, value: event.target.value } : row)); }} />
              <span className="text-xs text-slate-500">{item.existing ? 'already recorded' : ''}</span>
            </div>
          ))}
        </div>
      )}
      {warnings.length > 0 && <ul className="list-disc space-y-0.5 pl-5 text-xs text-amber-800">{warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul>}
      {preview && <PreviewSummary preview={preview} planned={planned} />}
      <div className="flex flex-wrap gap-2">
        {preview ? (
          <>
            <Button size="sm" onClick={() => void apply()} disabled={busy || applicableChangeIds(preview).length === 0} className="bg-cyan-600 hover:bg-cyan-700">{busy && <Loader2 size={14} className="mr-1 animate-spin" />}Apply and mark processed</Button>
            <Button size="sm" variant="outline" onClick={resetPreview} disabled={busy}>Back</Button>
          </>
        ) : (
          <Button size="sm" onClick={() => void review()} disabled={busy || selectedCount === 0}>{busy && <Loader2 size={14} className="mr-1 animate-spin" />}Review {selectedCount} selected</Button>
        )}
        <Button size="sm" variant="ghost" onClick={() => { resetPreview(); onCancel(); }} disabled={busy}>Cancel</Button>
      </div>
    </div>
  );
}

/**
 * One line per record the investigator ticked. The primary interface that
 * carries a new asset's address is part of that asset's line; an address
 * added to an asset already in the case gets a line of its own.
 */
function PreviewSummary({ preview, planned }: { preview: PartialImportPreview; planned: PlannedAsset[] }) {
  const lines = preview.changes.flatMap((change) => {
    const owner = planned.find((item) => item.changeIds.includes(change.id));
    if (change.entity_type === 'network_interface') {
      if (!owner?.existing) return change.valid ? [] : [{ change, text: change.error ?? 'invalid' }];
      return [{ change, text: change.valid ? `add ${owner.ipAddress} to ${owner.name}` : change.error ?? 'invalid' }];
    }
    const address = change.entity_type === 'asset' && owner?.ipAddress ? ` (${owner.ipAddress})` : '';
    return [{ change, text: change.valid ? `${change.operation} ${humanEntity(change.entity_type)}: ${change.title}${address}` : change.error ?? 'invalid' }];
  });
  const invalid = lines.filter((line) => !line.change.valid).length;
  return (
    <div className="space-y-1 rounded border bg-white p-2 text-xs">
      <p className="font-medium text-slate-700">
        {lines.length - invalid} to apply
        {invalid > 0 && <span className="text-red-700"> · {invalid} invalid (skipped)</span>}
      </p>
      {lines.map(({ change, text }) => <p key={change.id} className={change.valid ? 'text-slate-600' : 'text-red-700'}>{text}</p>)}
    </div>
  );
}

/** Links already on the capture stay first; a record linked twice is kept once. */
function mergeLinks(current: CaptureLink[], added: CaptureLink[]): CaptureLink[] {
  const seen = new Set(current.map((link) => `${link.entity_type}:${link.entity_id}`));
  return [...current, ...added.filter((link) => {
    const key = `${link.entity_type}:${link.entity_id}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  })];
}

function StatusBadge({ status }: { status: CaptureStatus }) {
  const style = status === 'open' ? 'bg-amber-100 text-amber-800' : status === 'processed' ? 'bg-emerald-100 text-emerald-800' : 'bg-slate-100 text-slate-600';
  return <span className={`shrink-0 rounded px-2 py-0.5 text-xs ${style}`}>{status}</span>;
}
function humanEntity(value: string) { return value.replaceAll('_', ' '); }
function localTime(value: string) { const date = new Date(value); return Number.isNaN(date.valueOf()) ? value : date.toLocaleString(); }
