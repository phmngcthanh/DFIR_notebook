/**
 * Paste what a responder pulled from the client network (arp -a, ipconfig
 * /all, ip addr, an nmap scan, a DHCP lease file) and turn it into assets.
 * Every host is a row to add, use to update the asset it matches, or skip;
 * nothing is written until the chosen rows have been previewed by the core
 * and confirmed, and then as one attributed commit.
 */
import { useMemo, useState } from 'react';
import { FileUp, Loader2, Radar, ShieldCheck, X } from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { pickTextFile } from '@/lib/api';
import { describeReasons } from '@/lib/asset-match';
import { buildDiscoveryImport, planDiscovery, type DiscoveryAction, type DiscoveryInventory, type DiscoveryRow } from '@/lib/discovery-import';
import { DISCOVERY_FORMATS, parseDiscovery, type DiscoveryFormat, type ParsedDiscovery } from '@/lib/discovery-parse';
import { useDraft } from '@/lib/drafts';
import { fromLocalInput } from '@/lib/environment';
import { applicableChangeIds, applyReviewed, discardPreview, previewDocument } from '@/lib/reviewed-import';
import type { PartialImportPreview } from '@/types';

interface Props {
  inventory: DiscoveryInventory;
  onApplied: () => Promise<void> | void;
  onClose: () => void;
}

const AUTO = 'auto';

export default function DiscoveryImportPanel({ inventory, onApplied, onClose }: Props) {
  const [text, setText] = useDraft('discovery.text', '', { persist: true });
  const [format, setFormat] = useDraft<DiscoveryFormat | typeof AUTO>('discovery.format', AUTO, { persist: true });
  const [hostName, setHostName] = useDraft('discovery.hostName', '', { persist: true });
  const [observed, setObserved] = useDraft('discovery.observed', '', { persist: true });
  const [sourceFile, setSourceFile] = useState('');
  const [parsed, setParsed] = useState<ParsedDiscovery | null>(null);
  const [rows, setRows] = useState<DiscoveryRow[]>([]);
  const [preview, setPreview] = useState<PartialImportPreview | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);

  const chosen = rows.filter((row) => row.action !== 'skip');
  const counts = useMemo(() => ({
    create: rows.filter((row) => row.action === 'create').length,
    update: rows.filter((row) => row.action === 'update').length,
  }), [rows]);

  const resetPreview = () => {
    if (preview) void discardPreview(preview.preview_id);
    setPreview(null);
  };
  const edit = (id: string, patch: Partial<DiscoveryRow>) => {
    resetPreview();
    setRows((current) => current.map((row) => (row.id === id ? { ...row, ...patch } : row)));
  };

  const selectFile = async () => {
    try {
      const file = await pickTextFile('.txt,.log,.csv,.leases,.lease');
      if (!file) return;
      resetPreview();
      setSourceFile(file.name);
      setText(file.text);
      setParsed(null);
      setRows([]);
    } catch (reason) {
      toast.error(String(reason));
    }
  };

  const read = () => {
    try {
      resetPreview();
      const value = parseDiscovery(text, { format: format === AUTO ? undefined : format, hostName });
      setParsed(value);
      setRows(planDiscovery(value, inventory));
      setWarnings(value.warnings);
    } catch (reason) {
      setParsed(null);
      setRows([]);
      toast.error(String(reason));
    }
  };

  const observedAt = () => fromLocalInput(observed) || new Date().toISOString();

  const review = async () => {
    if (!parsed) return;
    setBusy(true);
    try {
      resetPreview();
      const built = buildDiscoveryImport(rows, inventory, { observedAt: observedAt(), sourceLabel: `${parsed.label}${sourceFile ? `: ${sourceFile}` : ''}` });
      setWarnings([...parsed.warnings, ...built.warnings]);
      setPreview(await previewDocument(built.document));
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
      toast.success(`Recorded ${summary.created} new and ${summary.updated} updated record${summary.created + summary.updated === 1 ? '' : 's'} from ${parsed?.label ?? 'discovery'}`);
      setPreview(null);
      setParsed(null);
      setRows([]);
      setText('');
      setSourceFile('');
      await onApplied();
    } catch (reason) {
      toast.error(String(reason));
    } finally {
      setBusy(false);
    }
  };

  const close = () => {
    resetPreview();
    onClose();
  };
  const invalid = preview?.changes.filter((change) => !change.valid) ?? [];

  return (
    <Card className="border-sky-200 bg-sky-50/30">
      <CardHeader className="flex flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2 text-base"><Radar size={18} />Paste discovery output</CardTitle>
          <p className="mt-1 max-w-3xl text-xs text-slate-500">
            Paste an ARP table (<code>arp -a</code>, <code>ip neigh</code>), <code>ipconfig /all</code>, <code>ip addr</code> / <code>ifconfig</code>, an nmap scan, or a DHCP lease file.
            Hosts found become assets marked <em>discovered</em>, with the time you saw them. Hosts already in the case are matched by MAC address, name, or address and only gain what they lacked.
          </p>
        </div>
        <Button size="sm" variant="ghost" aria-label="Close discovery import" onClick={close}><X size={16} /></Button>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid gap-3 md:grid-cols-[210px_1fr_210px_auto]">
          <Field label="Format">
            <Select value={format} onValueChange={(value) => { setFormat(value as DiscoveryFormat | typeof AUTO); setParsed(null); setRows([]); resetPreview(); }}>
              <SelectTrigger aria-label="Discovery format"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value={AUTO}>Detect automatically</SelectItem>
                {DISCOVERY_FORMATS.map((item) => <SelectItem key={item.value} value={item.value}>{item.label}</SelectItem>)}
              </SelectContent>
            </Select>
          </Field>
          <Field label="Run on (name, for ip addr / ifconfig)">
            <Input value={hostName} onChange={(event) => { setHostName(event.target.value); setParsed(null); setRows([]); resetPreview(); }} placeholder="Host name; those commands do not print it" />
          </Field>
          <Field label="Observed at (default: now)">
            <Input type="datetime-local" value={observed} onChange={(event) => setObserved(event.target.value)} aria-label="Observed at" />
          </Field>
          <div className="flex items-end"><Button variant="outline" onClick={() => void selectFile()} disabled={busy}><FileUp size={16} className="mr-1" />Select file</Button></div>
        </div>
        <Textarea
          rows={9}
          className="font-mono text-xs"
          aria-label="Discovery output"
          value={text}
          onChange={(event) => { setText(event.target.value); setParsed(null); setRows([]); resetPreview(); }}
          placeholder={'Interface: 10.0.0.5 --- 0x4\n  Internet Address      Physical Address      Type\n  10.0.0.1              aa-bb-cc-dd-ee-01     dynamic\n  10.0.0.40             aa-bb-cc-dd-ee-02     dynamic'}
        />
        <div className="flex flex-wrap items-center gap-2">
          <Button onClick={read} disabled={busy || !text.trim()} className="bg-sky-600 hover:bg-sky-700"><ShieldCheck size={16} className="mr-1" />Read output</Button>
          {parsed && <Badge variant="outline">{parsed.label}</Badge>}
          {parsed && <span className="text-xs text-slate-500">{parsed.hosts.length} host{parsed.hosts.length === 1 ? '' : 's'}: {counts.create} to add, {counts.update} to update</span>}
        </div>

        {warnings.length > 0 && (
          <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-xs text-amber-900">
            <div className="mb-1 font-medium">Review points</div>
            <ul className="list-disc space-y-1 pl-5">{warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul>
          </div>
        )}

        {rows.length > 0 && (
          <div className="space-y-1 rounded-md border bg-white p-2">
            {rows.map((row) => (
              <div key={row.id} className="grid grid-cols-[150px_1fr_1.4fr] items-center gap-2 border-t py-1.5 text-xs first:border-t-0">
                <Select value={row.action} onValueChange={(value) => edit(row.id, { action: value as DiscoveryAction })}>
                  <SelectTrigger aria-label={`Action for ${row.name}`}><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="create">Add as new asset</SelectItem>
                    {row.match && <SelectItem value="update">{`Update ${row.match.asset.name}`}</SelectItem>}
                    <SelectItem value="skip">Skip</SelectItem>
                  </SelectContent>
                </Select>
                <div className="space-y-1">
                  {row.action === 'create'
                    ? <Input aria-label="New asset name" className="h-8 text-xs" value={row.name} onChange={(event) => edit(row.id, { name: event.target.value })} />
                    : <p className="font-medium text-slate-800">{row.action === 'update' ? row.match?.asset.name : row.name}</p>}
                  <p className="font-mono text-[11px] text-slate-500">{row.host.nics.map((nic) => [nic.ip, nic.mac].filter(Boolean).join(' · ')).join(' | ')}</p>
                </div>
                <div className="space-y-0.5 text-slate-500">
                  {row.host.reference && <p>Mentioned as the {row.host.reference}</p>}
                  {row.match
                    ? <p className={row.match.strength === 'strong' ? 'text-emerald-700' : 'text-amber-700'}>{row.match.strength === 'strong' ? 'Already in the case' : 'Possibly'}: {row.match.asset.name} ({describeReasons(row.match.reasons)}){row.match.macConflict ? '; the MAC address differs' : ''}</p>
                    : !row.host.reference && <p>Not in the case yet</p>}
                  {[row.host.os, row.host.vendor, row.host.ports?.length ? `${row.host.ports.length} open port${row.host.ports.length === 1 ? '' : 's'}` : '', row.host.note].filter(Boolean).length > 0 && (
                    <p>{[row.host.os, row.host.vendor, row.host.ports?.length ? `${row.host.ports.length} open port${row.host.ports.length === 1 ? '' : 's'}` : '', row.host.note].filter(Boolean).join(' · ')}</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        {rows.length > 0 && !preview && (
          <Button onClick={() => void review()} disabled={busy || chosen.length === 0}>
            {busy && <Loader2 size={15} className="mr-1 animate-spin" />}Review {chosen.length} host{chosen.length === 1 ? '' : 's'}
          </Button>
        )}

        {preview && (
          <div className="space-y-2 rounded-md border bg-white p-3 text-xs">
            <p className="font-medium text-slate-700">
              {preview.changes.filter((change) => change.operation === 'create').length} new · {preview.changes.filter((change) => change.operation === 'update').length} updated
              {invalid.length > 0 && <span className="text-red-700"> · {invalid.length} invalid (skipped)</span>}
            </p>
            <div className="max-h-48 overflow-auto">
              {preview.changes.filter((change) => change.entity_type === 'asset' || !change.valid).map((change) => (
                <p key={change.id} className={change.valid ? 'text-slate-600' : 'text-red-700'}>{change.valid ? `${change.operation} ${change.entity_type.replaceAll('_', ' ')}: ${change.title}` : `${change.title}: ${change.error ?? 'invalid'}`}</p>
              ))}
            </div>
            <div className="flex gap-2">
              <Button size="sm" onClick={() => void apply()} disabled={busy || applicableChangeIds(preview).length === 0} className="bg-sky-600 hover:bg-sky-700">
                {busy && <Loader2 size={14} className="mr-1 animate-spin" />}Apply {applicableChangeIds(preview).length} record{applicableChangeIds(preview).length === 1 ? '' : 's'}
              </Button>
              <Button size="sm" variant="outline" onClick={resetPreview} disabled={busy}>Back</Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return <div className="space-y-1"><Label>{label}</Label>{children}</div>;
}
