import { useMemo, useState } from 'react';
import { Boxes, FileUp, Loader2, ShieldCheck, X } from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { invoke, pickTextFile } from '@/lib/api';
import {
  buildVmInventoryImport,
  parseVmInventory,
  platformLabel,
  type ParsedVmInventory,
  type VmImportInventory,
  type VmInventoryPlatform,
} from '@/lib/vm-inventory';
import type {
  ApiResponse,
  PartialApplySummary,
  PartialImportPreview,
  PartialSelectionValidation,
} from '@/types';

interface Props {
  inventory: VmImportInventory;
  onApplied: () => Promise<void>;
  onClose: () => void;
}
const EXPORT_GUIDANCE: Record<VmInventoryPlatform, { native: string; csv: string }> = {
  esxi: {
    native: 'vim-cmd vmsvc/getallvms',
    csv: 'Get-VM | Select-Object Id,Name,PowerState,NumCpu,MemoryGB,@{N="GuestOS";E={$_.Guest.OSFullName}},@{N="VMHost";E={$_.VMHost.Name}},Version,@{N="IPAddress";E={$_.Guest.IPAddress -join ";"}},@{N="MacAddress";E={(Get-NetworkAdapter -VM $_).MacAddress -join ";"}} | Export-Csv -NoTypeInformation vms.csv',
  },
  proxmox: {
    native: 'pvesh get /cluster/resources --type vm --output-format json > vms.json',
    csv: 'CSV columns: vmid,name,node,status,type,maxcpu,maxmem,maxdisk,ipAddress,macAddress',
  },
  hyperv: {
    native: 'Get-VM | ConvertTo-Json -Depth 3 | Set-Content vms.json',
    csv: 'Get-VM | Select-Object VMId,Name,State,ComputerName,ProcessorCount,MemoryAssigned,MemoryStartup,Generation,Version,ConfigurationLocation,@{N="IPAddress";E={(Get-VMNetworkAdapter -VM $_).IPAddresses -join ";"}},@{N="MacAddress";E={(Get-VMNetworkAdapter -VM $_).MacAddress -join ";"}} | Export-Csv -NoTypeInformation vms.csv',
  },
};

export default function VmInventoryImportPanel({ inventory, onApplied, onClose }: Props) {
  const [platform, setPlatform] = useState<VmInventoryPlatform>('esxi');
  const [inventoryScope, setInventoryScope] = useState('');
  const [sourceFile, setSourceFile] = useState('');
  const [text, setText] = useState('');
  const [parsed, setParsed] = useState<ParsedVmInventory | null>(null);
  const [preview, setPreview] = useState<PartialImportPreview | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);

  const selectedChanges = useMemo(
    () => preview?.changes
      .filter((item) => item.valid && item.recommended_selected && ['create', 'update'].includes(item.operation))
      .map((item) => item.id) ?? [],
    [preview],
  );

  const clearPreview = async () => {
    if (preview) {
      await invoke<ApiResponse<boolean>>('discard_pending_partial_import', {
        previewId: preview.preview_id,
      }).catch(() => undefined);
    }
    setPreview(null);
  };

  const selectFile = async () => {
    try {
      const file = await pickTextFile('.csv,.json,.txt');
      if (!file) return;
      await clearPreview();
      setSourceFile(file.name);
      setText(file.text);
      setParsed(null);
    } catch (reason) {
      toast.error(String(reason));
    }
  };

  const prepare = async () => {
    setBusy(true);
    try {
      await clearPreview();
      const value = parseVmInventory(platform, text, {
        sourceFile: sourceFile || undefined,
        inventoryScope: inventoryScope || undefined,
      });
      const built = buildVmInventoryImport(value, inventory);
      const response = await invoke<ApiResponse<PartialImportPreview>>('preview_partial_import_text', {
        jsonData: built.document,
      });
      if (!response.success || !response.data) {
        throw new Error(response.error || 'Could not prepare the VM inventory import');
      }
      setParsed(value);
      setWarnings(built.warnings);
      setPreview(response.data);
      if (response.data.changes.some((item) => !item.valid)) {
        toast.warning('The preview contains invalid records. Review them before applying.');
      }
    } catch (reason) {
      setParsed(null);
      toast.error(String(reason));
    } finally {
      setBusy(false);
    }
  };

  const apply = async () => {
    if (!preview || selectedChanges.length === 0) return;
    if (!confirm(`Apply ${selectedChanges.length} reviewed VM inventory record(s) in one transaction?`)) return;
    setBusy(true);
    try {
      const validation = await invoke<ApiResponse<PartialSelectionValidation>>('validate_pending_partial_import', {
        previewId: preview.preview_id,
        selectedChangeIds: selectedChanges,
      });
      if (!validation.success || !validation.data?.valid) {
        throw new Error(validation.data?.errors.join('; ') || validation.error || 'The import selection is no longer valid');
      }
      const response = await invoke<ApiResponse<PartialApplySummary>>('apply_pending_partial_import', {
        previewId: preview.preview_id,
        selectedChangeIds: selectedChanges,
      });
      if (!response.success || !response.data) throw new Error(response.error || 'Could not apply the VM inventory');
      toast.success(`Imported ${response.data.created} new and ${response.data.updated} updated VM inventory records`);
      setPreview(null);
      await onApplied();
    } catch (reason) {
      toast.error(String(reason));
    } finally {
      setBusy(false);
    }
  };

  const close = () => {
    void clearPreview();
    onClose();
  };
  const guidance = EXPORT_GUIDANCE[platform];

  return (
    <Card className="border-violet-200 bg-violet-50/30">
      <CardHeader className="flex flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2 text-base"><Boxes size={18} />Import VM inventory</CardTitle>
          <p className="mt-1 text-xs text-slate-500">ESXi/vSphere, Proxmox VE, and Hyper-V inventories become reviewed, audited assets and inventory-managed NICs.</p>
        </div>
        <Button size="sm" variant="ghost" aria-label="Close VM inventory importer" onClick={close}><X size={16} /></Button>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 md:grid-cols-[220px_minmax(260px,1fr)_auto]">
          <Field label="Virtualization platform">
            <Select value={platform} onValueChange={(value: VmInventoryPlatform) => {
              setPlatform(value);
              setParsed(null);
              void clearPreview();
            }}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="esxi">VMware ESXi / vSphere</SelectItem>
                <SelectItem value="proxmox">Proxmox VE</SelectItem>
                <SelectItem value="hyperv">Microsoft Hyper-V</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Field label="Inventory scope (recommended)">
            <Input
              value={inventoryScope}
              onChange={(event) => {
                setInventoryScope(event.target.value);
                setParsed(null);
                void clearPreview();
              }}
              placeholder="ESXi host, Proxmox cluster, or Hyper-V host"
            />
          </Field>
          <div className="flex items-end"><Button variant="outline" onClick={() => void selectFile()} disabled={busy}><FileUp size={16} />Select file</Button></div>
        </div>

        <div className="space-y-2 rounded-md border bg-white p-3 text-xs">
          <div><span className="font-medium">Native / JSON:</span> <code className="break-all text-slate-600">{guidance.native}</code></div>
          <div><span className="font-medium">Rich CSV:</span> <code className="break-all text-slate-600">{guidance.csv}</code></div>
          <div className="text-slate-500">The parser auto-detects JSON, CSV, or native table text. Scope participates in duplicate-safe identity matching.</div>
        </div>

        <div className="flex flex-wrap gap-2 text-xs">
          <Badge variant="outline">{platformLabel(platform)}</Badge>
          <Badge variant="outline">CSV / JSON / native text</Badge>
          {sourceFile && <span className="self-center text-slate-500">Selected: <span className="font-medium text-slate-700">{sourceFile}</span></span>}
        </div>
        <Textarea
          rows={10}
          className="font-mono text-xs"
          value={text}
          onChange={(event) => {
            setText(event.target.value);
            setParsed(null);
            void clearPreview();
          }}
          placeholder={`Paste ${platformLabel(platform)} VM inventory here…`}
        />
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => void prepare()} disabled={busy || !text.trim()} className="bg-violet-600 hover:bg-violet-700">
            {busy ? <Loader2 size={16} className="animate-spin" /> : <ShieldCheck size={16} />}Parse and review
          </Button>
          {preview && <Button onClick={() => void apply()} disabled={busy || selectedChanges.length === 0}>
            Apply {selectedChanges.length} reviewed record{selectedChanges.length === 1 ? '' : 's'}
          </Button>}
        </div>

        {parsed && (
          <div className="grid gap-2 sm:grid-cols-5">
            <Summary label="Platform" value={platformLabel(parsed.platform)} />
            <Summary label="Format" value={parsed.sourceFormat} />
            <Summary label="Guests" value={parsed.records.length} />
            <Summary label="With IPs" value={parsed.records.filter((item) => item.ipAddresses.length).length} />
            <Summary label="Containers" value={parsed.records.filter((item) => item.kind === 'container').length} />
          </div>
        )}

        {warnings.length > 0 && (
          <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-xs text-amber-900">
            <div className="mb-1 font-medium">Import review points</div>
            <ul className="list-disc space-y-1 pl-5">{warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul>
          </div>
        )}

        {preview && (
          <div className="space-y-2 rounded-md border bg-white p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-sm font-medium"><Boxes size={16} />Transactional preview</div>
              <div className="flex gap-2 text-xs">
                <Badge variant="outline">{preview.changes.filter((item) => item.operation === 'create').length} create</Badge>
                <Badge variant="outline">{preview.changes.filter((item) => item.operation === 'update').length} update</Badge>
                <Badge variant={preview.changes.some((item) => !item.valid) ? 'destructive' : 'outline'}>
                  {preview.changes.filter((item) => !item.valid).length} invalid
                </Badge>
              </div>
            </div>
            <div className="max-h-56 overflow-auto">
              {preview.changes.map((item) => (
                <div key={item.id} className="grid grid-cols-[90px_120px_1fr] gap-2 border-t py-1.5 text-xs first:border-t-0">
                  <Badge variant={item.valid ? 'outline' : 'destructive'} className="justify-center">{item.operation}</Badge>
                  <span className="text-slate-500">{item.entity_type.replaceAll('_', ' ')}</span>
                  <span className={item.valid ? 'text-slate-800' : 'text-red-700'}>{item.valid ? item.title : item.error}</span>
                </div>
              ))}
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

function Summary({ label, value }: { label: string; value: string | number }) {
  return <div className="rounded-md border bg-white p-2"><div className="text-[10px] uppercase text-slate-400">{label}</div><div className="truncate text-sm font-medium capitalize">{value}</div></div>;
}
