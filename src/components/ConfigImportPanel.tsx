import { useMemo, useState } from 'react';
import { FileCode2, FileUp, Loader2, Network, ShieldCheck, X } from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { buildConfigImport, type ConfigImportInventory } from '@/lib/config-import';
import { invoke, pickTextFile } from '@/lib/api';
import {
  CONFIG_PROFILES,
  type ConfigProfile,
  parseDeviceConfig,
  type ParsedDeviceConfig,
} from '@/lib/network-config';
import type {
  ApiResponse,
  PartialApplySummary,
  PartialImportPreview,
  PartialSelectionValidation,
} from '@/types';

interface Props {
  inventory: ConfigImportInventory;
  onApplied: () => Promise<void>;
  onClose: () => void;
}

export default function ConfigImportPanel({ inventory, onApplied, onClose }: Props) {
  const [profile, setProfile] = useState<ConfigProfile>('palo_alto_firewall');
  const [roleOverride, setRoleOverride] = useState<'auto' | 'router' | 'switch'>('auto');
  const [deviceName, setDeviceName] = useState('');
  const [sourceFile, setSourceFile] = useState('');
  const [text, setText] = useState('');
  const [parsed, setParsed] = useState<ParsedDeviceConfig | null>(null);
  const [preview, setPreview] = useState<PartialImportPreview | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);

  const selectedChanges = useMemo(
    () => preview?.changes
      .filter((item) => item.valid && item.recommended_selected && ['create', 'update'].includes(item.operation))
      .map((item) => item.id) ?? [],
    [preview],
  );
  const profileInfo = CONFIG_PROFILES.find((item) => item.value === profile);

  const clearPreview = async () => {
    if (preview) await invoke<ApiResponse<boolean>>('discard_pending_partial_import', { previewId: preview.preview_id }).catch(() => undefined);
    setPreview(null);
  };

  const selectFile = async () => {
    try {
      const file = await pickTextFile('.conf,.cfg,.txt,.set,.xml');
      if (!file) return;
      await clearPreview();
      setText(file.text);
      setSourceFile(file.name);
      setParsed(null);
    } catch (reason) {
      toast.error(String(reason));
    }
  };

  const prepare = async () => {
    setBusy(true);
    try {
      await clearPreview();
      const value = parseDeviceConfig(profile, text, deviceName, sourceFile || undefined);
      if (!profile.endsWith('_firewall') && roleOverride !== 'auto') value.deviceType = roleOverride;
      const built = buildConfigImport(value, inventory);
      const response = await invoke<ApiResponse<PartialImportPreview>>('preview_partial_import_text', { jsonData: built.document });
      if (!response.success || !response.data) throw new Error(response.error || 'Could not prepare the configuration import');
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
    if (!confirm(`Apply ${selectedChanges.length} reviewed configuration record(s) in one transaction?`)) return;
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
      if (!response.success || !response.data) throw new Error(response.error || 'Could not apply the configuration import');
      toast.success(`Imported ${response.data.created} new and ${response.data.updated} updated network records`);
      setPreview(null);
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
          <CardTitle className="flex items-center gap-2 text-base"><FileCode2 size={18} />Import device configuration</CardTitle>
          <p className="mt-1 text-xs text-slate-500">The file is parsed locally, previewed, then applied through the audited transactional importer.</p>
        </div>
        <Button size="sm" variant="ghost" aria-label="Close configuration importer" onClick={onClose}><X size={16} /></Button>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-[minmax(220px,0.8fr)_180px_minmax(220px,1fr)_auto]">
          <Field label="Configuration profile">
            <Select value={profile} onValueChange={(value: ConfigProfile) => { setProfile(value); setRoleOverride('auto'); setParsed(null); void clearPreview(); }}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>{CONFIG_PROFILES.map((item) => <SelectItem key={item.value} value={item.value}>{item.label}</SelectItem>)}</SelectContent>
            </Select>
          </Field>
          <Field label="Infrastructure role">
            <Select value={profile.endsWith('_firewall') ? 'firewall' : roleOverride} disabled={profile.endsWith('_firewall')} onValueChange={(value: 'auto' | 'router' | 'switch') => { setRoleOverride(value); setParsed(null); void clearPreview(); }}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>{profile.endsWith('_firewall')
                ? <SelectItem value="firewall">Firewall</SelectItem>
                : <><SelectItem value="auto">Auto-detect</SelectItem><SelectItem value="router">Router / L3 switch</SelectItem><SelectItem value="switch">Layer-2 switch</SelectItem></>}</SelectContent>
            </Select>
          </Field>
          <Field label="Device name override (optional)">
            <Input value={deviceName} onChange={(event) => setDeviceName(event.target.value)} placeholder="Use hostname from configuration" />
          </Field>
          <div className="flex items-end"><Button variant="outline" onClick={() => void selectFile()} disabled={busy}><FileUp size={16} />Select file</Button></div>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
          <Badge variant="outline">{profileInfo?.expectedFormat}</Badge>
          {sourceFile && <span>Selected: <span className="font-medium text-slate-700">{sourceFile}</span></span>}
          <span className="text-amber-700">Raw configuration is retained in the encrypted case and its exports; remove embedded secrets first when required.</span>
        </div>
        <Textarea
          rows={10}
          className="font-mono text-xs"
          value={text}
          onChange={(event) => { setText(event.target.value); setParsed(null); void clearPreview(); }}
          placeholder={`Paste ${profileInfo?.label ?? 'device'} configuration here…`}
        />
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => void prepare()} disabled={busy || !text.trim()} className="bg-cyan-600 hover:bg-cyan-700">
            {busy ? <Loader2 size={16} className="animate-spin" /> : <ShieldCheck size={16} />}Parse and review
          </Button>
          {preview && <Button onClick={() => void apply()} disabled={busy || selectedChanges.length === 0}>
            Apply {selectedChanges.length} reviewed record{selectedChanges.length === 1 ? '' : 's'}
          </Button>}
        </div>

        {parsed && (
          <div className="grid gap-2 sm:grid-cols-6">
            <Summary label="Device" value={parsed.hostname} />
            <Summary label="Role" value={parsed.deviceType} />
            <Summary label="Interfaces" value={parsed.interfaces.length} />
            <Summary label="VLANs" value={parsed.vlans.length} />
            <Summary label="Routes" value={parsed.routes.length} />
            <Summary label="ACL / NAT" value={`${parsed.aclRules.length} / ${parsed.natRules.length}`} />
          </div>
        )}

        {warnings.length > 0 && (
          <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-xs text-amber-900">
            <div className="mb-1 font-medium">Parser limitations / review points</div>
            <ul className="list-disc space-y-1 pl-5">{warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul>
          </div>
        )}

        {preview && (
          <div className="space-y-2 rounded-md border bg-white p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-sm font-medium"><Network size={16} />Transactional preview</div>
              <div className="flex gap-2 text-xs">
                <Badge variant="outline">{preview.changes.filter((item) => item.operation === 'create').length} create</Badge>
                <Badge variant="outline">{preview.changes.filter((item) => item.operation === 'update').length} update</Badge>
                <Badge variant={preview.changes.some((item) => !item.valid) ? 'destructive' : 'outline'}>
                  {preview.changes.filter((item) => !item.valid).length} invalid
                </Badge>
              </div>
            </div>
            <div className="max-h-52 overflow-auto">
              {preview.changes.map((item) => (
                <div key={item.id} className="grid grid-cols-[90px_110px_1fr] gap-2 border-t py-1.5 text-xs first:border-t-0">
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
