import { useCallback, useEffect, useMemo, useState } from 'react';
import { invoke } from '@/lib/api';
import { Boxes, Cable, ChevronDown, ChevronRight, Pencil, Plus, Search, Star, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import VmInventoryImportPanel from '@/components/VmInventoryImportPanel';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Textarea } from '@/components/ui/textarea';
import { platformLabel, readStoredVmInventory } from '@/lib/vm-inventory';
import type { ApiResponse, Asset, Case, CompromiseStatus, ExpertIdentity, InfectionSummary, InvestigationStatus, Network, NetworkInterface } from '@/types';

interface Props { refreshTrigger: number; expert: ExpertIdentity }
interface AssetFormState {
  networkId: string; name: string; ipAddress: string; macAddress: string; assetType: string; os: string; userName: string;
  compromiseStatus: CompromiseStatus; investigationStatus: InvestigationStatus; properties: string; scanResults: string;
}
interface InterfaceFormState { name: string; ipAddress: string; macAddress: string; networkId: string; isPrimary: boolean }

const EMPTY_ASSET: AssetFormState = { networkId: '', name: '', ipAddress: '', macAddress: '', assetType: 'workstation', os: '', userName: '', compromiseStatus: 'unknown', investigationStatus: 'not_started', properties: '', scanResults: '' };
const EMPTY_INTERFACE: InterfaceFormState = { name: '', ipAddress: '', macAddress: '', networkId: '', isPrimary: false };

export default function AssetManager({ refreshTrigger, expert }: Props) {
  const [currentCase, setCurrentCase] = useState<Case | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [networks, setNetworks] = useState<Network[]>([]);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [form, setForm] = useState<AssetFormState>(EMPTY_ASSET);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [expandedAssetId, setExpandedAssetId] = useState<string | null>(null);
  const [interfaceForm, setInterfaceForm] = useState<InterfaceFormState>(EMPTY_INTERFACE);
  const [editingInterfaceId, setEditingInterfaceId] = useState<string | null>(null);
  const [showInterfaceForm, setShowInterfaceForm] = useState(false);
  const [search, setSearch] = useState('');
  const [networkFilter, setNetworkFilter] = useState('all');
  const [compromiseFilter, setCompromiseFilter] = useState('all');
  const [investigationFilter, setInvestigationFilter] = useState('all');
  const [focusOnly, setFocusOnly] = useState(expert.scope_network_ids.length > 0);
  const [showVmImport, setShowVmImport] = useState(false);

  const [infection, setInfection] = useState<InfectionSummary>({ entities: [], iocs: [] });

  const loadData = useCallback(async () => {
    try {
      const [caseResponse, assetResponse, networkResponse, interfaceResponse, infectionResponse] = await Promise.all([
        invoke<ApiResponse<Case | null>>('get_current_case_info'),
        invoke<ApiResponse<Asset[]>>('list_assets'), invoke<ApiResponse<Network[]>>('list_networks'),
        invoke<ApiResponse<NetworkInterface[]>>('list_network_interfaces', { assetId: null }),
        invoke<ApiResponse<InfectionSummary>>('get_infection_summary'),
      ]);
      if (!caseResponse.success) throw new Error(caseResponse.error);
      if (!assetResponse.success) throw new Error(assetResponse.error);
      if (!networkResponse.success) throw new Error(networkResponse.error);
      if (!interfaceResponse.success) throw new Error(interfaceResponse.error);
      if (!infectionResponse.success) throw new Error(infectionResponse.error);
      setCurrentCase(caseResponse.data ?? null);
      setAssets(assetResponse.data ?? []); setNetworks(networkResponse.data ?? []); setInterfaces(interfaceResponse.data ?? []);
      setInfection(infectionResponse.data ?? { entities: [], iocs: [] });
    } catch (reason) { toast.error(String(reason)); }
  }, []);

  useEffect(() => { void loadData(); }, [loadData, refreshTrigger]);

  const resetAssetForm = () => { setShowForm(false); setEditingId(null); setForm(EMPTY_ASSET); };
  const startEdit = (asset: Asset) => {
    setEditingId(asset.id); setShowForm(true);
    setForm({ networkId: asset.network_id ?? '', name: asset.name, ipAddress: asset.ip_address, macAddress: asset.mac_address ?? '', assetType: asset.asset_type,
      os: asset.os ?? '', userName: asset.user_name ?? '', compromiseStatus: asset.compromise_status, investigationStatus: asset.investigation_status,
      properties: asset.properties ?? '', scanResults: asset.scan_results ?? '' });
  };

  const saveAsset = async () => {
    if (expert.scope_network_ids.length && form.networkId && !expert.scope_network_ids.includes(form.networkId)
      && !confirm('This asset is outside your selected focus zones. Save it anyway?')) return;
    try {
      const response = await invoke<ApiResponse<Asset>>(editingId ? 'update_existing_asset' : 'create_new_asset', {
        id: editingId, ...form, networkId: form.networkId || null, macAddress: form.macAddress || null, os: form.os || null,
        userName: form.userName || null, properties: form.properties || null, scanResults: form.scanResults || null,
      });
      if (!response.success) throw new Error(response.error || 'Failed to save asset');
      toast.success(editingId ? 'Asset updated' : 'Asset created'); resetAssetForm(); await loadData();
    } catch (reason) { toast.error(String(reason)); }
  };

  const deleteAsset = async (id: string) => {
    if (!confirm('Delete this asset? Interfaces are removed, but timeline evidence is retained and unlinked.')) return;
    try { const response = await invoke<ApiResponse<boolean>>('remove_asset', { id }); if (!response.success) throw new Error(response.error); await loadData(); }
    catch (reason) { toast.error(String(reason)); }
  };

  const beginInterface = (item?: NetworkInterface) => {
    if (item) { setEditingInterfaceId(item.id); setInterfaceForm({ name: item.name, ipAddress: item.ip_address, macAddress: item.mac_address ?? '', networkId: item.network_id ?? '', isPrimary: item.is_primary }); }
    else { setEditingInterfaceId(null); setInterfaceForm(EMPTY_INTERFACE); }
    setShowInterfaceForm(true);
  };

  const saveInterface = async () => {
    if (!expandedAssetId) return;
    if (expert.scope_network_ids.length && interfaceForm.networkId && !expert.scope_network_ids.includes(interfaceForm.networkId)
      && !confirm('This interface connects outside your selected focus zones. Save it anyway?')) return;
    try {
      const response = await invoke<ApiResponse<NetworkInterface>>(editingInterfaceId ? 'update_existing_network_interface' : 'create_new_network_interface', {
        id: editingInterfaceId, assetId: expandedAssetId, ...interfaceForm, networkId: interfaceForm.networkId || null, macAddress: interfaceForm.macAddress || null,
      });
      if (!response.success) throw new Error(response.error || 'Failed to save interface');
      setShowInterfaceForm(false); setEditingInterfaceId(null); setInterfaceForm(EMPTY_INTERFACE); await loadData();
    } catch (reason) { toast.error(String(reason)); }
  };

  const setPrimary = async (id: string) => {
    try { const response = await invoke<ApiResponse<NetworkInterface>>('set_primary_network_interface', { id }); if (!response.success) throw new Error(response.error); await loadData(); }
    catch (reason) { toast.error(String(reason)); }
  };
  const deleteInterface = async (id: string) => {
    if (!confirm('Delete this interface?')) return;
    try { const response = await invoke<ApiResponse<boolean>>('remove_network_interface', { id }); if (!response.success) throw new Error(response.error); await loadData(); }
    catch (reason) { toast.error(String(reason)); }
  };

  const interfacesByAsset = useMemo(() => {
    const grouped = new Map<string, NetworkInterface[]>();
    for (const item of interfaces) {
      const items = grouped.get(item.asset_id) ?? [];
      items.push(item);
      grouped.set(item.asset_id, items);
    }
    return grouped;
  }, [interfaces]);
  const filteredAssets = useMemo(() => {
    const term = search.trim().toLowerCase();
    return assets.filter((asset) => {
      const assetInterfaces = interfacesByAsset.get(asset.id) ?? [];
      const vmInventory = readStoredVmInventory(asset.properties);
      const scopeMatch = !focusOnly || expert.scope_network_ids.length === 0 || assetInterfaces.some((item) => item.network_id && expert.scope_network_ids.includes(item.network_id));
      const networkMatch = networkFilter === 'all' || assetInterfaces.some((item) => item.network_id === networkFilter);
      return scopeMatch && networkMatch && (compromiseFilter === 'all' || asset.compromise_status === compromiseFilter)
        && (investigationFilter === 'all' || asset.investigation_status === investigationFilter)
        && (!term || [
          asset.name, asset.ip_address, asset.mac_address, asset.os, asset.user_name, asset.network_name,
          vmInventory?.platform, vmInventory?.hypervisor, vmInventory?.inventoryScope, vmInventory?.nativeId,
        ].some((value) => value?.toLowerCase().includes(term)));
    });
  }, [assets, interfacesByAsset, focusOnly, expert.scope_network_ids, networkFilter, compromiseFilter, investigationFilter, search]);

  return (
    <div className="space-y-4 p-6">
      <div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="text-2xl font-bold text-slate-800">Assets and PC Configuration</h2><p className="text-sm text-slate-500">Primary configuration, investigation status, multi-homed interfaces, and virtual-machine inventory</p></div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setShowVmImport((value) => !value)}><Boxes size={16} className="mr-2" />Import VM inventory</Button>
          <Button onClick={() => { resetAssetForm(); setShowForm(true); }} className="bg-cyan-600 hover:bg-cyan-700"><Plus size={16} className="mr-2" />Add Asset</Button>
        </div>
      </div>
      {showVmImport && currentCase && <VmInventoryImportPanel
        inventory={{ caseId: currentCase.id, assets, networks, networkInterfaces: interfaces }}
        onApplied={loadData}
        onClose={() => setShowVmImport(false)}
      />}
      <Card><CardContent className="flex flex-wrap items-end gap-3 p-3">
        <div className="relative min-w-64 flex-1"><Search size={15} className="absolute left-3 top-2.5 text-slate-400" /><Input className="pl-9" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search name, IP, MAC, OS, or user…" /></div>
        <SmallSelect value={networkFilter} onChange={setNetworkFilter} label="Network" items={[['all','All networks'], ...networks.map((item): [string,string] => [item.id,item.name])]} />
        <SmallSelect value={compromiseFilter} onChange={setCompromiseFilter} label="Compromise" items={statusItems('compromise')} />
        <SmallSelect value={investigationFilter} onChange={setInvestigationFilter} label="Progress" items={statusItems('investigation')} />
        {expert.scope_network_ids.length > 0 && <label className="flex h-9 items-center gap-2 rounded border px-3 text-sm"><input type="checkbox" checked={focusOnly} onChange={(e) => setFocusOnly(e.target.checked)} />Focus zones only</label>}
      </CardContent></Card>

      {showForm && <AssetForm form={form} setForm={setForm} networks={networks} editing={Boolean(editingId)} onSave={() => void saveAsset()} onCancel={resetAssetForm} />}

      <Card><CardContent className="p-0"><Table><TableHeader><TableRow><TableHead /><TableHead>Name</TableHead><TableHead>Primary network</TableHead><TableHead>IP</TableHead><TableHead>Type / OS</TableHead><TableHead>Compromise</TableHead><TableHead>Progress</TableHead><TableHead>NICs</TableHead><TableHead /></TableRow></TableHeader><TableBody>
        {filteredAssets.length === 0 ? <TableRow><TableCell colSpan={9} className="py-10 text-center text-slate-400">No matching assets.</TableCell></TableRow> : filteredAssets.map((asset) => {
          const assetInterfaces = interfacesByAsset.get(asset.id) ?? [];
          const sightingCount = infection.entities.find((entry) => entry.entity_kind === 'asset' && entry.entity_id === asset.id)?.sighting_count ?? 0;
          return <AssetRows key={asset.id} asset={asset} sightingCount={sightingCount} interfaces={assetInterfaces} expanded={expandedAssetId === asset.id}
            onToggle={() => { setExpandedAssetId(expandedAssetId === asset.id ? null : asset.id); setShowInterfaceForm(false); }} onEdit={() => startEdit(asset)} onDelete={() => void deleteAsset(asset.id)}
            interfaceForm={interfaceForm} setInterfaceForm={setInterfaceForm} showInterfaceForm={showInterfaceForm && expandedAssetId === asset.id}
            editingInterfaceId={editingInterfaceId} networks={networks} onBeginInterface={beginInterface} onSaveInterface={() => void saveInterface()}
            onCancelInterface={() => setShowInterfaceForm(false)} onPrimary={(id) => void setPrimary(id)} onDeleteInterface={(id) => void deleteInterface(id)} />;
        })}
      </TableBody></Table></CardContent></Card>
    </div>
  );
}

function AssetForm({ form, setForm, networks, editing, onSave, onCancel }: { form: AssetFormState; setForm: (value: AssetFormState) => void; networks: Network[]; editing: boolean; onSave: () => void; onCancel: () => void }) {
  return <Card><CardHeader><CardTitle className="text-sm">{editing ? 'Edit asset' : 'New asset'}</CardTitle></CardHeader><CardContent className="space-y-3">
    <div className="grid grid-cols-4 gap-3"><Field label="Name *"><Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field><Field label="Primary network"><NetworkSelect value={form.networkId} networks={networks} onChange={(networkId) => setForm({ ...form, networkId })} /></Field>
      <Field label="IP address"><Input value={form.ipAddress} onChange={(e) => setForm({ ...form, ipAddress: e.target.value })} /></Field><Field label="MAC address"><Input value={form.macAddress} onChange={(e) => setForm({ ...form, macAddress: e.target.value })} /></Field></div>
    <div className="grid grid-cols-5 gap-3"><Field label="Type"><Select value={form.assetType} onValueChange={(assetType) => setForm({ ...form, assetType })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{['workstation','server','vm','laptop','router','switch','other'].map((type) => <SelectItem key={type} value={type}>{type}</SelectItem>)}</SelectContent></Select></Field>
      <Field label="OS"><Input value={form.os} onChange={(e) => setForm({ ...form, os: e.target.value })} /></Field><Field label="User / owner"><Input value={form.userName} onChange={(e) => setForm({ ...form, userName: e.target.value })} /></Field>
      <Field label="Compromise"><Select value={form.compromiseStatus} onValueChange={(compromiseStatus: CompromiseStatus) => setForm({ ...form, compromiseStatus })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{['unknown','clean','suspected','infected'].map((value) => <SelectItem key={value} value={value}>{label(value)}</SelectItem>)}</SelectContent></Select></Field>
      <Field label="Investigation"><Select value={form.investigationStatus} onValueChange={(investigationStatus: InvestigationStatus) => setForm({ ...form, investigationStatus })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{['not_started','in_progress','completed'].map((value) => <SelectItem key={value} value={value}>{label(value)}</SelectItem>)}</SelectContent></Select></Field></div>
    <div className="grid grid-cols-2 gap-3"><Field label="Properties / findings"><Textarea rows={3} value={form.properties} onChange={(e) => setForm({ ...form, properties: e.target.value })} /></Field><Field label="Scan results (JSON)"><Textarea rows={3} value={form.scanResults} onChange={(e) => setForm({ ...form, scanResults: e.target.value })} /></Field></div>
    <div className="flex gap-2"><Button onClick={onSave} className="bg-cyan-600 hover:bg-cyan-700">Save</Button><Button variant="outline" onClick={onCancel}>Cancel</Button></div>
  </CardContent></Card>;
}

interface AssetRowsProps { asset: Asset; sightingCount: number; interfaces: NetworkInterface[]; expanded: boolean; onToggle: () => void; onEdit: () => void; onDelete: () => void; interfaceForm: InterfaceFormState; setInterfaceForm: (value: InterfaceFormState) => void; showInterfaceForm: boolean; editingInterfaceId: string | null; networks: Network[]; onBeginInterface: (item?: NetworkInterface) => void; onSaveInterface: () => void; onCancelInterface: () => void; onPrimary: (id: string) => void; onDeleteInterface: (id: string) => void }
function AssetRows(props: AssetRowsProps) {
  const { asset, interfaces, expanded } = props;
  const vmInventory = readStoredVmInventory(asset.properties);
  return <><TableRow className={asset.compromise_status === 'infected' ? 'bg-red-50' : asset.compromise_status === 'suspected' ? 'bg-amber-50' : ''}>
    <TableCell><Button size="sm" variant="ghost" onClick={props.onToggle}>{expanded ? <ChevronDown size={15} /> : <ChevronRight size={15} />}</Button></TableCell><TableCell className="font-medium">{asset.name}<div className="text-xs text-slate-400">{asset.user_name}</div></TableCell><TableCell>{asset.network_name || 'Unassigned'}</TableCell><TableCell className="font-mono text-xs">{asset.ip_address || '—'}</TableCell><TableCell><Badge variant="outline">{asset.asset_type}</Badge><div className="mt-1 text-xs text-slate-500">{asset.os}</div></TableCell>
    <TableCell><StatusBadge value={asset.compromise_status} />{props.sightingCount > 0 && <span className="ml-1 rounded bg-red-600 px-1.5 py-0.5 text-xs text-white" title={`${props.sightingCount} IOC sighting(s) recorded on this asset`}>⚠{props.sightingCount}</span>}</TableCell><TableCell><StatusBadge value={asset.investigation_status} /></TableCell><TableCell>{interfaces.length}</TableCell><TableCell><div className="flex"><Button size="sm" variant="ghost" onClick={props.onEdit}><Pencil size={14} /></Button><Button size="sm" variant="ghost" onClick={props.onDelete}><Trash2 size={14} className="text-red-500" /></Button></div></TableCell>
  </TableRow>{expanded && <TableRow><TableCell colSpan={9} className="bg-slate-50 p-4">
    {vmInventory && <div className="mb-4 rounded border border-violet-200 bg-violet-50 p-3">
      <div className="mb-2 flex flex-wrap items-center gap-2"><Boxes size={15} className="text-violet-600" /><strong className="text-sm">Imported virtualization inventory</strong><Badge variant="outline">{platformLabel(vmInventory.platform)}</Badge><Badge variant="outline">{vmInventory.kind}</Badge></div>
      <div className="grid gap-2 text-xs sm:grid-cols-3 lg:grid-cols-6">
        <InventoryField label="Native ID" value={vmInventory.nativeId} />
        <InventoryField label="Host / node" value={vmInventory.hypervisor ?? vmInventory.inventoryScope} />
        <InventoryField label="State" value={vmInventory.state} />
        <InventoryField label="CPU" value={vmInventory.cpuCount} />
        <InventoryField label="Memory" value={formatBytes(vmInventory.memoryBytes)} />
        <InventoryField label="Disk" value={formatBytes(vmInventory.diskBytes)} />
      </div>
    </div>}
    <div className="mb-3 flex items-center justify-between"><h3 className="flex items-center gap-2 text-sm font-semibold"><Cable size={15} />Network interfaces</h3><Button size="sm" variant="outline" onClick={() => props.onBeginInterface()}><Plus size={14} className="mr-1" />Add NIC</Button></div>
    <div className="grid gap-2">{interfaces.map((item) => <div key={item.id} className="flex items-center justify-between rounded border bg-white p-2 text-sm"><div className="flex items-center gap-3">{item.is_primary && <Star size={14} className="fill-amber-400 text-amber-500" />}<strong>{item.name}</strong><span>{item.network_name || 'Unassigned'}</span><code>{item.ip_address}</code><span className="text-slate-500">{item.mac_address}</span></div><div className="flex">{!item.is_primary && <Button size="sm" variant="ghost" onClick={() => props.onPrimary(item.id)} title="Make primary"><Star size={14} /></Button>}<Button size="sm" variant="ghost" onClick={() => props.onBeginInterface(item)}><Pencil size={14} /></Button><Button size="sm" variant="ghost" onClick={() => props.onDeleteInterface(item.id)}><Trash2 size={14} className="text-red-500" /></Button></div></div>)}</div>
    {props.showInterfaceForm && <div className="mt-3 grid grid-cols-6 items-end gap-2 rounded border bg-white p-3"><Field label="Name"><Input value={props.interfaceForm.name} onChange={(e) => props.setInterfaceForm({ ...props.interfaceForm, name: e.target.value })} /></Field><Field label="Network"><NetworkSelect value={props.interfaceForm.networkId} networks={props.networks} onChange={(networkId) => props.setInterfaceForm({ ...props.interfaceForm, networkId })} /></Field><Field label="IP"><Input value={props.interfaceForm.ipAddress} onChange={(e) => props.setInterfaceForm({ ...props.interfaceForm, ipAddress: e.target.value })} /></Field><Field label="MAC"><Input value={props.interfaceForm.macAddress} onChange={(e) => props.setInterfaceForm({ ...props.interfaceForm, macAddress: e.target.value })} /></Field><label className="flex h-9 items-center gap-2"><input type="checkbox" checked={props.interfaceForm.isPrimary} onChange={(e) => props.setInterfaceForm({ ...props.interfaceForm, isPrimary: e.target.checked })} />Primary</label><div className="flex gap-1"><Button size="sm" onClick={props.onSaveInterface}>Save</Button><Button size="sm" variant="outline" onClick={props.onCancelInterface}>Cancel</Button></div></div>}
  </TableCell></TableRow>}</>;
}

function Field({ label: text, children }: { label: string; children: React.ReactNode }) { return <div className="space-y-1"><Label>{text}</Label>{children}</div>; }
function NetworkSelect({ value, networks, onChange }: { value: string; networks: Network[]; onChange: (value: string) => void }) { return <Select value={value || '__none__'} onValueChange={(next) => onChange(next === '__none__' ? '' : next)}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="__none__">Unassigned</SelectItem>{networks.map((network) => <SelectItem key={network.id} value={network.id}>{network.name}</SelectItem>)}</SelectContent></Select>; }
function SmallSelect({ value, onChange, label: text, items }: { value: string; onChange: (value: string) => void; label: string; items: [string,string][] }) { return <div><Label className="text-xs">{text}</Label><Select value={value} onValueChange={onChange}><SelectTrigger className="w-44"><SelectValue /></SelectTrigger><SelectContent>{items.map(([id,name]) => <SelectItem key={id} value={id}>{name}</SelectItem>)}</SelectContent></Select></div>; }
function statusItems(type: 'compromise' | 'investigation'): [string,string][] { const values = type === 'compromise' ? ['unknown','clean','suspected','infected'] : ['not_started','in_progress','completed']; return [['all','All'], ...values.map((value): [string,string] => [value,label(value)])]; }
function label(value: string) { return value.replaceAll('_', ' ').replace(/^./, (character) => character.toUpperCase()); }
function StatusBadge({ value }: { value: string }) { const colors: Record<string,string> = { infected:'bg-red-100 text-red-700',suspected:'bg-amber-100 text-amber-700',clean:'bg-green-100 text-green-700',unknown:'bg-slate-100 text-slate-600',not_started:'bg-slate-100 text-slate-600',in_progress:'bg-blue-100 text-blue-700',completed:'bg-green-100 text-green-700' }; return <span className={`rounded px-2 py-1 text-xs ${colors[value] ?? colors.unknown}`}>{label(value)}</span>; }
function InventoryField({ label: text, value }: { label: string; value: string | number | undefined }) { return <div><div className="text-[10px] uppercase text-slate-400">{text}</div><div className="truncate font-medium text-slate-700">{value ?? '—'}</div></div>; }
function formatBytes(value: number | undefined): string | undefined { if (value === undefined) return undefined; const units = ['B','KiB','MiB','GiB','TiB']; let size = value; let unit = 0; while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; } return `${size >= 10 || unit === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`; }
