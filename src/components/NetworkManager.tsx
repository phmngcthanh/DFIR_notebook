import { useCallback, useEffect, useMemo, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Cable, Network as NetworkIcon, Pencil, Plus, Search, Shield, Trash2, Wifi } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Textarea } from '@/components/ui/textarea';
import FirewallDetails from '@/components/FirewallDetails';
import type { ApiResponse, Firewall, Network, NetworkConnection } from '@/types';

interface Props { refreshTrigger: number }
type Section = 'zones' | 'connections' | 'firewalls';

const emptyNetwork = { name: '', subnet: '', networkType: 'LAN', description: '', vlanId: '' };
const emptyConnection = { sourceNetworkId: '', targetNetworkId: '', connectionType: 'routed', description: '', deviceName: '' };
const emptyFirewall = { networkId: '', name: '', vendor: '', model: '', rules: '', configText: '' };

export default function NetworkManager({ refreshTrigger }: Props) {
  const [section, setSection] = useState<Section>('zones');
  const [networks, setNetworks] = useState<Network[]>([]);
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [firewalls, setFirewalls] = useState<Firewall[]>([]);
  const [search, setSearch] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [networkForm, setNetworkForm] = useState(emptyNetwork);
  const [connectionForm, setConnectionForm] = useState(emptyConnection);
  const [firewallForm, setFirewallForm] = useState(emptyFirewall);
  const [selectedFirewallId, setSelectedFirewallId] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [networkResponse, connectionResponse, firewallResponse] = await Promise.all([
        invoke<ApiResponse<Network[]>>('list_networks'),
        invoke<ApiResponse<NetworkConnection[]>>('list_network_connections'),
        invoke<ApiResponse<Firewall[]>>('list_firewalls'),
      ]);
      if (!networkResponse.success) throw new Error(networkResponse.error);
      if (!connectionResponse.success) throw new Error(connectionResponse.error);
      if (!firewallResponse.success) throw new Error(firewallResponse.error);
      setNetworks(networkResponse.data ?? []);
      setConnections(connectionResponse.data ?? []);
      setFirewalls(firewallResponse.data ?? []);
    } catch (reason) { toast.error(String(reason)); }
  }, []);

  useEffect(() => { void loadData(); }, [loadData, refreshTrigger]);

  const resetForm = () => {
    setShowForm(false); setEditingId(null); setNetworkForm(emptyNetwork); setConnectionForm(emptyConnection); setFirewallForm(emptyFirewall);
  };

  const startAdd = () => { resetForm(); setShowForm(true); };
  const startNetworkEdit = (item: Network) => {
    setEditingId(item.id); setNetworkForm({ name: item.name, subnet: item.subnet, networkType: item.network_type, description: item.description, vlanId: item.vlan_id ?? '' }); setShowForm(true);
  };
  const startConnectionEdit = (item: NetworkConnection) => {
    setEditingId(item.id); setConnectionForm({ sourceNetworkId: item.source_network_id, targetNetworkId: item.target_network_id, connectionType: item.connection_type, description: item.description, deviceName: item.device_name ?? '' }); setShowForm(true);
  };
  const startFirewallEdit = (item: Firewall) => {
    setEditingId(item.id); setFirewallForm({ networkId: item.network_id ?? '', name: item.name, vendor: item.vendor ?? '', model: item.model ?? '', rules: item.rules ?? '', configText: item.config_text ?? '' }); setShowForm(true);
  };

  const saveNetwork = async () => {
    const command = editingId ? 'update_existing_network' : 'create_new_network';
    const response = await invoke<ApiResponse<Network>>(command, { id: editingId, ...networkForm, vlanId: networkForm.vlanId || null });
    if (!response.success) throw new Error(response.error || 'Failed to save network');
  };
  const saveConnection = async () => {
    const command = editingId ? 'update_existing_network_connection' : 'create_new_network_connection';
    const response = await invoke<ApiResponse<NetworkConnection>>(command, { id: editingId, ...connectionForm, deviceName: connectionForm.deviceName || null });
    if (!response.success) throw new Error(response.error || 'Failed to save connection');
  };
  const saveFirewall = async () => {
    const command = editingId ? 'update_existing_firewall' : 'create_new_firewall';
    const response = await invoke<ApiResponse<Firewall>>(command, { id: editingId, ...firewallForm, networkId: firewallForm.networkId || null, vendor: firewallForm.vendor || null, model: firewallForm.model || null, rules: firewallForm.rules || null, configText: firewallForm.configText || null });
    if (!response.success) throw new Error(response.error || 'Failed to save firewall');
  };

  const handleSave = async () => {
    try {
      if (section === 'zones') await saveNetwork();
      if (section === 'connections') await saveConnection();
      if (section === 'firewalls') await saveFirewall();
      toast.success(editingId ? 'Changes saved' : 'Record created'); resetForm(); await loadData();
    } catch (reason) { toast.error(String(reason)); }
  };

  const handleDelete = async (command: string, id: string, label: string) => {
    if (!confirm(`Delete ${label}? This action is recorded in case history.`)) return;
    try {
      const response = await invoke<ApiResponse<boolean>>(command, { id });
      if (!response.success) throw new Error(response.error || `Failed to delete ${label}`);
      await loadData();
    } catch (reason) { toast.error(String(reason)); }
  };

  const normalized = search.trim().toLowerCase();
  const filteredNetworks = useMemo(() => networks.filter((item) => !normalized || [item.name, item.subnet, item.network_type, item.description, item.vlan_id].some((value) => value?.toLowerCase().includes(normalized))), [networks, normalized]);
  const filteredConnections = useMemo(() => connections.filter((item) => !normalized || [item.source_network_name, item.target_network_name, item.connection_type, item.device_name, item.description].some((value) => value?.toLowerCase().includes(normalized))), [connections, normalized]);
  const filteredFirewalls = useMemo(() => firewalls.filter((item) => !normalized || [item.name, item.network_name, item.vendor, item.model].some((value) => value?.toLowerCase().includes(normalized))), [firewalls, normalized]);

  return (
    <div className="space-y-4 p-6">
      <div className="flex items-center justify-between">
        <div><h2 className="text-2xl font-bold text-slate-800">Network Design</h2><p className="text-sm text-slate-500">Zones, logical links, and dedicated firewall records</p></div>
        <Button onClick={startAdd} className="bg-cyan-600 hover:bg-cyan-700"><Plus size={16} className="mr-2" />Add {section === 'zones' ? 'Zone' : section === 'connections' ? 'Connection' : 'Firewall'}</Button>
      </div>
      <Tabs value={section} onValueChange={(value) => { resetForm(); setSection(value as Section); }}>
        <div className="flex items-center justify-between gap-4">
          <TabsList><TabsTrigger value="zones"><Wifi size={14} />Zones</TabsTrigger><TabsTrigger value="connections"><Cable size={14} />Connections</TabsTrigger><TabsTrigger value="firewalls"><Shield size={14} />Firewalls</TabsTrigger></TabsList>
          <div className="relative w-80"><Search size={15} className="absolute left-3 top-2.5 text-slate-400" /><Input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search network records…" className="pl-9" /></div>
        </div>

        {showForm && (
          <Card className="mt-4"><CardHeader><CardTitle className="text-sm">{editingId ? 'Edit' : 'New'} {section.slice(0, -1)}</CardTitle></CardHeader><CardContent>
            {section === 'zones' && <NetworkForm value={networkForm} onChange={setNetworkForm} />}
            {section === 'connections' && <ConnectionForm value={connectionForm} onChange={setConnectionForm} networks={networks} />}
            {section === 'firewalls' && <FirewallForm value={firewallForm} onChange={setFirewallForm} networks={networks} />}
            <div className="mt-4 flex gap-2"><Button onClick={() => void handleSave()} className="bg-cyan-600 hover:bg-cyan-700">Save</Button><Button variant="outline" onClick={resetForm}>Cancel</Button></div>
          </CardContent></Card>
        )}

        <TabsContent value="zones"><NetworkTable items={filteredNetworks} onEdit={startNetworkEdit} onDelete={(id) => void handleDelete('remove_network', id, 'network zone')} /></TabsContent>
        <TabsContent value="connections"><ConnectionTable items={filteredConnections} onEdit={startConnectionEdit} onDelete={(id) => void handleDelete('remove_network_connection', id, 'network connection')} /></TabsContent>
        <TabsContent value="firewalls" className="space-y-4"><FirewallTable items={filteredFirewalls} selectedId={selectedFirewallId} onManage={(id) => setSelectedFirewallId(selectedFirewallId === id ? null : id)} onEdit={startFirewallEdit} onDelete={(id) => void handleDelete('remove_firewall', id, 'firewall')} />{firewalls.find((item) => item.id === selectedFirewallId) && <FirewallDetails firewall={firewalls.find((item) => item.id === selectedFirewallId)!} networks={networks} onChanged={loadData} />}</TabsContent>
      </Tabs>
    </div>
  );
}

interface NetworkFormValue { name: string; subnet: string; networkType: string; description: string; vlanId: string }
function NetworkForm({ value, onChange }: { value: NetworkFormValue; onChange: (value: NetworkFormValue) => void }) {
  return <div className="space-y-3"><div className="grid grid-cols-4 gap-3">
    <Field label="Name *"><Input value={value.name} onChange={(e) => onChange({ ...value, name: e.target.value })} /></Field>
    <Field label="Subnet *"><Input value={value.subnet} placeholder="192.168.1.0/24" onChange={(e) => onChange({ ...value, subnet: e.target.value })} /></Field>
    <Field label="Type"><Select value={value.networkType} onValueChange={(networkType) => onChange({ ...value, networkType })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{['LAN','DMZ','DMS','WAN','GUEST','MANAGEMENT','OTHER'].map((type) => <SelectItem key={type} value={type}>{type}</SelectItem>)}</SelectContent></Select></Field>
    <Field label="VLAN"><Input value={value.vlanId} onChange={(e) => onChange({ ...value, vlanId: e.target.value })} /></Field>
  </div><Field label="Description"><Textarea value={value.description} onChange={(e) => onChange({ ...value, description: e.target.value })} /></Field></div>;
}

interface ConnectionFormValue { sourceNetworkId: string; targetNetworkId: string; connectionType: string; description: string; deviceName: string }
function ConnectionForm({ value, onChange, networks }: { value: ConnectionFormValue; onChange: (value: ConnectionFormValue) => void; networks: Network[] }) {
  return <div className="space-y-3"><div className="grid grid-cols-4 gap-3">
    <Field label="Source *"><NetworkSelect value={value.sourceNetworkId} networks={networks} onChange={(sourceNetworkId) => onChange({ ...value, sourceNetworkId })} /></Field>
    <Field label="Target *"><NetworkSelect value={value.targetNetworkId} networks={networks} onChange={(targetNetworkId) => onChange({ ...value, targetNetworkId })} /></Field>
    <Field label="Type *"><Input value={value.connectionType} onChange={(e) => onChange({ ...value, connectionType: e.target.value })} /></Field>
    <Field label="Device"><Input value={value.deviceName} onChange={(e) => onChange({ ...value, deviceName: e.target.value })} /></Field>
  </div><Field label="Description"><Textarea value={value.description} onChange={(e) => onChange({ ...value, description: e.target.value })} /></Field></div>;
}

interface FirewallFormValue { networkId: string; name: string; vendor: string; model: string; rules: string; configText: string }
function FirewallForm({ value, onChange, networks }: { value: FirewallFormValue; onChange: (value: FirewallFormValue) => void; networks: Network[] }) {
  return <div className="space-y-3"><div className="grid grid-cols-4 gap-3">
    <Field label="Name *"><Input value={value.name} onChange={(e) => onChange({ ...value, name: e.target.value })} /></Field>
    <Field label="Initial home zone"><NetworkSelect optional value={value.networkId} networks={networks} onChange={(networkId) => onChange({ ...value, networkId })} /></Field>
    <Field label="Vendor"><Input value={value.vendor} onChange={(e) => onChange({ ...value, vendor: e.target.value })} /></Field>
    <Field label="Model"><Input value={value.model} onChange={(e) => onChange({ ...value, model: e.target.value })} /></Field>
  </div><div className="grid grid-cols-2 gap-3"><Field label="Rules (JSON)"><Textarea rows={5} value={value.rules} onChange={(e) => onChange({ ...value, rules: e.target.value })} /></Field><Field label="Configuration"><Textarea rows={5} value={value.configText} onChange={(e) => onChange({ ...value, configText: e.target.value })} /></Field></div></div>;
}

function Field({ label, children }: { label: string; children: React.ReactNode }) { return <div className="space-y-1"><Label>{label}</Label>{children}</div>; }
function NetworkSelect({ value, networks, onChange, optional = false }: { value: string; networks: Network[]; onChange: (value: string) => void; optional?: boolean }) {
  return <Select value={value || (optional ? '__none__' : undefined)} onValueChange={(next) => onChange(next === '__none__' ? '' : next)}><SelectTrigger><SelectValue placeholder="Select network" /></SelectTrigger><SelectContent>{optional && <SelectItem value="__none__">Unassigned</SelectItem>}{networks.map((network) => <SelectItem key={network.id} value={network.id}>{network.name}</SelectItem>)}</SelectContent></Select>;
}

const Actions = ({ onEdit, onDelete }: { onEdit: () => void; onDelete: () => void }) => <div className="flex"><Button size="sm" variant="ghost" onClick={onEdit}><Pencil size={14} /></Button><Button size="sm" variant="ghost" onClick={onDelete}><Trash2 size={14} className="text-red-500" /></Button></div>;
function NetworkTable({ items, onEdit, onDelete }: { items: Network[]; onEdit: (item: Network) => void; onDelete: (id: string) => void }) { return <Card><CardContent className="p-0"><Table><TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Subnet</TableHead><TableHead>Type</TableHead><TableHead>VLAN</TableHead><TableHead>Description</TableHead><TableHead /></TableRow></TableHeader><TableBody>{items.length ? items.map((item) => <TableRow key={item.id}><TableCell className="font-medium">{item.name}</TableCell><TableCell className="font-mono text-xs">{item.subnet}</TableCell><TableCell>{item.network_type}</TableCell><TableCell>{item.vlan_id || '—'}</TableCell><TableCell className="max-w-sm truncate">{item.description}</TableCell><TableCell><Actions onEdit={() => onEdit(item)} onDelete={() => onDelete(item.id)} /></TableCell></TableRow>) : <Empty columns={6} />}</TableBody></Table></CardContent></Card>; }
function ConnectionTable({ items, onEdit, onDelete }: { items: NetworkConnection[]; onEdit: (item: NetworkConnection) => void; onDelete: (id: string) => void }) { return <Card><CardContent className="p-0"><Table><TableHeader><TableRow><TableHead>Source</TableHead><TableHead>Target</TableHead><TableHead>Type</TableHead><TableHead>Device</TableHead><TableHead>Description</TableHead><TableHead /></TableRow></TableHeader><TableBody>{items.length ? items.map((item) => <TableRow key={item.id}><TableCell>{item.source_network_name}</TableCell><TableCell>{item.target_network_name}</TableCell><TableCell>{item.connection_type}</TableCell><TableCell>{item.device_name || '—'}</TableCell><TableCell className="max-w-sm truncate">{item.description}</TableCell><TableCell><Actions onEdit={() => onEdit(item)} onDelete={() => onDelete(item.id)} /></TableCell></TableRow>) : <Empty columns={6} />}</TableBody></Table></CardContent></Card>; }
function FirewallTable({ items, selectedId, onManage, onEdit, onDelete }: { items: Firewall[]; selectedId: string | null; onManage: (id: string) => void; onEdit: (item: Firewall) => void; onDelete: (id: string) => void }) { return <Card><CardContent className="p-0"><Table><TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Home zone</TableHead><TableHead>Vendor</TableHead><TableHead>Model</TableHead><TableHead>Configuration</TableHead><TableHead /></TableRow></TableHeader><TableBody>{items.length ? items.map((item) => <TableRow key={item.id} className={selectedId === item.id ? 'bg-amber-50' : ''}><TableCell className="font-medium">{item.name}</TableCell><TableCell>{item.network_name || 'Unassigned'}</TableCell><TableCell>{item.vendor || '—'}</TableCell><TableCell>{item.model || '—'}</TableCell><TableCell className="max-w-sm truncate">{item.config_text || item.rules || '—'}</TableCell><TableCell><div className="flex"><Button size="sm" variant={selectedId === item.id ? 'secondary' : 'ghost'} title="Manage interfaces and NAT" onClick={() => onManage(item.id)}><NetworkIcon size={14} /></Button><Actions onEdit={() => onEdit(item)} onDelete={() => onDelete(item.id)} /></div></TableCell></TableRow>) : <Empty columns={6} />}</TableBody></Table></CardContent></Card>; }
function Empty({ columns }: { columns: number }) { return <TableRow><TableCell colSpan={columns} className="py-10 text-center text-slate-400">No matching records.</TableCell></TableRow>; }
