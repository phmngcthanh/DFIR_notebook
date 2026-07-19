import { useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Pencil, Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Textarea } from '@/components/ui/textarea';
import type { ApiResponse, Firewall, FirewallInterface, FirewallNatRule, Network } from '@/types';

interface Props {
  firewall: Firewall;
  networks: Network[];
  onChanged: () => Promise<void>;
}

const emptyInterface = { name: '', addresses: '', macAddress: '', networkId: '', vlanId: '', role: 'other', isPrimary: false, description: '' };
const emptyNat = { name: '', natType: 'dnat', enabled: true, protocol: 'any', sourceCidr: '', originalDestination: '', originalPort: '', translatedSource: '', translatedDestination: '', translatedPort: '', inboundInterfaceId: '', outboundInterfaceId: '', description: '' };

const optional = (value: string) => value.trim() || null;
const addresses = (value: string) => value.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean);

export default function FirewallDetails({ firewall, networks, onChanged }: Props) {
  const [interfaces, setInterfaces] = useState<FirewallInterface[]>([]);
  const [natRules, setNatRules] = useState<FirewallNatRule[]>([]);
  const [interfaceForm, setInterfaceForm] = useState(emptyInterface);
  const [natForm, setNatForm] = useState(emptyNat);
  const [editingInterface, setEditingInterface] = useState<string | null>(null);
  const [editingNat, setEditingNat] = useState<string | null>(null);
  const [showInterfaceForm, setShowInterfaceForm] = useState(false);
  const [showNatForm, setShowNatForm] = useState(false);

  const load = useCallback(async () => {
    const [interfaceResponse, natResponse] = await Promise.all([
      invoke<ApiResponse<FirewallInterface[]>>('list_firewall_interfaces', { firewallId: firewall.id }),
      invoke<ApiResponse<FirewallNatRule[]>>('list_firewall_nat_rules', { firewallId: firewall.id }),
    ]);
    if (!interfaceResponse.success) throw new Error(interfaceResponse.error || 'Could not load firewall interfaces');
    if (!natResponse.success) throw new Error(natResponse.error || 'Could not load NAT rules');
    setInterfaces(interfaceResponse.data ?? []);
    setNatRules(natResponse.data ?? []);
  }, [firewall.id]);

  useEffect(() => { void load().catch((error) => toast.error(String(error))); }, [load]);

  const saveInterface = async () => {
    try {
      const command = editingInterface ? 'update_existing_firewall_interface' : 'create_new_firewall_interface';
      const response = await invoke<ApiResponse<FirewallInterface>>(command, {
        id: editingInterface, firewallId: firewall.id, name: interfaceForm.name,
        ipAddresses: addresses(interfaceForm.addresses), macAddress: optional(interfaceForm.macAddress),
        networkId: optional(interfaceForm.networkId), vlanId: optional(interfaceForm.vlanId),
        role: interfaceForm.role, isPrimary: interfaceForm.isPrimary, description: interfaceForm.description,
      });
      if (!response.success) throw new Error(response.error || 'Could not save firewall interface');
      setInterfaceForm(emptyInterface); setEditingInterface(null); setShowInterfaceForm(false);
      await load(); await onChanged();
      toast.success(editingInterface ? 'Interface updated' : 'Interface added');
    } catch (error) { toast.error(String(error)); }
  };

  const saveNat = async () => {
    try {
      const command = editingNat ? 'update_existing_firewall_nat_rule' : 'create_new_firewall_nat_rule';
      const response = await invoke<ApiResponse<FirewallNatRule>>(command, {
        id: editingNat, firewallId: firewall.id, name: natForm.name, natType: natForm.natType,
        enabled: natForm.enabled, protocol: natForm.protocol, sourceCidr: optional(natForm.sourceCidr),
        originalDestination: optional(natForm.originalDestination), originalPort: optional(natForm.originalPort),
        translatedSource: optional(natForm.translatedSource), translatedDestination: optional(natForm.translatedDestination),
        translatedPort: optional(natForm.translatedPort), inboundInterfaceId: optional(natForm.inboundInterfaceId),
        outboundInterfaceId: optional(natForm.outboundInterfaceId), description: natForm.description,
      });
      if (!response.success) throw new Error(response.error || 'Could not save NAT rule');
      setNatForm(emptyNat); setEditingNat(null); setShowNatForm(false); await load();
      toast.success(editingNat ? 'NAT rule updated' : 'NAT rule added');
    } catch (error) { toast.error(String(error)); }
  };

  const remove = async (command: string, id: string, label: string) => {
    if (!confirm(`Delete ${label}? This is recorded in case history.`)) return;
    try {
      const response = await invoke<ApiResponse<boolean>>(command, { id });
      if (!response.success) throw new Error(response.error || `Could not delete ${label}`);
      await load(); await onChanged();
    } catch (error) { toast.error(String(error)); }
  };

  const editInterface = (item: FirewallInterface) => {
    setEditingInterface(item.id); setShowInterfaceForm(true);
    setInterfaceForm({ name: item.name, addresses: item.ip_addresses.join('\n'), macAddress: item.mac_address ?? '', networkId: item.network_id ?? '', vlanId: item.vlan_id ?? '', role: item.role, isPrimary: item.is_primary, description: item.description });
  };
  const editNat = (item: FirewallNatRule) => {
    setEditingNat(item.id); setShowNatForm(true);
    setNatForm({ name: item.name, natType: item.nat_type, enabled: item.enabled, protocol: item.protocol, sourceCidr: item.source_cidr ?? '', originalDestination: item.original_destination ?? '', originalPort: item.original_port ?? '', translatedSource: item.translated_source ?? '', translatedDestination: item.translated_destination ?? '', translatedPort: item.translated_port ?? '', inboundInterfaceId: item.inbound_interface_id ?? '', outboundInterfaceId: item.outbound_interface_id ?? '', description: item.description });
  };

  return <Card className="border-amber-200 bg-amber-50/30">
    <CardHeader><CardTitle className="text-base">{firewall.name}: interfaces and address translation</CardTitle></CardHeader>
    <CardContent><Tabs defaultValue="interfaces">
      <TabsList><TabsTrigger value="interfaces">Interfaces ({interfaces.length})</TabsTrigger><TabsTrigger value="nat">NAT / VIP ({natRules.length})</TabsTrigger></TabsList>
      <TabsContent value="interfaces" className="space-y-3">
        <div className="flex items-center justify-between"><p className="text-sm text-slate-600">Each interface can hold multiple IPv4/IPv6 addresses or CIDRs and attach to a zone.</p><Button size="sm" onClick={() => { setEditingInterface(null); setInterfaceForm(emptyInterface); setShowInterfaceForm(true); }}><Plus size={14} className="mr-1" />Interface</Button></div>
        {showInterfaceForm && <Card><CardContent className="space-y-3 pt-5">
          <div className="grid grid-cols-4 gap-3"><Field label="Name *"><Input value={interfaceForm.name} onChange={(e) => setInterfaceForm({ ...interfaceForm, name: e.target.value })} placeholder="ethernet1/1" /></Field><Field label="Role"><Choice value={interfaceForm.role} values={['wan','lan','dmz','management','ha','vpn','other']} onChange={(role) => setInterfaceForm({ ...interfaceForm, role })} /></Field><Field label="Zone"><NetworkChoice value={interfaceForm.networkId} networks={networks} onChange={(networkId) => setInterfaceForm({ ...interfaceForm, networkId })} /></Field><Field label="VLAN"><Input value={interfaceForm.vlanId} onChange={(e) => setInterfaceForm({ ...interfaceForm, vlanId: e.target.value })} /></Field></div>
          <div className="grid grid-cols-2 gap-3"><Field label="IP addresses / CIDRs (one per line or comma-separated)"><Textarea rows={4} value={interfaceForm.addresses} onChange={(e) => setInterfaceForm({ ...interfaceForm, addresses: e.target.value })} placeholder={'203.0.113.4/29\n2001:db8::1/64'} /></Field><div className="space-y-3"><Field label="MAC address"><Input value={interfaceForm.macAddress} onChange={(e) => setInterfaceForm({ ...interfaceForm, macAddress: e.target.value })} /></Field><Field label="Description"><Input value={interfaceForm.description} onChange={(e) => setInterfaceForm({ ...interfaceForm, description: e.target.value })} /></Field><label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={interfaceForm.isPrimary} onChange={(event) => setInterfaceForm({ ...interfaceForm, isPrimary: event.target.checked })} className="h-4 w-4 rounded border-slate-300" />Primary/home interface</label></div></div>
          <div className="flex gap-2"><Button size="sm" onClick={() => void saveInterface()}>Save interface</Button><Button size="sm" variant="outline" onClick={() => setShowInterfaceForm(false)}>Cancel</Button></div>
        </CardContent></Card>}
        <Table><TableHeader><TableRow><TableHead>Interface</TableHead><TableHead>Role / zone</TableHead><TableHead>Addresses</TableHead><TableHead>MAC / VLAN</TableHead><TableHead /></TableRow></TableHeader><TableBody>{interfaces.length ? interfaces.map((item) => <TableRow key={item.id}><TableCell className="font-medium">{item.name}{item.is_primary && <span className="ml-2 text-xs text-amber-700">Primary</span>}</TableCell><TableCell>{item.role.toUpperCase()} Â· {item.network_name || 'Unassigned'}</TableCell><TableCell className="font-mono text-xs">{item.ip_addresses.join(', ') || 'â€”'}</TableCell><TableCell className="text-xs">{item.mac_address || 'â€”'}{item.vlan_id ? ` Â· VLAN ${item.vlan_id}` : ''}</TableCell><TableCell><RowActions onEdit={() => editInterface(item)} onDelete={() => void remove('remove_firewall_interface', item.id, 'interface')} /></TableCell></TableRow>) : <Empty columns={5} text="No firewall interfaces recorded." />}</TableBody></Table>
      </TabsContent>
      <TabsContent value="nat" className="space-y-3">
        <div className="flex items-center justify-between"><p className="text-sm text-slate-600">Structured VIP, DNAT, SNAT and port mappings. Port values accept a port, range, or comma-separated list.</p><Button size="sm" onClick={() => { setEditingNat(null); setNatForm(emptyNat); setShowNatForm(true); }}><Plus size={14} className="mr-1" />NAT rule</Button></div>
        {showNatForm && <Card><CardContent className="space-y-3 pt-5">
          <div className="grid grid-cols-4 gap-3"><Field label="Name *"><Input value={natForm.name} onChange={(e) => setNatForm({ ...natForm, name: e.target.value })} /></Field><Field label="Type"><Choice value={natForm.natType} values={['vip','dnat','snat','port_mapping']} onChange={(natType) => setNatForm({ ...natForm, natType })} /></Field><Field label="Protocol"><Choice value={natForm.protocol} values={['any','tcp','udp','icmp','sctp','other']} onChange={(protocol) => setNatForm({ ...natForm, protocol })} /></Field><label className="flex items-end gap-2 pb-2 text-sm"><input type="checkbox" checked={natForm.enabled} onChange={(event) => setNatForm({ ...natForm, enabled: event.target.checked })} className="h-4 w-4 rounded border-slate-300" />Enabled</label></div>
          <div className="grid grid-cols-3 gap-3"><Field label="Source CIDR"><Input value={natForm.sourceCidr} onChange={(e) => setNatForm({ ...natForm, sourceCidr: e.target.value })} /></Field><Field label="Original destination"><Input value={natForm.originalDestination} onChange={(e) => setNatForm({ ...natForm, originalDestination: e.target.value })} /></Field><Field label="Original port(s)"><Input value={natForm.originalPort} onChange={(e) => setNatForm({ ...natForm, originalPort: e.target.value })} placeholder="443 or 8000-8100" /></Field></div>
          <div className="grid grid-cols-3 gap-3"><Field label="Translated source"><Input value={natForm.translatedSource} onChange={(e) => setNatForm({ ...natForm, translatedSource: e.target.value })} /></Field><Field label="Translated destination"><Input value={natForm.translatedDestination} onChange={(e) => setNatForm({ ...natForm, translatedDestination: e.target.value })} /></Field><Field label="Translated port(s)"><Input value={natForm.translatedPort} onChange={(e) => setNatForm({ ...natForm, translatedPort: e.target.value })} /></Field></div>
          <div className="grid grid-cols-3 gap-3"><Field label="Inbound interface"><InterfaceChoice value={natForm.inboundInterfaceId} interfaces={interfaces} onChange={(inboundInterfaceId) => setNatForm({ ...natForm, inboundInterfaceId })} /></Field><Field label="Outbound interface"><InterfaceChoice value={natForm.outboundInterfaceId} interfaces={interfaces} onChange={(outboundInterfaceId) => setNatForm({ ...natForm, outboundInterfaceId })} /></Field><Field label="Description"><Input value={natForm.description} onChange={(e) => setNatForm({ ...natForm, description: e.target.value })} /></Field></div>
          <div className="flex gap-2"><Button size="sm" onClick={() => void saveNat()}>Save NAT rule</Button><Button size="sm" variant="outline" onClick={() => setShowNatForm(false)}>Cancel</Button></div>
        </CardContent></Card>}
        <Table><TableHeader><TableRow><TableHead>Rule</TableHead><TableHead>Match</TableHead><TableHead>Translation</TableHead><TableHead>Interfaces</TableHead><TableHead /></TableRow></TableHeader><TableBody>{natRules.length ? natRules.map((item) => <TableRow key={item.id} className={!item.enabled ? 'opacity-50' : ''}><TableCell><div className="font-medium">{item.name}</div><div className="text-xs uppercase text-slate-500">{item.nat_type.replace('_', ' ')} Â· {item.protocol}</div></TableCell><TableCell className="font-mono text-xs">{item.source_cidr ? `from ${item.source_cidr} ` : ''}{item.original_destination || '*'}{item.original_port ? `:${item.original_port}` : ''}</TableCell><TableCell className="font-mono text-xs">{item.translated_source ? `source â†’ ${item.translated_source}; ` : ''}{item.translated_destination ? `destination â†’ ${item.translated_destination}${item.translated_port ? `:${item.translated_port}` : ''}` : 'â€”'}</TableCell><TableCell className="text-xs">{interfaceName(interfaces, item.inbound_interface_id)} â†’ {interfaceName(interfaces, item.outbound_interface_id)}</TableCell><TableCell><RowActions onEdit={() => editNat(item)} onDelete={() => void remove('remove_firewall_nat_rule', item.id, 'NAT rule')} /></TableCell></TableRow>) : <Empty columns={5} text="No structured NAT or VIP records." />}</TableBody></Table>
      </TabsContent>
    </Tabs></CardContent>
  </Card>;
}

function Field({ label, children }: { label: string; children: React.ReactNode }) { return <div className="space-y-1"><Label>{label}</Label>{children}</div>; }
function Choice({ value, values, onChange }: { value: string; values: string[]; onChange: (value: string) => void }) { return <Select value={value} onValueChange={onChange}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{values.map((item) => <SelectItem key={item} value={item}>{item.replace('_', ' ').toUpperCase()}</SelectItem>)}</SelectContent></Select>; }
function NetworkChoice({ value, networks, onChange }: { value: string; networks: Network[]; onChange: (value: string) => void }) { return <Select value={value || '__none__'} onValueChange={(next) => onChange(next === '__none__' ? '' : next)}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="__none__">Unassigned</SelectItem>{networks.map((item) => <SelectItem key={item.id} value={item.id}>{item.name}</SelectItem>)}</SelectContent></Select>; }
function InterfaceChoice({ value, interfaces, onChange }: { value: string; interfaces: FirewallInterface[]; onChange: (value: string) => void }) { return <Select value={value || '__any__'} onValueChange={(next) => onChange(next === '__any__' ? '' : next)}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="__any__">Any / unspecified</SelectItem>{interfaces.map((item) => <SelectItem key={item.id} value={item.id}>{item.name}</SelectItem>)}</SelectContent></Select>; }
function RowActions({ onEdit, onDelete }: { onEdit: () => void; onDelete: () => void }) { return <div className="flex"><Button size="sm" variant="ghost" onClick={onEdit}><Pencil size={14} /></Button><Button size="sm" variant="ghost" onClick={onDelete}><Trash2 size={14} className="text-red-500" /></Button></div>; }
function Empty({ columns, text }: { columns: number; text: string }) { return <TableRow><TableCell colSpan={columns} className="py-8 text-center text-slate-400">{text}</TableCell></TableRow>; }
function interfaceName(items: FirewallInterface[], id?: string) { return id ? items.find((item) => item.id === id)?.name ?? 'Missing interface' : 'Any'; }
