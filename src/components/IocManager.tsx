import { useCallback, useEffect, useMemo, useState } from 'react';
import { downloadText, invoke } from '@/lib/api';
import { Download, Pencil, Plus, Search, ShieldAlert, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Textarea } from '@/components/ui/textarea';
import type { ApiResponse, Ioc } from '@/types';

interface Props { refreshTrigger: number }
interface FormState { iocType: string; value: string; description: string; threatLevel: string; firstSeen: string; lastSeen: string }
const EMPTY: FormState = { iocType: 'IP', value: '', description: '', threatLevel: 'medium', firstSeen: '', lastSeen: '' };

export default function IocManager({ refreshTrigger }: Props) {
  const [iocs, setIocs] = useState<Ioc[]>([]);
  const [form, setForm] = useState<FormState>(EMPTY);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [threatFilter, setThreatFilter] = useState('all');

  const loadIocs = useCallback(async () => {
    try {
      const response = await invoke<ApiResponse<Ioc[]>>('list_iocs');
      if (!response.success) throw new Error(response.error || 'Could not load IOCs');
      setIocs(response.data ?? []);
    } catch (reason) { toast.error(String(reason)); }
  }, []);
  useEffect(() => { void loadIocs(); }, [loadIocs, refreshTrigger]);

  const reset = () => { setForm(EMPTY); setEditingId(null); setShowForm(false); };
  const edit = (ioc: Ioc) => {
    setEditingId(ioc.id); setShowForm(true);
    setForm({ iocType: ioc.ioc_type, value: ioc.value, description: ioc.description, threatLevel: ioc.threat_level,
      firstSeen: toLocalInput(ioc.first_seen), lastSeen: toLocalInput(ioc.last_seen) });
  };
  const save = async () => {
    if (!form.value.trim()) { toast.error('IOC value is required'); return; }
    try {
      const response = await invoke<ApiResponse<Ioc>>(editingId ? 'update_existing_ioc' : 'create_new_ioc', {
        id: editingId, ...form, value: form.value.trim(), description: form.description.trim(),
        firstSeen: toUtc(form.firstSeen), lastSeen: toUtc(form.lastSeen),
      });
      if (!response.success) throw new Error(response.error || 'Could not save IOC');
      toast.success(editingId ? 'IOC updated' : 'IOC created'); reset(); await loadIocs();
    } catch (reason) { toast.error(String(reason)); }
  };
  const remove = async (id: string) => {
    if (!confirm('Delete this IOC?')) return;
    try { const response = await invoke<ApiResponse<boolean>>('remove_ioc', { id }); if (!response.success) throw new Error(response.error || 'Could not delete IOC'); await loadIocs(); }
    catch (reason) { toast.error(String(reason)); }
  };

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    return iocs.filter((ioc) => (typeFilter === 'all' || ioc.ioc_type === typeFilter)
      && (threatFilter === 'all' || ioc.threat_level === threatFilter)
      && (!term || [ioc.value, ioc.description, ioc.ioc_type].some((value) => value.toLowerCase().includes(term))));
  }, [iocs, search, typeFilter, threatFilter]);

  // Push the currently visible indicators outward. CSV for SIEM/EDR/firewall
  // imports; STIX 2.1 for a threat-intel platform. The server formats the set
  // of ids we send, so "filter, then export" gives the analyst exactly the
  // indicators they chose.
  const exportIocs = async (format: 'csv' | 'stix') => {
    if (filtered.length === 0) { toast.error('No IOCs to export'); return; }
    try {
      const command = format === 'csv' ? 'export_iocs_csv' : 'export_iocs_stix';
      const response = await invoke<ApiResponse<string>>(command, { ids: filtered.map((ioc) => ioc.id) });
      if (!response.success || response.data === undefined) throw new Error(response.error || 'Export failed');
      const date = new Date().toISOString().slice(0, 10);
      downloadText(format === 'csv' ? `iocs-${date}.csv` : `iocs-${date}.stix.json`, response.data);
      toast.success(`Exported ${filtered.length} IOC${filtered.length === 1 ? '' : 's'} as ${format.toUpperCase()}`);
    } catch (reason) { toast.error(String(reason)); }
  };

  return <div className="space-y-4 p-6">
    <div className="flex items-center justify-between"><div><h2 className="flex items-center gap-2 text-2xl font-bold text-slate-800"><ShieldAlert className="text-cyan-600" />Indicators of Compromise</h2><p className="text-sm text-slate-500">Search, validate, and version IOC findings</p></div><div className="flex gap-2"><Button variant="outline" disabled={filtered.length === 0} onClick={() => void exportIocs('csv')} title="Download the visible IOCs as CSV"><Download size={16} className="mr-2" />Export CSV</Button><Button variant="outline" disabled={filtered.length === 0} onClick={() => void exportIocs('stix')} title="Download the visible IOCs as a STIX 2.1 bundle"><Download size={16} className="mr-2" />Export STIX</Button><Button onClick={() => { reset(); setShowForm(true); }} className="bg-cyan-600 hover:bg-cyan-700"><Plus size={16} className="mr-2" />Add IOC</Button></div></div>
    <Card><CardContent className="flex flex-wrap gap-3 p-3"><div className="relative min-w-64 flex-1"><Search size={15} className="absolute left-3 top-2.5 text-slate-400" /><Input className="pl-9" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search value, type, or description…" /></div><Filter value={typeFilter} onChange={setTypeFilter} values={['all','IP','Hash','Domain','URL','Email','Registry','Mutex']} /><Filter value={threatFilter} onChange={setThreatFilter} values={['all','low','medium','high','critical']} /></CardContent></Card>
    {showForm && <IocForm form={form} setForm={setForm} editing={Boolean(editingId)} onSave={() => void save()} onCancel={reset} />}
    <Card><CardContent className="p-0"><Table><TableHeader><TableRow><TableHead>Type</TableHead><TableHead>Value</TableHead><TableHead>Threat</TableHead><TableHead>Description</TableHead><TableHead>First seen</TableHead><TableHead>Last seen</TableHead><TableHead /></TableRow></TableHeader><TableBody>
      {filtered.length === 0 ? <TableRow><TableCell colSpan={7} className="py-10 text-center text-slate-400">No matching IOCs.</TableCell></TableRow> : filtered.map((ioc) => <TableRow key={ioc.id}><TableCell><span className={`rounded px-2 py-0.5 text-xs ${typeColor(ioc.ioc_type)}`}>{ioc.ioc_type}</span></TableCell><TableCell className="max-w-xs truncate font-mono text-xs">{ioc.value}</TableCell><TableCell><span className={`rounded px-2 py-0.5 text-xs text-white ${threatColor(ioc.threat_level)}`}>{ioc.threat_level}</span></TableCell><TableCell className="max-w-xs truncate text-xs">{ioc.description || '—'}</TableCell><TableCell className="text-xs">{displayTime(ioc.first_seen)}</TableCell><TableCell className="text-xs">{displayTime(ioc.last_seen)}</TableCell><TableCell className="whitespace-nowrap"><Button variant="ghost" size="sm" onClick={() => edit(ioc)}><Pencil size={14} /></Button><Button variant="ghost" size="sm" onClick={() => void remove(ioc.id)}><Trash2 size={14} className="text-red-500" /></Button></TableCell></TableRow>)}
    </TableBody></Table></CardContent></Card>
  </div>;
}

function IocForm({ form, setForm, editing, onSave, onCancel }: { form: FormState; setForm: React.Dispatch<React.SetStateAction<FormState>>; editing: boolean; onSave: () => void; onCancel: () => void }) {
  const update = (key: keyof FormState, value: string) => setForm((current) => ({ ...current, [key]: value }));
  return <Card><CardHeader><CardTitle className="text-sm">{editing ? 'Edit IOC' : 'New IOC'}</CardTitle></CardHeader><CardContent className="space-y-3">
    <div className="grid gap-3 md:grid-cols-3"><Field label="Type"><Select value={form.iocType} onValueChange={(value) => update('iocType', value)}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{['IP','Hash','Domain','URL','Email','Registry','Mutex'].map((value) => <SelectItem key={value} value={value}>{value}</SelectItem>)}</SelectContent></Select></Field><Field label="Threat"><Select value={form.threatLevel} onValueChange={(value) => update('threatLevel', value)}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{['low','medium','high','critical'].map((value) => <SelectItem key={value} value={value}>{value}</SelectItem>)}</SelectContent></Select></Field><Field label="Value *"><Input value={form.value} onChange={(event) => update('value', event.target.value)} /></Field></div>
    <div className="grid gap-3 md:grid-cols-2"><Field label="First seen (local time)"><Input type="datetime-local" value={form.firstSeen} onChange={(event) => update('firstSeen', event.target.value)} /></Field><Field label="Last seen (local time)"><Input type="datetime-local" value={form.lastSeen} onChange={(event) => update('lastSeen', event.target.value)} /></Field></div>
    <Field label="Description"><Textarea rows={2} value={form.description} onChange={(event) => update('description', event.target.value)} /></Field>
    <div className="flex gap-2"><Button onClick={onSave}>{editing ? 'Update' : 'Save'}</Button><Button variant="outline" onClick={onCancel}>Cancel</Button></div>
  </CardContent></Card>;
}
function Field({ label, children }: { label: string; children: React.ReactNode }) { return <div className="space-y-1"><Label>{label}</Label>{children}</div>; }
function Filter({ value, onChange, values }: { value: string; onChange: (value: string) => void; values: string[] }) { return <Select value={value} onValueChange={onChange}><SelectTrigger className="w-40"><SelectValue /></SelectTrigger><SelectContent>{values.map((item) => <SelectItem key={item} value={item}>{item === 'all' ? 'All' : item}</SelectItem>)}</SelectContent></Select>; }
function toUtc(value: string) { return value ? new Date(value).toISOString() : null; }
function toLocalInput(value?: string) { if (!value) return ''; const date = new Date(value); const offset = date.getTimezoneOffset() * 60_000; return new Date(date.getTime() - offset).toISOString().slice(0, 16); }
function displayTime(value?: string) { if (!value) return '—'; const date = new Date(value); return Number.isNaN(date.valueOf()) ? value : date.toLocaleString(); }
function typeColor(type: string) { return type === 'IP' ? 'bg-blue-100 text-blue-700' : type === 'Hash' ? 'bg-red-100 text-red-700' : type === 'Domain' ? 'bg-green-100 text-green-700' : 'bg-purple-100 text-purple-700'; }
function threatColor(level: string) { return level === 'critical' ? 'bg-red-600' : level === 'high' ? 'bg-orange-500' : level === 'medium' ? 'bg-amber-500' : 'bg-blue-500'; }
