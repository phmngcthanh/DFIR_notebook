import { useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { AlertTriangle, CheckCircle2, Clock, FileText, GitGraph, KeyRound, Network, Pencil, Server, ShieldAlert } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import type { ApiResponse, Asset, Case, Firewall, Ioc, Network as NetworkType, Note, TimelineEvent } from '@/types';

interface Props { refreshTrigger: number; onCaseUpdated: () => void }
interface Stats { networks: number; assets: number; infectedAssets: number; incompleteAssets: number; timelineEvents: number; criticalEvents: number; iocs: number; notes: number; firewalls: number }
const EMPTY_STATS: Stats = { networks: 0, assets: 0, infectedAssets: 0, incompleteAssets: 0, timelineEvents: 0, criticalEvents: 0, iocs: 0, notes: 0, firewalls: 0 };

export default function Dashboard({ refreshTrigger, onCaseUpdated }: Props) {
  const [stats, setStats] = useState<Stats>(EMPTY_STATS);
  const [recentEvents, setRecentEvents] = useState<TimelineEvent[]>([]);
  const [caseInfo, setCaseInfo] = useState<Case | null>(null);
  const [editing, setEditing] = useState(false);
  const [caseForm, setCaseForm] = useState({ name: '', description: '', clientName: '', status: 'active' });
  const [passwordForm, setPasswordForm] = useState({ currentPassword: '', newPassword: '', confirmation: '' });
  const [changingPassword, setChangingPassword] = useState(false);

  const loadStats = useCallback(async () => {
    try {
      const [caseRes, networkRes, assetRes, eventRes, iocRes, noteRes, firewallRes] = await Promise.all([
        invoke<ApiResponse<Case | null>>('get_current_case_info'), invoke<ApiResponse<NetworkType[]>>('list_networks'), invoke<ApiResponse<Asset[]>>('list_assets'),
        invoke<ApiResponse<TimelineEvent[]>>('list_timeline_events'), invoke<ApiResponse<Ioc[]>>('list_iocs'), invoke<ApiResponse<Note[]>>('list_notes'), invoke<ApiResponse<Firewall[]>>('list_firewalls'),
      ]);
      for (const response of [caseRes, networkRes, assetRes, eventRes, iocRes, noteRes, firewallRes]) if (!response.success) throw new Error(response.error || 'Dashboard query failed');
      const assets = assetRes.data ?? []; const events = eventRes.data ?? []; const currentCase = caseRes.data ?? null;
      setCaseInfo(currentCase);
      setStats({ networks: (networkRes.data ?? []).length, assets: assets.length,
        infectedAssets: assets.filter((item) => item.compromise_status === 'infected' || item.compromise_status === 'suspected').length,
        incompleteAssets: assets.filter((item) => item.investigation_status !== 'completed').length,
        timelineEvents: events.length, criticalEvents: events.filter((item) => item.severity === 'critical').length,
        iocs: (iocRes.data ?? []).length, notes: (noteRes.data ?? []).length, firewalls: (firewallRes.data ?? []).length });
      setRecentEvents([...events].sort((a, b) => b.timestamp.localeCompare(a.timestamp)).slice(0, 10));
    } catch (reason) { toast.error(String(reason)); }
  }, []);
  useEffect(() => { void loadStats(); }, [loadStats, refreshTrigger]);

  const toggleEditing = () => {
    if (!editing && caseInfo) setCaseForm({ name: caseInfo.name, description: caseInfo.description, clientName: caseInfo.client_name, status: caseInfo.status });
    setEditing((value) => !value);
  };

  const saveCase = async () => {
    try {
      const response = await invoke<ApiResponse<Case>>('update_current_case', caseForm);
      if (!response.success) throw new Error(response.error || 'Could not update case');
      setCaseInfo(response.data ?? caseInfo); setEditing(false); onCaseUpdated(); toast.success('Case metadata updated');
    } catch (reason) { toast.error(String(reason)); }
  };
  const changeDatabasePassword = async () => {
    if ([...passwordForm.newPassword].length < 6) {
      toast.error('New database password must contain at least 6 characters');
      return;
    }
    if (passwordForm.newPassword !== passwordForm.confirmation) {
      toast.error('New database passwords do not match');
      return;
    }
    setChangingPassword(true);
    try {
      const response = await invoke<ApiResponse<boolean>>('change_database_password', {
        currentPassword: passwordForm.currentPassword,
        newPassword: passwordForm.newPassword,
      });
      if (!response.success) throw new Error(response.error || 'Could not change database password');
      toast.success('Database file password changed');
    } catch (reason) {
      toast.error(String(reason));
    } finally {
      setPasswordForm({ currentPassword: '', newPassword: '', confirmation: '' });
      setChangingPassword(false);
    }
  };
  const statCards = [
    ['Networks', stats.networks, <Network size={20} />, 'bg-blue-50 text-blue-600'], ['Assets', stats.assets, <Server size={20} />, 'bg-green-50 text-green-600'],
    ['Suspected / infected', stats.infectedAssets, <AlertTriangle size={20} />, 'bg-red-50 text-red-600'], ['Not completed', stats.incompleteAssets, <Clock size={20} />, 'bg-amber-50 text-amber-600'],
    ['Timeline events', stats.timelineEvents, <Clock size={20} />, 'bg-purple-50 text-purple-600'], ['Critical events', stats.criticalEvents, <CheckCircle2 size={20} />, 'bg-rose-50 text-rose-600'],
    ['IOCs', stats.iocs, <ShieldAlert size={20} />, 'bg-orange-50 text-orange-600'], ['Notes / firewalls', `${stats.notes} / ${stats.firewalls}`, <FileText size={20} />, 'bg-cyan-50 text-cyan-600'],
  ];

  return <div className="space-y-6 p-6">
    <div className="flex items-start justify-between"><div><h2 className="text-2xl font-bold text-slate-800">Investigation Dashboard</h2><p className="text-sm text-slate-500">Full-case counts and latest evidence</p></div><Button variant="outline" size="sm" onClick={toggleEditing}><Pencil size={14} className="mr-2" />Case metadata</Button></div>
    {editing && <Card><CardHeader><CardTitle className="text-sm">Edit case metadata</CardTitle></CardHeader><CardContent className="space-y-3"><div className="grid gap-3 md:grid-cols-3"><Field label="Case name"><Input value={caseForm.name} onChange={(event) => setCaseForm((value) => ({ ...value, name: event.target.value }))} /></Field><Field label="Client"><Input value={caseForm.clientName} onChange={(event) => setCaseForm((value) => ({ ...value, clientName: event.target.value }))} /></Field><Field label="Status"><Select value={caseForm.status} onValueChange={(status) => setCaseForm((value) => ({ ...value, status }))}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{['active','closed','archived'].map((value) => <SelectItem key={value} value={value}>{value}</SelectItem>)}</SelectContent></Select></Field></div><Field label="Description"><Textarea rows={2} value={caseForm.description} onChange={(event) => setCaseForm((value) => ({ ...value, description: event.target.value }))} /></Field><p className="text-xs text-slate-500">Session expert names provide change attribution. Changing the case name does not rename the SQLite file.</p><Button onClick={() => void saveCase()}>Save case</Button></CardContent></Card>}
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">{statCards.map(([label, value, icon, color]) => <Card key={String(label)}><CardContent className="flex items-center gap-3 p-4"><div className={`rounded-lg p-2 ${color}`}>{icon}</div><div><p className="text-2xl font-bold text-slate-800">{value}</p><p className="text-xs text-slate-500">{label}</p></div></CardContent></Card>)}</div>
    <div className="grid gap-6 xl:grid-cols-2"><Card><CardHeader><CardTitle className="text-sm">Recent timeline events</CardTitle></CardHeader><CardContent className="max-h-96 overflow-auto">{recentEvents.length === 0 ? <p className="py-8 text-center text-sm text-slate-400">No events yet</p> : <div className="space-y-2">{recentEvents.map((event) => <div key={event.id} className="rounded bg-slate-50 p-3 text-xs"><div className="flex items-center gap-2"><span className={`rounded px-2 py-0.5 text-white ${severityColor(event.severity)}`}>{event.severity}</span><span className="text-slate-500">{displayTime(event.timestamp)}</span></div><p className="mt-1 text-slate-800">{event.description}</p>{event.asset_name && <p className="text-slate-500">Asset: {event.asset_name}</p>}</div>)}</div>}</CardContent></Card>
      <Card><CardHeader><CardTitle className="flex items-center gap-2 text-sm"><GitGraph size={16} />Lean offline workflow</CardTitle></CardHeader><CardContent className="space-y-3 text-sm text-slate-600"><p>Document zones and connections, record PC/NIC configuration and investigation status, then place evidence on the timeline.</p><p>Each edit is committed locally with the entered expert name. At the team meeting, load change bundles under <strong>Expert Merge</strong>, compare each field, accept agreed edits, and mark the merged master as the next shared baseline.</p><p className="rounded bg-slate-50 p-3 text-xs">No server, account system, or database service is involved. The open case is one local encrypted SQLite file.</p></CardContent></Card></div>
    <Card><CardHeader><CardTitle className="flex items-center gap-2 text-sm"><KeyRound size={16} />Database file security</CardTitle></CardHeader><CardContent className="space-y-4"><p className="text-sm text-slate-600">Change the password for this physical database copy. It is independent of the expert name, logical case identity, and optional export password.</p><div className="grid gap-3 md:grid-cols-3"><Field label="Current password"><Input type="password" autoComplete="current-password" value={passwordForm.currentPassword} onChange={(event) => setPasswordForm((value) => ({ ...value, currentPassword: event.target.value }))} /></Field><Field label="New password"><Input type="password" autoComplete="new-password" value={passwordForm.newPassword} onChange={(event) => setPasswordForm((value) => ({ ...value, newPassword: event.target.value }))} /></Field><Field label="Confirm new password"><Input type="password" autoComplete="new-password" value={passwordForm.confirmation} onChange={(event) => setPasswordForm((value) => ({ ...value, confirmation: event.target.value }))} /></Field></div><div className="flex flex-wrap items-center justify-between gap-3"><p className="text-xs text-slate-500">Powered by SQLCipher Community Edition (Zetetic LLC, BSD-style license). The encrypted database has authenticated pages; retain separate backups.</p><Button onClick={() => void changeDatabasePassword()} disabled={changingPassword || !passwordForm.currentPassword || !passwordForm.newPassword}>{changingPassword ? 'Changing...' : 'Change database password'}</Button></div></CardContent></Card>
  </div>;
}
function Field({ label, children }: { label: string; children: React.ReactNode }) { return <div className="space-y-1"><Label>{label}</Label>{children}</div>; }
function displayTime(value: string) { if (!value.trim()) return 'Correct time unknown'; const date = new Date(value); return Number.isNaN(date.valueOf()) ? value : date.toLocaleString(); }
function severityColor(value: string) { return value === 'critical' ? 'bg-red-600' : value === 'high' ? 'bg-orange-500' : value === 'medium' ? 'bg-amber-500' : 'bg-blue-500'; }
