import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { DataSet } from 'vis-data';
import { Timeline as VisTimeline } from 'vis-timeline';
import { Clock, Pencil, Plus, Search, ServerCog, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Textarea } from '@/components/ui/textarea';
import type { ApiResponse, Asset, ClockProfile, TimelineEvent, TimePreview } from '@/types';

interface Props { refreshTrigger: number }
interface EventForm {
  assetId: string;
  serverTimestamp: string;
  serverTimezone: string;
  correctTimestamp: string;
  correctTimezone: string;
  clockProfileId: string;
  eventType: string;
  description: string;
  severity: string;
  source: string;
  mitreTactic: string;
  mitreTechnique: string;
}
interface ProfileForm {
  name: string;
  description: string;
  serverReferenceRaw: string;
  serverTimezone: string;
  correctReferenceRaw: string;
  correctTimezone: string;
}

const localTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
const EMPTY_EVENT: EventForm = {
  assetId: '', serverTimestamp: '', serverTimezone: localTimezone,
  correctTimestamp: '', correctTimezone: localTimezone, clockProfileId: '', eventType: 'malware_detection',
  description: '', severity: 'medium', source: '', mitreTactic: '', mitreTechnique: '',
};
const EMPTY_PROFILE: ProfileForm = {
  name: '', description: '', serverReferenceRaw: '', serverTimezone: localTimezone,
  correctReferenceRaw: '', correctTimezone: localTimezone,
};
const EVENT_TYPES = ['malware_detection','suspicious_login','privilege_escalation','lateral_movement','data_exfiltration','persistence','network_connection','file_execution','registry_modification','service_creation','scheduled_task','other'];
const TIMEZONES = Array.from(new Set([
  'UTC', localTimezone, 'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Europe/Moscow',
  'Asia/Novosibirsk', 'Asia/Dubai', 'Asia/Kolkata', 'Asia/Bangkok', 'Asia/Shanghai',
  'Asia/Tokyo', 'Australia/Sydney', 'America/New_York', 'America/Chicago', 'America/Denver',
  'America/Los_Angeles', '+00:00', '+07:00', '-05:00',
]));

export default function TimelineView({ refreshTrigger }: Props) {
  const timelineRef = useRef<HTMLDivElement>(null);
  const timelineInstance = useRef<VisTimeline | null>(null);
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [profiles, setProfiles] = useState<ClockProfile[]>([]);
  const [form, setForm] = useState<EventForm>(EMPTY_EVENT);
  const [showForm, setShowForm] = useState(false);
  const [showProfiles, setShowProfiles] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'timeline' | 'table'>('table');
  const [displayTimezone, setDisplayTimezone] = useState(localTimezone);
  const [search, setSearch] = useState('');
  const [assetFilter, setAssetFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [fromFilter, setFromFilter] = useState('');
  const [toFilter, setToFilter] = useState('');
  const fromPreview = useTimestampPreview(fromFilter, displayTimezone, 0);
  const toPreview = useTimestampPreview(toFilter, displayTimezone, 0);

  const loadData = useCallback(async () => {
    try {
      const [eventResponse, assetResponse, profileResponse] = await Promise.all([
        invoke<ApiResponse<TimelineEvent[]>>('list_timeline_events'),
        invoke<ApiResponse<Asset[]>>('list_assets'),
        invoke<ApiResponse<ClockProfile[]>>('list_clock_profiles'),
      ]);
      if (!eventResponse.success) throw new Error(eventResponse.error || 'Could not load timeline');
      if (!assetResponse.success) throw new Error(assetResponse.error || 'Could not load assets');
      if (!profileResponse.success) throw new Error(profileResponse.error || 'Could not load clock profiles');
      setEvents(eventResponse.data ?? []);
      setAssets(assetResponse.data ?? []);
      setProfiles(profileResponse.data ?? []);
    } catch (reason) { toast.error(String(reason)); }
  }, []);

  useEffect(() => { void loadData(); }, [loadData, refreshTrigger]);

  const filteredEvents = useMemo(() => {
    const term = search.trim().toLowerCase();
    const from = fromPreview.value?.epoch_millis ?? Number.NEGATIVE_INFINITY;
    const to = toPreview.value?.epoch_millis ?? Number.POSITIVE_INFINITY;
    return events.filter((event) => {
      const hasTimeFilter = Boolean(fromFilter.trim() || toFilter.trim());
      const time = event.timestamp ? new Date(event.timestamp).getTime() : Number.NaN;
      return (!hasTimeFilter || (!Number.isNaN(time) && time >= from && time <= to))
        && (assetFilter === 'all' || (assetFilter === '__none__' ? !event.asset_id : event.asset_id === assetFilter))
        && (severityFilter === 'all' || event.severity === severityFilter)
        && (typeFilter === 'all' || event.event_type === typeFilter)
        && (!term || [event.description,event.source,event.mitre_tactic,event.mitre_technique,event.asset_name,event.event_type,event.raw_timestamp,event.clock_profile_name]
          .some((value) => value?.toLowerCase().includes(term)));
    });
  }, [events, search, assetFilter, severityFilter, typeFilter, fromFilter, toFilter, fromPreview.value, toPreview.value]);

  useEffect(() => {
    if (viewMode !== 'timeline' || !timelineRef.current) return;
    timelineInstance.current?.destroy();
    const timedEvents = filteredEvents.filter((event) => event.timestamp);
    if (timedEvents.length === 0) return;
    const items = new DataSet(timedEvents.map((event) => ({
      id: event.id,
      content: `${label(event.event_type)}: ${event.description.slice(0, 60)}`,
      title: `${formatInZone(event.timestamp, displayTimezone)} [${displayTimezone}]\n${formatInZone(event.timestamp, 'UTC')} [UTC]`,
      start: event.timestamp,
      group: event.asset_id ?? '__unassigned__',
      className: `timeline-${event.severity}`,
    })));
    const groupMap = new Map<string, string>();
    timedEvents.forEach((event) => groupMap.set(event.asset_id ?? '__unassigned__', event.asset_name ?? 'Unassigned'));
    const groups = new DataSet([...groupMap].map(([id, content]) => ({ id, content })));
    timelineInstance.current = new VisTimeline(timelineRef.current, items, groups, {
      height: '520px', zoomKey: 'ctrlKey', verticalScroll: true,
    });
    timelineInstance.current.fit();
    return () => { timelineInstance.current?.destroy(); timelineInstance.current = null; };
  }, [filteredEvents, viewMode, displayTimezone]);

  const resetForm = () => { setForm(EMPTY_EVENT); setEditingId(null); setShowForm(false); };
  const startEdit = (event: TimelineEvent) => {
    setEditingId(event.id);
    setShowForm(true);
    setForm({
      assetId: event.asset_id ?? '', serverTimestamp: event.raw_timestamp ?? '',
      serverTimezone: event.raw_timezone ?? localTimezone,
      correctTimestamp: event.correct_timestamp_raw ?? (event.clock_profile_id ? '' : event.timestamp),
      correctTimezone: event.correct_timezone ?? 'UTC', clockProfileId: event.clock_profile_id ?? '',
      eventType: event.event_type, description: event.description, severity: event.severity,
      source: event.source ?? '', mitreTactic: event.mitre_tactic ?? '', mitreTechnique: event.mitre_technique ?? '',
    });
  };
  const saveEvent = async () => {
    try {
      const response = await invoke<ApiResponse<TimelineEvent>>(
        editingId ? 'update_existing_timeline_event' : 'create_new_timeline_event',
        {
          id: editingId, ...form, assetId: form.assetId || null,
          clockProfileId: form.clockProfileId || null, source: form.source || null,
          mitreTactic: form.mitreTactic || null, mitreTechnique: form.mitreTechnique || null,
        },
      );
      if (!response.success) throw new Error(response.error || 'Failed to save event');
      toast.success(editingId ? 'Timeline event updated' : 'Timeline event created');
      resetForm();
      await loadData();
    } catch (reason) { toast.error(String(reason)); }
  };
  const deleteEvent = async (id: string) => {
    if (!confirm('Delete this timeline event? The deletion remains visible in case history.')) return;
    try {
      const response = await invoke<ApiResponse<boolean>>('remove_timeline_event', { id });
      if (!response.success) throw new Error(response.error || 'Could not delete event');
      await loadData();
    } catch (reason) { toast.error(String(reason)); }
  };

  return <div className="space-y-4 p-6">
    <TimezoneOptions />
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div><h2 className="flex items-center gap-2 text-2xl font-bold text-slate-800"><Clock className="text-cyan-600" />Incident Timeline</h2><p className="text-sm text-slate-500">Preserve server log time, correlate incorrect clocks, and normalize evidence to UTC</p></div>
      <div className="flex flex-wrap gap-2">
        <Button variant="outline" onClick={() => setShowProfiles((value) => !value)}><ServerCog size={16} className="mr-2" />Server clocks ({profiles.length})</Button>
        <Select value={viewMode} onValueChange={(value: 'timeline' | 'table') => setViewMode(value)}><SelectTrigger className="w-32"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="table">Table</SelectItem><SelectItem value="timeline">Timeline</SelectItem></SelectContent></Select>
        <Button onClick={() => { resetForm(); setShowForm(true); }} className="bg-cyan-600 hover:bg-cyan-700"><Plus size={16} className="mr-2" />Add Event</Button>
      </div>
    </div>

    {showProfiles && <ClockProfileManager profiles={profiles} onChanged={loadData} />}

    <Card><CardContent className="space-y-3 p-3">
      <div className="grid gap-3 lg:grid-cols-7">
        <div className="relative lg:col-span-2"><Search size={15} className="absolute left-3 top-2.5 text-slate-400" /><Input className="pl-9" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search description, source, MITRE, or raw time…" /></div>
        <FilterSelect value={assetFilter} onChange={setAssetFilter} items={[['all','All assets'],['__none__','Unassigned'],...assets.map((asset):[string,string]=>[asset.id,asset.name])]} />
        <FilterSelect value={severityFilter} onChange={setSeverityFilter} items={[['all','All severities'],...['info','low','medium','high','critical'].map((value):[string,string]=>[value,label(value)])]} />
        <FilterSelect value={typeFilter} onChange={setTypeFilter} items={[['all','All event types'],...EVENT_TYPES.map((value):[string,string]=>[value,label(value)])]} />
        <Input value={fromFilter} onChange={(event) => setFromFilter(event.target.value)} placeholder="From DD-MM-YYYY…" title={fromPreview.error || 'From time'} />
        <Input value={toFilter} onChange={(event) => setToFilter(event.target.value)} placeholder="To DD-MM-YYYY…" title={toPreview.error || 'To time'} />
      </div>
      <div className="flex flex-wrap items-end gap-3">
        <TimezoneField labelText="Display / filter timezone" value={displayTimezone} onChange={setDisplayTimezone} className="w-72" />
        <p className="pb-2 text-xs text-slate-500">24-hour display: DD-MM-YYYY HH:mm:ss.SSS. UTC is always shown beside the selected zone.</p>
      </div>
      {(fromPreview.error || toPreview.error) && <p className="text-xs text-red-600">Filter time: {fromPreview.error || toPreview.error}</p>}
    </CardContent></Card>

    {showForm && <EventEditor form={form} setForm={setForm} assets={assets} profiles={profiles} editing={Boolean(editingId)} onSave={() => void saveEvent()} onCancel={resetForm} />}

    {viewMode === 'timeline' ? <Card><CardContent className="p-4">
      <p className="mb-2 text-xs text-slate-500">The visual axis uses corrected incident times. Events whose correct time is unknown remain available in the table.</p>
      {filteredEvents.some((event) => event.timestamp) ? <div ref={timelineRef} /> : <p className="py-10 text-center text-slate-400">No matching events have a known correct time yet.</p>}
    </CardContent></Card> :
      <Card><CardContent className="p-0"><Table><TableHeader><TableRow><TableHead>Corrected incident time</TableHead><TableHead>Server evidence time</TableHead><TableHead>Asset</TableHead><TableHead>Type / description</TableHead><TableHead>Severity</TableHead><TableHead>Source / MITRE</TableHead><TableHead /></TableRow></TableHeader><TableBody>{filteredEvents.length ? filteredEvents.map((event) => <TableRow key={event.id}>
        <TableCell className="min-w-60 text-xs">{event.timestamp ? <TimestampPair utc={event.timestamp} selectedZone={displayTimezone} /> : <span className="text-slate-500">Unknown — add later</span>}</TableCell>
        <TableCell className="min-w-60 text-xs">{event.server_timestamp_utc ? <><TimestampPair utc={event.server_timestamp_utc} selectedZone={displayTimezone} /><div className="mt-1 text-slate-500">Raw: <span className="font-mono">{event.raw_timestamp}</span> [{event.raw_timezone}] · precision: {event.time_precision}</div></> : <span className="text-slate-500">Unknown — add later</span>}{(event.clock_profile_name || (event.server_timestamp_utc && event.correct_timestamp_raw)) && <div className="mt-1 text-cyan-700">{event.clock_profile_name || 'Direct real-time comparison'}: {formatOffset(event.clock_offset_ms)}</div>}</TableCell>
        <TableCell>{event.asset_name || '—'}</TableCell>
        <TableCell><div>{label(event.event_type)}</div><div className="max-w-sm text-sm text-slate-600">{event.description}</div></TableCell>
        <TableCell><Severity value={event.severity} /></TableCell>
        <TableCell><div>{event.source || '—'}</div><div className="text-xs text-slate-500">{event.mitre_technique || event.mitre_tactic || '—'}</div></TableCell>
        <TableCell><div className="flex"><Button size="sm" variant="ghost" onClick={() => startEdit(event)}><Pencil size={14} /></Button><Button size="sm" variant="ghost" onClick={() => void deleteEvent(event.id)}><Trash2 size={14} className="text-red-500" /></Button></div></TableCell>
      </TableRow>) : <TableRow><TableCell colSpan={7} className="py-10 text-center text-slate-400">No matching events.</TableCell></TableRow>}</TableBody></Table></CardContent></Card>}
  </div>;
}

function EventEditor({ form, setForm, assets, profiles, editing, onSave, onCancel }: {
  form: EventForm; setForm: (value: EventForm) => void; assets: Asset[]; profiles: ClockProfile[];
  editing: boolean; onSave: () => void; onCancel: () => void;
}) {
  const profile = profiles.find((item) => item.id === form.clockProfileId);
  const serverPreview = useTimestampPreview(form.serverTimestamp, form.serverTimezone, 0);
  const correctPreview = useTimestampPreview(form.correctTimestamp, form.correctTimezone, 0);
  const profilePreview = useTimestampPreview(form.serverTimestamp, form.serverTimezone, profile?.offset_ms ?? 0);
  const directOffset = serverPreview.value && correctPreview.value
    ? correctPreview.value.epoch_millis - serverPreview.value.epoch_millis : 0;
  const invalid = Boolean(serverPreview.error || correctPreview.error || (profile && profilePreview.error));
  return <Card className="border-cyan-200"><CardHeader><CardTitle className="text-sm">{editing ? 'Edit timeline event' : 'New timeline event'}</CardTitle></CardHeader><CardContent className="space-y-4">
    <div className="grid gap-4 lg:grid-cols-2">
      <div className="rounded-md border border-slate-200 bg-slate-50 p-3">
        <h4 className="mb-3 text-sm font-semibold">Server / evidence time (optional)</h4>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field text="Timestamp shown by server"><Input value={form.serverTimestamp} onChange={(event) => setForm({ ...form, serverTimestamp: event.target.value })} placeholder="18-07-2026 14:05:03.127, ISO, or Unix epoch" /></Field>
          <TimezoneField labelText="Server timestamp timezone" value={form.serverTimezone} onChange={(serverTimezone) => setForm({ ...form, serverTimezone })} />
        </div>
        <PreviewPanel preview={serverPreview} selectedZone={localTimezone} labelText="Normalized server time" />
      </div>
      <div className="rounded-md border border-cyan-200 bg-cyan-50/50 p-3">
        <h4 className="mb-3 text-sm font-semibold">Known real / correct time (optional)</h4>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field text="Actual timestamp"><Input value={form.correctTimestamp} onChange={(event) => setForm({ ...form, correctTimestamp: event.target.value, clockProfileId: '' })} placeholder="Enter the real time for this event" /></Field>
          <TimezoneField labelText="Actual timestamp timezone" value={form.correctTimezone} onChange={(correctTimezone) => setForm({ ...form, correctTimezone })} />
        </div>
        <PreviewPanel preview={correctPreview} selectedZone={localTimezone} labelText="Normalized correct time" />
        {serverPreview.value && correctPreview.value && <p className="mt-2 text-xs font-medium text-cyan-800">Direct correction: {formatOffset(directOffset)}</p>}
        <div className="mt-3"><Field text="Or apply a saved server correction"><select className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm" value={form.clockProfileId} onChange={(event) => setForm({ ...form, clockProfileId: event.target.value, correctTimestamp: '' })}><option value="">Select a saved profile</option>{profiles.map((item) => <option key={item.id} value={item.id}>{item.name} ({formatOffset(item.offset_ms)})</option>)}</select></Field></div>
        {profile && serverPreview.value && <PreviewPanel preview={profilePreview} selectedZone={localTimezone} labelText={`Corrected using ${profile.name}`} />}
      </div>
    </div>
    <p className="text-xs text-slate-500">Both times may be left unknown and added later. Missing time components are treated as 00. RFC 3339 offsets and Unix epochs override the timezone field.</p>
    <div className="grid gap-3 lg:grid-cols-4">
      <Field text="Asset"><Select value={form.assetId || '__none__'} onValueChange={(value) => setForm({ ...form, assetId: value === '__none__' ? '' : value })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="__none__">None</SelectItem>{assets.map((asset) => <SelectItem key={asset.id} value={asset.id}>{asset.name}</SelectItem>)}</SelectContent></Select></Field>
      <Field text="Type"><Select value={form.eventType} onValueChange={(eventType) => setForm({ ...form, eventType })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{EVENT_TYPES.map((value) => <SelectItem key={value} value={value}>{label(value)}</SelectItem>)}</SelectContent></Select></Field>
      <Field text="Severity"><Select value={form.severity} onValueChange={(severity) => setForm({ ...form, severity })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{['info','low','medium','high','critical'].map((value) => <SelectItem key={value} value={value}>{label(value)}</SelectItem>)}</SelectContent></Select></Field>
      <Field text="Source"><Input value={form.source} onChange={(event) => setForm({ ...form, source: event.target.value })} placeholder="Log, EDR, witness…" /></Field>
    </div>
    <div className="grid gap-3 lg:grid-cols-2"><Field text="MITRE tactic"><Input value={form.mitreTactic} onChange={(event) => setForm({ ...form, mitreTactic: event.target.value })} /></Field><Field text="MITRE technique"><Input value={form.mitreTechnique} onChange={(event) => setForm({ ...form, mitreTechnique: event.target.value })} /></Field></div>
    <Field text="Description *"><Textarea value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} /></Field>
    <div className="flex gap-2"><Button onClick={onSave} disabled={invalid || Boolean(profile && !form.serverTimestamp.trim())} className="bg-cyan-600 hover:bg-cyan-700">Save</Button><Button variant="outline" onClick={onCancel}>Cancel</Button></div>
  </CardContent></Card>;
}

function ClockProfileManager({ profiles, onChanged }: { profiles: ClockProfile[]; onChanged: () => Promise<void> }) {
  const [form, setForm] = useState<ProfileForm>(EMPTY_PROFILE);
  const [editingId, setEditingId] = useState<string | null>(null);
  const serverPreview = useTimestampPreview(form.serverReferenceRaw, form.serverTimezone, 0);
  const correctPreview = useTimestampPreview(form.correctReferenceRaw, form.correctTimezone, 0);
  const calculatedOffset = serverPreview.value && correctPreview.value
    ? correctPreview.value.epoch_millis - serverPreview.value.epoch_millis : 0;
  const reset = () => { setForm(EMPTY_PROFILE); setEditingId(null); };
  const edit = (profile: ClockProfile) => {
    setEditingId(profile.id);
    setForm({
      name: profile.name, description: profile.description,
      serverReferenceRaw: profile.server_reference_raw, serverTimezone: profile.server_timezone,
      correctReferenceRaw: profile.correct_reference_raw, correctTimezone: profile.correct_timezone,
    });
  };
  const save = async () => {
    try {
      const response = await invoke<ApiResponse<ClockProfile>>(
        editingId ? 'update_existing_clock_profile' : 'create_new_clock_profile',
        { id: editingId, ...form },
      );
      if (!response.success) throw new Error(response.error || 'Could not save clock profile');
      toast.success(editingId ? 'Server clock profile updated' : 'Server clock profile created');
      reset();
      await onChanged();
    } catch (reason) { toast.error(String(reason)); }
  };
  const remove = async (id: string) => {
    if (!confirm('Delete this server clock profile?')) return;
    try {
      const response = await invoke<ApiResponse<boolean>>('remove_clock_profile', { id });
      if (!response.success) throw new Error(response.error || 'Could not delete clock profile');
      reset();
      await onChanged();
    } catch (reason) { toast.error(String(reason)); }
  };
  return <Card className="border-indigo-200"><CardHeader><CardTitle className="flex items-center gap-2 text-base"><ServerCog size={18} />Server clock correlation</CardTitle></CardHeader><CardContent className="space-y-4">
    <p className="text-sm text-slate-600">Capture one server clock reading and the known-correct investigator/reference time for the same instant. The calculated offset can then correct every event from that server.</p>
    <div className="grid gap-3 lg:grid-cols-2"><Field text="Profile / server name *"><Input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="DC01 incorrect clock" /></Field><Field text="Description"><Input value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} placeholder="How the comparison was established" /></Field></div>
    <div className="grid gap-4 lg:grid-cols-2">
      <div className="rounded-md border p-3"><h4 className="mb-3 text-sm font-semibold">Server time shown</h4><div className="grid gap-3 sm:grid-cols-2"><Field text="Server reference timestamp"><Input value={form.serverReferenceRaw} onChange={(event) => setForm({ ...form, serverReferenceRaw: event.target.value })} placeholder="18-07-2026 09:30:00.000" /></Field><TimezoneField labelText="Server timezone" value={form.serverTimezone} onChange={(serverTimezone) => setForm({ ...form, serverTimezone })} /></div><PreviewPanel preview={serverPreview} selectedZone={localTimezone} labelText="Normalized server time" /></div>
      <div className="rounded-md border p-3"><h4 className="mb-3 text-sm font-semibold">Known-correct time at same instant</h4><div className="grid gap-3 sm:grid-cols-2"><Field text="Correct reference timestamp"><Input value={form.correctReferenceRaw} onChange={(event) => setForm({ ...form, correctReferenceRaw: event.target.value })} placeholder="18-07-2026 10:47:12.500" /></Field><TimezoneField labelText="Correct timezone" value={form.correctTimezone} onChange={(correctTimezone) => setForm({ ...form, correctTimezone })} /></div><PreviewPanel preview={correctPreview} selectedZone={localTimezone} labelText="Normalized correct time" /></div>
    </div>
    <div className="flex flex-wrap items-center gap-3 rounded-md bg-indigo-50 p-3"><strong>Calculated correction: {formatOffset(calculatedOffset)}</strong><span className="text-xs text-slate-600">correct UTC − interpreted server UTC</span></div>
    <div className="flex gap-2"><Button onClick={() => void save()} disabled={!form.name.trim() || !serverPreview.value || !correctPreview.value} className="bg-indigo-600 hover:bg-indigo-700">{editingId ? 'Update profile' : 'Create profile'}</Button>{editingId && <Button variant="outline" onClick={reset}>Cancel</Button>}</div>
    {profiles.length > 0 && <Table><TableHeader><TableRow><TableHead>Profile</TableHead><TableHead>Server reference</TableHead><TableHead>Correct reference</TableHead><TableHead>Correction</TableHead><TableHead /></TableRow></TableHeader><TableBody>{profiles.map((profile) => <TableRow key={profile.id}><TableCell><div className="font-medium">{profile.name}</div><div className="text-xs text-slate-500">{profile.description}</div></TableCell><TableCell className="font-mono text-xs">{profile.server_reference_raw}<div className="text-slate-500">{profile.server_timezone}</div></TableCell><TableCell className="font-mono text-xs">{profile.correct_reference_raw}<div className="text-slate-500">{profile.correct_timezone}</div></TableCell><TableCell>{formatOffset(profile.offset_ms)}</TableCell><TableCell><div className="flex"><Button size="sm" variant="ghost" onClick={() => edit(profile)}><Pencil size={14} /></Button><Button size="sm" variant="ghost" onClick={() => void remove(profile.id)}><Trash2 size={14} className="text-red-500" /></Button></div></TableCell></TableRow>)}</TableBody></Table>}
  </CardContent></Card>;
}

function useTimestampPreview(input: string, timezone: string, offsetMs: number) {
  const requestKey = `${input}\u0000${timezone}\u0000${offsetMs}`;
  const [state, setState] = useState<{ key?: string; value?: TimePreview; error?: string }>({});
  useEffect(() => {
    if (!input.trim()) return;
    let active = true;
    const timer = window.setTimeout(async () => {
      try {
        const response = await invoke<ApiResponse<TimePreview>>('preview_timestamp', { input, timezone, offsetMs });
        if (!active) return;
        setState(response.success && response.data ? { key: requestKey, value: response.data } : { key: requestKey, error: response.error || 'Invalid timestamp' });
      } catch (reason) { if (active) setState({ key: requestKey, error: String(reason) }); }
    }, 180);
    return () => { active = false; window.clearTimeout(timer); };
  }, [input, timezone, offsetMs, requestKey]);
  return input.trim() && state.key === requestKey ? state : {};
}

function PreviewPanel({ preview, selectedZone, labelText = 'Normalized time' }: { preview: { value?: TimePreview; error?: string }; selectedZone: string; labelText?: string }) {
  if (preview.error) return <p className="mt-2 text-xs text-red-600">{preview.error}</p>;
  if (!preview.value) return null;
  return <div className="mt-2 rounded bg-white p-2 text-xs"><div className="mb-1 text-slate-500">{labelText} · precision: {preview.value.precision}{preview.value.used_embedded_timezone ? ' · embedded offset/epoch used' : ''}</div><TimestampPair utc={preview.value.corrected_utc} selectedZone={selectedZone} /></div>;
}

function TimestampPair({ utc, selectedZone }: { utc: string; selectedZone: string }) {
  const primaryZone = selectedZone || localTimezone;
  const counterpart = isUtc(primaryZone) ? localTimezone : 'UTC';
  return <div className="space-y-0.5 font-mono"><div>{formatInZone(utc, primaryZone)} <span className="font-sans text-slate-500">[{primaryZone}]</span></div>{counterpart !== primaryZone && <div className="text-slate-500">{formatInZone(utc, counterpart)} <span className="font-sans">[{counterpart}]</span></div>}</div>;
}

function formatInZone(value: string, timezone: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const fixed = parseFixedOffset(timezone);
  const displayDate = fixed === null ? date : new Date(date.getTime() + fixed * 60_000);
  const targetZone = fixed === null ? timezone : 'UTC';
  try {
    const parts = new Intl.DateTimeFormat('en-GB', {
      timeZone: targetZone, day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit',
      minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3, hourCycle: 'h23',
    }).formatToParts(displayDate);
    const get = (type: Intl.DateTimeFormatPartTypes) => parts.find((part) => part.type === type)?.value ?? '00';
    return `${get('day')}-${get('month')}-${get('year')} ${get('hour')}:${get('minute')}:${get('second')}.${get('fractionalSecond')}`;
  } catch { return formatInZone(value, 'UTC'); }
}

function parseFixedOffset(value: string) {
  const match = value.trim().match(/^(?:UTC)?([+-])(\d{1,2})(?::(\d{2}))?$/i);
  if (!match) return null;
  const minutes = Number(match[2]) * 60 + Number(match[3] || 0);
  return match[1] === '-' ? -minutes : minutes;
}
function isUtc(value: string) { return value.trim().toUpperCase() === 'UTC' || value.trim() === 'Z' || parseFixedOffset(value) === 0; }
function formatOffset(milliseconds: number) {
  const sign = milliseconds < 0 ? '−' : '+';
  const absolute = Math.abs(milliseconds);
  const hours = Math.floor(absolute / 3_600_000);
  const minutes = Math.floor((absolute % 3_600_000) / 60_000);
  const seconds = Math.floor((absolute % 60_000) / 1_000);
  const millis = absolute % 1_000;
  return `${sign}${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}.${String(millis).padStart(3, '0')}`;
}
function TimezoneOptions() { return <datalist id="dfir-timezones">{TIMEZONES.map((timezone) => <option key={timezone} value={timezone} />)}</datalist>; }
function TimezoneField({ labelText, value, onChange, className = '' }: { labelText: string; value: string; onChange: (value: string) => void; className?: string }) { return <Field text={labelText} className={className}><Input list="dfir-timezones" value={value} onChange={(event) => onChange(event.target.value)} placeholder="UTC, +07:00, or IANA zone" /></Field>; }
function FilterSelect({ value, onChange, items }: { value: string; onChange: (value: string) => void; items: [string,string][] }) { return <Select value={value} onValueChange={onChange}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{items.map(([id,text]) => <SelectItem key={id} value={id}>{text}</SelectItem>)}</SelectContent></Select>; }
function Field({ text, children, className = '' }: { text: string; children: React.ReactNode; className?: string }) { return <div className={`space-y-1 ${className}`}><Label>{text}</Label>{children}</div>; }
function label(value: string) { return value.replaceAll('_',' ').replace(/^./,(character)=>character.toUpperCase()); }
function Severity({ value }: { value: string }) { const color = value === 'critical' ? 'bg-red-500' : value === 'high' ? 'bg-orange-500' : value === 'medium' ? 'bg-amber-500' : value === 'low' ? 'bg-blue-400' : 'bg-slate-400'; return <span className={`rounded px-2 py-1 text-xs text-white ${color}`}>{value}</span>; }
