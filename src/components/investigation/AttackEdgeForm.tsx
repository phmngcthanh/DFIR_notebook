import { useState } from 'react';
import { invoke } from '@/lib/api';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import type {
  ApiResponse, Asset, AttackEdge, AttackEdgeConfidence, AttackEdgeSourceKind, AttackEdgeType,
  Firewall, Ioc, Network, SightingEntityKind, TimelineEvent,
} from '@/types';

export interface EndpointRef {
  kind: AttackEdgeSourceKind;
  id: string;
}

interface Props {
  edge?: AttackEdge;
  prefill?: { source?: EndpointRef; target?: { kind: SightingEntityKind; id: string } };
  networks: Network[];
  assets: Asset[];
  firewalls: Firewall[];
  iocs: Ioc[];
  timelineEvents: TimelineEvent[];
  onSaved: () => void;
  onCancel: () => void;
}

const EDGE_TYPES: AttackEdgeType[] = ['initial_access', 'lateral_movement', 'privilege_escalation', 'persistence', 'c2', 'exfiltration', 'other'];
const CONFIDENCE: AttackEdgeConfidence[] = ['confirmed', 'probable', 'suspected'];
const NONE = '__none__';

export default function AttackEdgeForm({ edge, prefill, networks, assets, firewalls, iocs, timelineEvents, onSaved, onCancel }: Props) {
  const [sourceKind, setSourceKind] = useState<AttackEdgeSourceKind>(edge?.source_kind ?? prefill?.source?.kind ?? 'external');
  const [sourceId, setSourceId] = useState(edge?.source_id ?? prefill?.source?.id ?? (prefill?.source?.kind ? prefill.source.id : 'Internet'));
  const [targetKind, setTargetKind] = useState<SightingEntityKind>(edge?.target_kind ?? prefill?.target?.kind ?? 'asset');
  const [targetId, setTargetId] = useState(edge?.target_id ?? prefill?.target?.id ?? '');
  const [title, setTitle] = useState(edge?.title ?? '');
  const [description, setDescription] = useState(edge?.description ?? '');
  const [edgeType, setEdgeType] = useState<AttackEdgeType>(edge?.edge_type ?? 'lateral_movement');
  const [confidence, setConfidence] = useState<AttackEdgeConfidence>(edge?.confidence ?? 'suspected');
  const [mitreTactic, setMitreTactic] = useState(edge?.mitre_tactic ?? '');
  const [mitreTechnique, setMitreTechnique] = useState(edge?.mitre_technique ?? '');
  const [occurredAt, setOccurredAt] = useState(edge?.occurred_at ? toLocalInput(edge.occurred_at) : '');
  const [timelineEventId, setTimelineEventId] = useState(edge?.timeline_event_id ?? NONE);
  const [sequence, setSequence] = useState(edge ? String(edge.sequence) : '');
  const [iocIds, setIocIds] = useState<string[]>(edge?.ioc_ids ?? []);
  const [saving, setSaving] = useState(false);

  const entityOptions = (kind: string) => kind === 'asset'
    ? assets.map((item) => ({ id: item.id, label: `${item.name} (${item.ip_address || 'no IP'})` }))
    : kind === 'network'
      ? networks.map((item) => ({ id: item.id, label: `${item.name} (${item.subnet})` }))
      : firewalls.map((item) => ({ id: item.id, label: item.name }));

  const save = async () => {
    if (!title.trim()) { toast.error('Attack edge title is required'); return; }
    if (!targetId) { toast.error('Select a target entity'); return; }
    if (sourceKind !== 'external' && !sourceId) { toast.error('Select a source entity'); return; }
    setSaving(true);
    try {
      const payload = {
        sourceKind, sourceId, targetKind, targetId,
        title: title.trim(), description: description.trim(),
        edgeType, confidence,
        mitreTactic: mitreTactic.trim() || null,
        mitreTechnique: mitreTechnique.trim() || null,
        occurredAt: occurredAt ? new Date(occurredAt).toISOString() : null,
        timelineEventId: timelineEventId === NONE ? null : timelineEventId,
        sequence: sequence.trim() === '' ? (edge ? edge.sequence : null) : Number(sequence),
        iocIds,
      };
      const response = edge
        ? await invoke<ApiResponse<AttackEdge>>('update_existing_attack_edge', { id: edge.id, ...payload, sequence: payload.sequence ?? 0 })
        : await invoke<ApiResponse<AttackEdge>>('create_new_attack_edge', payload);
      if (!response.success) throw new Error(response.error || 'Could not save attack edge');
      toast.success(edge ? 'Attack edge updated' : 'Attack edge recorded');
      onSaved();
    } catch (reason) { toast.error(String(reason)); } finally { setSaving(false); }
  };

  const remove = async () => {
    if (!edge || !confirm('Delete this attack edge?')) return;
    try {
      const response = await invoke<ApiResponse<boolean>>('remove_attack_edge', { id: edge.id });
      if (!response.success) throw new Error(response.error || 'Could not delete attack edge');
      toast.success('Attack edge deleted');
      onSaved();
    } catch (reason) { toast.error(String(reason)); }
  };

  const toggleIoc = (id: string) => setIocIds((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id]);

  return <Card>
    <CardHeader><CardTitle className="text-sm">{edge ? 'Edit attack edge' : 'Draw attack edge'}</CardTitle></CardHeader>
    <CardContent className="space-y-3 text-sm">
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1"><Label>From</Label>
          <Select value={sourceKind} onValueChange={(value) => { setSourceKind(value as AttackEdgeSourceKind); setSourceId(value === 'external' ? 'Internet' : ''); }}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>{['external', 'asset', 'network', 'firewall'].map((kind) => <SelectItem key={kind} value={kind}>{kind}</SelectItem>)}</SelectContent>
          </Select>
          {sourceKind === 'external'
            ? <Input value={sourceId} onChange={(event) => setSourceId(event.target.value)} placeholder="Origin label (e.g. Internet)" />
            : <Select value={sourceId} onValueChange={setSourceId}><SelectTrigger><SelectValue placeholder="Select source" /></SelectTrigger><SelectContent>{entityOptions(sourceKind).map((option) => <SelectItem key={option.id} value={option.id}>{option.label}</SelectItem>)}</SelectContent></Select>}
        </div>
        <div className="space-y-1"><Label>To</Label>
          <Select value={targetKind} onValueChange={(value) => { setTargetKind(value as SightingEntityKind); setTargetId(''); }}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>{['asset', 'network', 'firewall'].map((kind) => <SelectItem key={kind} value={kind}>{kind}</SelectItem>)}</SelectContent>
          </Select>
          <Select value={targetId} onValueChange={setTargetId}><SelectTrigger><SelectValue placeholder="Select target" /></SelectTrigger><SelectContent>{entityOptions(targetKind).map((option) => <SelectItem key={option.id} value={option.id}>{option.label}</SelectItem>)}</SelectContent></Select>
        </div>
      </div>
      <div className="space-y-1"><Label>Title *</Label><Input value={title} onChange={(event) => setTitle(event.target.value)} placeholder="e.g. RDP lateral movement" /></div>
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1"><Label>Type</Label><Select value={edgeType} onValueChange={(value) => setEdgeType(value as AttackEdgeType)}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{EDGE_TYPES.map((value) => <SelectItem key={value} value={value}>{value.replaceAll('_', ' ')}</SelectItem>)}</SelectContent></Select></div>
        <div className="space-y-1"><Label>Confidence</Label><Select value={confidence} onValueChange={(value) => setConfidence(value as AttackEdgeConfidence)}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{CONFIDENCE.map((value) => <SelectItem key={value} value={value}>{value}</SelectItem>)}</SelectContent></Select></div>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1"><Label>MITRE tactic</Label><Input value={mitreTactic} onChange={(event) => setMitreTactic(event.target.value)} placeholder="TA0008" /></div>
        <div className="space-y-1"><Label>MITRE technique</Label><Input value={mitreTechnique} onChange={(event) => setMitreTechnique(event.target.value)} placeholder="T1021.001" /></div>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1"><Label>Occurred at (local time)</Label><Input type="datetime-local" value={occurredAt} onChange={(event) => setOccurredAt(event.target.value)} /></div>
        <div className="space-y-1"><Label>Step number</Label><Input type="number" min="0" value={sequence} onChange={(event) => setSequence(event.target.value)} placeholder="auto" /></div>
      </div>
      <div className="space-y-1"><Label>Linked timeline event</Label>
        <Select value={timelineEventId} onValueChange={setTimelineEventId}>
          <SelectTrigger><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value={NONE}>None</SelectItem>
            {timelineEvents.map((event) => <SelectItem key={event.id} value={event.id}>{event.timestamp || 'no time'} · {event.description.slice(0, 60)}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>
      {iocs.length > 0 && <div className="space-y-1"><Label>Linked IOCs</Label>
        <div className="max-h-28 space-y-1 overflow-y-auto rounded border p-2">
          {iocs.map((ioc) => <label key={ioc.id} className="flex items-center gap-2 text-xs">
            <input type="checkbox" checked={iocIds.includes(ioc.id)} onChange={() => toggleIoc(ioc.id)} />
            <span className="font-mono">{ioc.ioc_type} · {ioc.value}</span>
          </label>)}
        </div>
      </div>}
      <div className="space-y-1"><Label>Description</Label><Textarea rows={2} value={description} onChange={(event) => setDescription(event.target.value)} /></div>
      <div className="flex gap-2">
        <Button size="sm" onClick={() => void save()} disabled={saving}>{saving ? 'Saving…' : edge ? 'Update' : 'Save edge'}</Button>
        <Button size="sm" variant="outline" onClick={onCancel}>Cancel</Button>
        {edge && <Button size="sm" variant="outline" className="ml-auto text-red-600" onClick={() => void remove()}>Delete</Button>}
      </div>
    </CardContent>
  </Card>;
}

function toLocalInput(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return '';
  const offset = date.getTimezoneOffset() * 60_000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 16);
}
