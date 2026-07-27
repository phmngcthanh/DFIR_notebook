import { useEffect, useState } from 'react';
import { invoke } from '@/lib/api';
import { CircleAlert, Crosshair, EyeOff, Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import type { ApiResponse, AttackEdge, IocSighting, SightingEntityKind, TimelineEvent } from '@/types';

export interface SelectedEntity {
  kind: SightingEntityKind | 'external';
  id: string;
  label: string;
  nodeId: string;
  raw?: Record<string, unknown>;
}

interface Props {
  entity: SelectedEntity;
  attackEdges: AttackEdge[];
  timelineEvents: TimelineEvent[];
  refreshToken: number;
  onHideNode: (nodeId: string) => void;
  onHideNetwork?: (networkId: string) => void;
  onRecordSighting: () => void;
  onDrawFromHere: () => void;
  onEditEdge: (edge: AttackEdge) => void;
  onSightingRemoved: () => void;
}

export default function EntityInspector({
  entity, attackEdges, timelineEvents, refreshToken,
  onHideNode, onHideNetwork, onRecordSighting, onDrawFromHere, onEditEdge, onSightingRemoved,
}: Props) {
  const [sightings, setSightings] = useState<IocSighting[]>([]);

  useEffect(() => {
    if (entity.kind === 'external') { setSightings([]); return; }
    let cancelled = false;
    void invoke<ApiResponse<IocSighting[]>>('list_ioc_sightings', { entityKind: entity.kind, entityId: entity.id })
      .then((response) => {
        if (cancelled) return;
        if (!response.success) throw new Error(response.error);
        setSightings(response.data ?? []);
      })
      .catch((reason) => toast.error(String(reason)));
    return () => { cancelled = true; };
  }, [entity, refreshToken]);

  const removeSighting = async (id: string) => {
    if (!confirm('Delete this IOC sighting?')) return;
    try {
      const response = await invoke<ApiResponse<boolean>>('remove_ioc_sighting', { id });
      if (!response.success) throw new Error(response.error || 'Could not delete sighting');
      onSightingRemoved();
    } catch (reason) { toast.error(String(reason)); }
  };

  const touching = attackEdges.filter((edge) =>
    (edge.source_kind === entity.kind && (entity.kind === 'external' ? edge.source_id.trim() === entity.id : edge.source_id === entity.id))
    || (edge.target_kind === entity.kind && edge.target_id === entity.id));
  const events = entity.kind === 'asset'
    ? timelineEvents.filter((event) => event.asset_id === entity.id)
    : [];

  return <Card className="flex min-h-0 flex-col">
    <CardHeader className="pb-2"><CardTitle className="text-sm">{entity.label}</CardTitle></CardHeader>
    <CardContent className="min-h-0 space-y-3 overflow-y-auto text-xs">
      <div className="flex flex-wrap gap-2">
        <Badge variant="outline">{entity.kind}</Badge>
        {typeof entity.raw?.compromise_status === 'string' && <Badge variant={entity.raw.compromise_status === 'infected' ? 'destructive' : 'outline'}>{String(entity.raw.compromise_status)}</Badge>}
      </div>
      {entity.raw && <div className="space-y-1">
        {Object.entries(entity.raw)
          .filter(([key, value]) => value != null && value !== '' && !['id', 'created_at', 'network_id', 'network_name', 'properties', 'scan_results', 'rules', 'config_text'].includes(key))
          .map(([key, value]) => <div key={key} className="grid grid-cols-[110px_1fr] gap-2"><span className="text-slate-500">{key.replaceAll('_', ' ')}</span><span className="break-all font-mono">{String(value)}</span></div>)}
      </div>}
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="outline" onClick={() => onHideNode(entity.nodeId)}><EyeOff size={13} className="mr-1" />Hide</Button>
        {entity.kind === 'network' && onHideNetwork && <Button size="sm" variant="outline" onClick={() => onHideNetwork(entity.id)}><EyeOff size={13} className="mr-1" />Hide with members</Button>}
        {entity.kind !== 'external' && <Button size="sm" variant="outline" onClick={onRecordSighting}><Plus size={13} className="mr-1" />IOC sighting</Button>}
        <Button size="sm" variant="outline" onClick={onDrawFromHere}><Crosshair size={13} className="mr-1" />Attack from here</Button>
      </div>

      {entity.kind !== 'external' && <section>
        <h4 className="mb-1 font-semibold text-slate-600">IOC sightings ({sightings.length})</h4>
        {sightings.length === 0 ? <p className="text-slate-400">None recorded.</p> : sightings.map((sighting) => <div key={sighting.id} className="mb-1 flex items-start justify-between gap-2 rounded border border-slate-200 p-2">
          <div>
            <p className="font-mono">{sighting.ioc_type} · {sighting.ioc_value}</p>
            <p className="text-slate-500">{sighting.threat_level} threat{sighting.sighted_at ? ` · ${new Date(sighting.sighted_at).toLocaleString()}` : ''}</p>
            {sighting.location && <p className="break-all text-slate-500">{sighting.location}</p>}
            {sighting.note && <p className="text-slate-500">{sighting.note}</p>}
          </div>
          <Button size="sm" variant="ghost" onClick={() => void removeSighting(sighting.id)}><Trash2 size={13} className="text-red-500" /></Button>
        </div>)}
      </section>}

      <section>
        <h4 className="mb-1 font-semibold text-slate-600">Attack edges ({touching.length})</h4>
        {touching.length === 0 ? <p className="text-slate-400">None drawn.</p> : touching.map((edge) => <button key={edge.id} className="mb-1 block w-full rounded border border-slate-200 p-2 text-left hover:bg-slate-50" onClick={() => onEditEdge(edge)}>
          <p className="font-medium">{edge.title}</p>
          <p className="text-slate-500">{(edge.source_name ?? edge.source_id)} → {(edge.target_name ?? edge.target_id)} · {edge.edge_type.replaceAll('_', ' ')} · {edge.confidence}</p>
          {(edge.occurred_at || edge.timeline_event_time) && <p className="text-slate-500">{new Date(edge.occurred_at ?? edge.timeline_event_time ?? '').toLocaleString()}</p>}
        </button>)}
      </section>

      {entity.kind === 'asset' && <section>
        <h4 className="mb-1 font-semibold text-slate-600">Timeline events ({events.length})</h4>
        {events.length === 0 ? <p className="text-slate-400">None linked.</p> : events.slice(0, 12).map((event) => <div key={event.id} className="mb-1 rounded border border-slate-200 p-2">
          <p className="flex items-center gap-1 font-medium">{['high', 'critical'].includes(event.severity) && <CircleAlert size={12} className="text-red-500" />}{event.event_type}</p>
          <p className="text-slate-500">{event.timestamp || 'no corrected time'} · {event.description.slice(0, 80)}</p>
        </div>)}
        {events.length > 12 && <p className="text-slate-400">…and {events.length - 12} more in the Timeline tab.</p>}
      </section>}
    </CardContent>
  </Card>;
}
