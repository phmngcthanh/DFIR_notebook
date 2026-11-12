import { useState } from 'react';
import { invoke } from '@/lib/api';
import { useDraft, useDraftDiscard } from '@/lib/drafts';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import type { ApiResponse, Ioc, IocSighting, SightingEntityKind } from '@/types';

interface Props {
  entityKind: SightingEntityKind;
  entityId: string;
  entityName: string;
  iocs: Ioc[];
  onSaved: () => void;
  onCancel: () => void;
}

export default function SightingForm({ entityKind, entityId, entityName, iocs, onSaved, onCancel }: Props) {
  // Typed work survives leaving the Investigation screen; Save and Cancel forget it.
  const draftKey = `investigation.sighting.${entityKind}.${entityId}.`;
  const discardDraft = useDraftDiscard();
  const [iocId, setIocId] = useDraft(`${draftKey}iocId`, iocs[0]?.id ?? '');
  const [sightedAt, setSightedAt] = useDraft(`${draftKey}sightedAt`, '');
  const [location, setLocation] = useDraft(`${draftKey}location`, '');
  const [note, setNote] = useDraft(`${draftKey}note`, '');
  const selected = iocs.find((ioc) => ioc.id === iocId);
  const highThreat = selected ? ['high', 'critical'].includes(selected.threat_level) : false;
  const [escalate, setEscalate] = useDraft(`${draftKey}escalate`, false);
  const [escalateTo, setEscalateTo] = useDraft<'suspected' | 'infected'>(`${draftKey}escalateTo`, highThreat ? 'infected' : 'suspected');
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!iocId) { toast.error('Select an IOC for this sighting'); return; }
    setSaving(true);
    try {
      const response = await invoke<ApiResponse<IocSighting>>('create_new_ioc_sighting', {
        iocId,
        entityKind,
        entityId,
        sightedAt: sightedAt ? new Date(sightedAt).toISOString() : null,
        location: location.trim(),
        note: note.trim(),
        setCompromiseStatus: entityKind === 'asset' && escalate ? escalateTo : null,
      });
      if (!response.success) throw new Error(response.error || 'Could not record sighting');
      toast.success(`IOC sighting recorded on ${entityName}`);
      discardDraft(draftKey);
      onSaved();
    } catch (reason) { toast.error(String(reason)); } finally { setSaving(false); }
  };

  return <Card>
    <CardHeader><CardTitle className="text-sm">Record IOC sighting on {entityName}</CardTitle></CardHeader>
    <CardContent className="space-y-3 text-sm">
      {iocs.length === 0 ? <p className="text-slate-500">Add an IOC in the IOCs tab first.</p> : <>
        <div className="space-y-1"><Label>IOC *</Label>
          <Select value={iocId} onValueChange={(value) => { setIocId(value); const ioc = iocs.find((item) => item.id === value); setEscalateTo(ioc && ['high', 'critical'].includes(ioc.threat_level) ? 'infected' : 'suspected'); }}>
            <SelectTrigger><SelectValue placeholder="Select IOC" /></SelectTrigger>
            <SelectContent>{iocs.map((ioc) => <SelectItem key={ioc.id} value={ioc.id}>{ioc.ioc_type} · {ioc.value}</SelectItem>)}</SelectContent>
          </Select>
        </div>
        <div className="space-y-1"><Label>Sighted at (local time)</Label><Input type="datetime-local" value={sightedAt} onChange={(event) => setSightedAt(event.target.value)} /></div>
        <div className="space-y-1"><Label>Location (path, registry key, log source…)</Label><Input value={location} onChange={(event) => setLocation(event.target.value)} /></div>
        <div className="space-y-1"><Label>Note</Label><Textarea rows={2} value={note} onChange={(event) => setNote(event.target.value)} /></div>
        {entityKind === 'asset' && <div className="flex items-center gap-2">
          <input id="escalate" type="checkbox" checked={escalate} onChange={(event) => setEscalate(event.target.checked)} />
          <Label htmlFor="escalate">Mark this asset as</Label>
          <Select value={escalateTo} onValueChange={(value) => setEscalateTo(value as 'suspected' | 'infected')}>
            <SelectTrigger className="w-32"><SelectValue /></SelectTrigger>
            <SelectContent><SelectItem value="suspected">suspected</SelectItem><SelectItem value="infected">infected</SelectItem></SelectContent>
          </Select>
        </div>}
        <div className="flex gap-2">
          <Button size="sm" onClick={() => void save()} disabled={saving}>{saving ? 'Saving…' : 'Record sighting'}</Button>
          <Button size="sm" variant="outline" onClick={() => { discardDraft(draftKey); onCancel(); }}>Cancel</Button>
        </div>
      </>}
    </CardContent>
  </Card>;
}
