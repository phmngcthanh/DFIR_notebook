/**
 * How one asset relates to others: a VM runs on its hypervisor, a host is
 * managed by a console, a server backs up to another. Shown inside the
 * expanded asset row, outgoing links first, then what points at this asset.
 */
import { useMemo, useState } from 'react';
import { Link2, Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { invoke } from '@/lib/api';
import { RELATION_TYPES, relationPhrase } from '@/lib/environment';
import type { ApiResponse, Asset, AssetRelation, RelationType } from '@/types';

interface Props {
  asset: Asset;
  assets: Asset[];
  relations: AssetRelation[];
  onChanged: () => void | Promise<void>;
}

export default function AssetRelationsPanel({ asset, assets, relations, onChanged }: Props) {
  const outgoing = relations.filter((item) => item.source_asset_id === asset.id);
  const incoming = relations.filter((item) => item.target_asset_id === asset.id);
  const [adding, setAdding] = useState(false);
  const [type, setType] = useState<RelationType>(asset.asset_type === 'vm' ? 'runs_on' : 'depends_on');
  const [targetId, setTargetId] = useState('');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);

  const candidates = useMemo(
    () => assets.filter((item) => item.id !== asset.id).sort((left, right) => left.name.localeCompare(right.name)),
    [assets, asset.id],
  );
  const nameOf = (id: string, fallback?: string | null) => assets.find((item) => item.id === id)?.name ?? fallback ?? id;

  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    try {
      await action();
      await onChanged();
    } catch (reason) {
      toast.error(String(reason));
    } finally {
      setBusy(false);
    }
  };

  const add = () => run(async () => {
    if (!targetId) throw new Error('Choose the asset to link to');
    const response = await invoke<ApiResponse<AssetRelation>>('create_new_asset_relation', {
      sourceAssetId: asset.id, targetAssetId: targetId, relationType: type, note: note.trim() || null,
    });
    if (!response.success) throw new Error(response.error || 'Could not save the link');
    setAdding(false);
    setTargetId('');
    setNote('');
  });

  const remove = (relation: AssetRelation) => run(async () => {
    const response = await invoke<ApiResponse<boolean>>('remove_asset_relation', { id: relation.id });
    if (!response.success) throw new Error(response.error || 'Could not remove the link');
  });

  return (
    <div className="mt-4 space-y-2" aria-label="Asset relations">
      <div className="flex items-center justify-between">
        <h3 className="flex items-center gap-2 text-sm font-semibold"><Link2 size={15} />Relations</h3>
        <Button size="sm" variant="outline" onClick={() => setAdding((value) => !value)} disabled={candidates.length === 0}><Plus size={14} className="mr-1" />Add relation</Button>
      </div>
      {outgoing.length === 0 && incoming.length === 0 && !adding && (
        <p className="text-xs text-slate-500">No links to other assets. Record what runs on what, or what depends on what.</p>
      )}
      <ul className="space-y-1">
        {outgoing.map((item) => (
          <li key={item.id} className="flex items-center justify-between rounded border bg-white px-2 py-1.5 text-sm">
            <span><strong>{asset.name}</strong> {relationPhrase(item.relation_type)} <strong>{nameOf(item.target_asset_id, item.target_name)}</strong>{item.note && <span className="ml-2 text-xs text-slate-500">{item.note}</span>}</span>
            <Button size="sm" variant="ghost" aria-label={`Remove link to ${nameOf(item.target_asset_id, item.target_name)}`} disabled={busy} onClick={() => void remove(item)}><Trash2 size={14} className="text-red-500" /></Button>
          </li>
        ))}
        {incoming.map((item) => (
          <li key={item.id} className="flex items-center justify-between rounded border bg-white px-2 py-1.5 text-sm">
            <span><strong>{asset.name}</strong> {relationPhrase(item.relation_type, 'in')} <strong>{nameOf(item.source_asset_id, item.source_name)}</strong>{item.note && <span className="ml-2 text-xs text-slate-500">{item.note}</span>}</span>
            <Button size="sm" variant="ghost" aria-label={`Remove link from ${nameOf(item.source_asset_id, item.source_name)}`} disabled={busy} onClick={() => void remove(item)}><Trash2 size={14} className="text-red-500" /></Button>
          </li>
        ))}
      </ul>
      {adding && (
        <div className="grid items-end gap-2 rounded border bg-white p-3 md:grid-cols-[170px_1fr_1fr_auto]">
          <div className="space-y-1">
            <Label>This asset…</Label>
            <Select value={type} onValueChange={(value) => setType(value as RelationType)}>
              <SelectTrigger aria-label="Relation type"><SelectValue /></SelectTrigger>
              <SelectContent>{RELATION_TYPES.map((item) => <SelectItem key={item.value} value={item.value}>{item.out}</SelectItem>)}</SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label>…this asset</Label>
            <Select value={targetId} onValueChange={setTargetId}>
              <SelectTrigger aria-label="Related asset"><SelectValue placeholder="Choose an asset" /></SelectTrigger>
              <SelectContent>{candidates.map((item) => <SelectItem key={item.id} value={item.id}>{item.name}{item.ip_address ? ` (${item.ip_address})` : ''}</SelectItem>)}</SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label htmlFor={`relation-note-${asset.id}`}>Note</Label>
            <Input id={`relation-note-${asset.id}`} value={note} onChange={(event) => setNote(event.target.value)} placeholder="Optional" />
          </div>
          <div className="flex gap-1">
            <Button size="sm" onClick={() => void add()} disabled={busy || !targetId}>Save</Button>
            <Button size="sm" variant="outline" onClick={() => setAdding(false)}>Cancel</Button>
          </div>
        </div>
      )}
    </div>
  );
}
