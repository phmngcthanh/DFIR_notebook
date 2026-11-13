/**
 * Assets that look like the same machine recorded twice: typed by hand and
 * then imported, seen once by name and once by address, found by two teams.
 * Pairs with a shared MAC address or the same name at the same address come
 * first; an address alone or a short name alone is only worth a look.
 *
 * Merging keeps one asset and folds the other into it: interfaces, timeline
 * events, IOC sightings, attack paths, and relations all move over, empty
 * fields are filled, and the merged-away asset is deleted. One attributed
 * commit records all of it, and the deleted record stays in case history.
 */
import { useMemo, useState } from 'react';
import { GitMerge, Loader2, X } from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { invoke } from '@/lib/api';
import { describeReasons, findDuplicatePairs } from '@/lib/asset-match';
import { originLabel } from '@/lib/environment';
import type { ApiResponse, Asset, AssetMergeSummary, NetworkInterface } from '@/types';

interface Props {
  assets: Asset[];
  interfaces: NetworkInterface[];
  onMerged: () => void | Promise<void>;
  onClose: () => void;
}

export default function DuplicateAssetsPanel({ assets, interfaces, onMerged, onClose }: Props) {
  const pairs = useMemo(() => findDuplicatePairs(assets, interfaces), [assets, interfaces]);
  const nicCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of interfaces) counts.set(item.asset_id, (counts.get(item.asset_id) ?? 0) + 1);
    return counts;
  }, [interfaces]);
  const [busy, setBusy] = useState(false);

  const merge = async (keep: Asset, remove: Asset) => {
    if (!confirm(`Merge "${remove.name}" into "${keep.name}"?\n\n"${remove.name}" is deleted. Its interfaces, timeline events, IOC sightings, attack paths, and relations move to "${keep.name}", which also takes any detail it lacks. The deleted record stays in case history.`)) return;
    setBusy(true);
    try {
      const response = await invoke<ApiResponse<AssetMergeSummary>>('merge_asset_records', { keepId: keep.id, removeId: remove.id });
      if (!response.success || !response.data) throw new Error(response.error || 'Could not merge the assets');
      const moved = response.data;
      toast.success(`Merged ${remove.name} into ${keep.name}`, {
        description: `Moved ${moved.interfaces_moved} interface${moved.interfaces_moved === 1 ? '' : 's'}, ${moved.timeline_events} timeline event${moved.timeline_events === 1 ? '' : 's'}, ${moved.sightings} sighting${moved.sightings === 1 ? '' : 's'}, ${moved.attack_edges} attack path${moved.attack_edges === 1 ? '' : 's'} and ${moved.relations} relation${moved.relations === 1 ? '' : 's'}.`,
      });
      await onMerged();
    } catch (reason) {
      toast.error(String(reason));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="border-violet-200 bg-violet-50/30">
      <CardHeader className="flex flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2 text-base"><GitMerge size={18} />Possible duplicates</CardTitle>
          <p className="mt-1 text-xs text-slate-500">Assets that share a MAC address, a name, or an address. Choose which one to keep; the other is folded into it.</p>
        </div>
        <Button size="sm" variant="ghost" aria-label="Close duplicate check" onClick={onClose}><X size={16} /></Button>
      </CardHeader>
      <CardContent className="space-y-2">
        {pairs.length === 0 && <p className="text-sm text-slate-600">No two assets share a MAC address, a name, or an address.</p>}
        {pairs.map((pair) => (
          <div key={`${pair.first.id}:${pair.second.id}`} className="space-y-2 rounded-md border bg-white p-3">
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <Badge className={pair.strength === 'strong' ? 'bg-red-100 text-red-800' : 'bg-amber-100 text-amber-800'}>{pair.strength === 'strong' ? 'Very likely the same machine' : 'Worth a look'}</Badge>
              <span className="text-slate-600">{describeReasons(pair.reasons)}</span>
            </div>
            <div className="grid gap-3 md:grid-cols-2">
              {[pair.first, pair.second].map((asset, index) => {
                const other = index === 0 ? pair.second : pair.first;
                return (
                  <div key={asset.id} className="space-y-1 rounded border bg-slate-50 p-2 text-sm">
                    <p className="font-medium text-slate-800">{asset.name}</p>
                    <p className="text-xs text-slate-500">
                      {[asset.ip_address, asset.mac_address, asset.asset_type, asset.os].filter(Boolean).join(' · ') || 'no details'}
                      {' · '}{nicCounts.get(asset.id) ?? 0} NIC{(nicCounts.get(asset.id) ?? 0) === 1 ? '' : 's'}
                    </p>
                    <p className="text-xs text-slate-500">{originLabel(asset.origin)}{asset.owner ? ` · owner ${asset.owner}` : ''}</p>
                    <Button size="sm" variant="outline" disabled={busy} onClick={() => void merge(asset, other)} aria-label={`Keep ${asset.name} and merge ${other.name} into it`}>
                      {busy ? <Loader2 size={14} className="mr-1 animate-spin" /> : <GitMerge size={14} className="mr-1" />}Keep this one
                    </Button>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
