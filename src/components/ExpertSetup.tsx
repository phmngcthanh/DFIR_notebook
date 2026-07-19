import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { UserRound, Network as NetworkIcon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import type { ApiResponse, ExpertIdentity, Network } from '@/types';

interface Props {
  onComplete: (expert: ExpertIdentity) => void;
  onCancel?: () => void;
}

export default function ExpertSetup({ onComplete, onCancel }: Props) {
  const [name, setName] = useState(() => localStorage.getItem('dfir-expert-name') ?? '');
  const [scopeLabel, setScopeLabel] = useState('');
  const [scopeNetworkIds, setScopeNetworkIds] = useState<string[]>([]);
  const [networks, setNetworks] = useState<Network[]>([]);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    void invoke<ApiResponse<Network[]>>('list_networks').then((response) => {
      if (response.success) setNetworks(response.data ?? []);
    });
  }, []);

  const toggleNetwork = (id: string) => {
    setScopeNetworkIds((current) => current.includes(id) ? current.filter((value) => value !== id) : [...current, id]);
  };

  const handleSave = async () => {
    if (!name.trim()) {
      setError('Expert name is required');
      return;
    }
    setSaving(true);
    setError('');
    try {
      const response = await invoke<ApiResponse<ExpertIdentity>>('set_current_expert', {
        name: name.trim(),
        scopeLabel: scopeLabel.trim() || null,
        scopeNetworkIds,
      });
      if (!response.success || !response.data) throw new Error(response.error || 'Failed to set expert');
      localStorage.setItem('dfir-expert-name', name.trim());
      onComplete(response.data);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="flex h-full items-center justify-center bg-slate-50 p-8">
      <Card className="w-full max-w-xl">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <UserRound className="text-cyan-600" size={20} />
            Identify this work session
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          <p className="text-sm text-slate-600">
            This name is recorded with every change. It is attribution only and is not checked against the database password. A different expert can use the same unlocked case in a later session.
          </p>
          <div className="space-y-2">
            <Label htmlFor="expert-name">Expert name *</Label>
            <Input id="expert-name" value={name} onChange={(event) => setName(event.target.value)} placeholder="e.g. Alice" />
          </div>
          <div className="space-y-2">
            <Label htmlFor="scope-label">Optional assignment</Label>
            <Input id="scope-label" value={scopeLabel} onChange={(event) => setScopeLabel(event.target.value)} placeholder="e.g. Finance department / Room 204" />
            <p className="text-xs text-slate-500">The assignment filters and labels work but never prevents an edit.</p>
          </div>
          {networks.length > 0 && (
            <div className="space-y-2">
              <Label className="flex items-center gap-2"><NetworkIcon size={14} /> Focus network zones</Label>
              <div className="grid max-h-40 grid-cols-2 gap-2 overflow-auto rounded-md border p-3">
                {networks.map((network) => (
                  <label key={network.id} className="flex cursor-pointer items-center gap-2 text-sm">
                    <input type="checkbox" checked={scopeNetworkIds.includes(network.id)} onChange={() => toggleNetwork(network.id)} />
                    <span className="truncate">{network.name}</span>
                  </label>
                ))}
              </div>
            </div>
          )}
          {error && <p className="text-sm text-red-600">{error}</p>}
          <div className="flex gap-2">
            <Button onClick={handleSave} disabled={saving} className="bg-cyan-600 hover:bg-cyan-700">
              {saving ? 'Starting...' : 'Start session'}
            </Button>
            {onCancel && <Button variant="outline" onClick={onCancel}>Cancel</Button>}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
