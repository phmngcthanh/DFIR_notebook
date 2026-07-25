import { useCallback, useEffect, useState } from 'react';
import { invoke } from '@/lib/api';
import { Database, FolderLock, Plus, RefreshCw } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import type { ApiResponse, LocalCaseFile } from '@/types';
import LocalCaseSetup from '@/components/LocalCaseSetup';
import { branding } from '@/config/branding';

interface Props { onComplete: () => void }

export default function CasePicker({ onComplete }: Props) {
  const [cases, setCases] = useState<LocalCaseFile[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [showNewCase, setShowNewCase] = useState(false);

  const loadCases = useCallback(async () => {
    try {
      const response = await invoke<ApiResponse<LocalCaseFile[]>>('list_local_cases');
      if (!response.success) throw new Error(response.error || 'Could not list case files');
      setCases(response.data ?? []);
    } catch (reason) {
      toast.error(String(reason));
    }
  }, []);

  useEffect(() => { void loadCases(); }, [loadCases]);

  const openCase = async (fileName: string) => {
    setBusy(true);
    try {
      const response = await invoke<ApiResponse<string>>('open_local_case', {
        fileName,
        databasePassword: password,
      });
      if (!response.success) throw new Error(response.error || 'Could not unlock case');
      setPassword('');
      setSelected(null);
      onComplete();
    } catch (reason) {
      toast.error(String(reason));
    } finally {
      setBusy(false);
    }
  };

  if (showNewCase) {
    return <LocalCaseSetup mode="new" onComplete={onComplete} onCancel={() => { setShowNewCase(false); void loadCases(); }} />;
  }

  return (
    <div className="flex h-full flex-col items-center overflow-y-auto p-6">
      <div className="w-full max-w-xl">
        <div className="mb-6 text-center">
          <FolderLock size={48} className="mx-auto mb-3 text-cyan-600" />
          <h2 className="text-2xl font-bold text-slate-800">{branding.productName}</h2>
          <p className="mt-1 text-sm text-slate-500">Case files on this device</p>
        </div>
        <div className="mb-4 flex gap-2">
          <Button className="h-12 flex-1 bg-cyan-600 text-base hover:bg-cyan-700" onClick={() => setShowNewCase(true)}>
            <Plus size={18} className="mr-2" />New Case
          </Button>
          <Button variant="outline" className="h-12" onClick={() => void loadCases()} aria-label="Refresh case list">
            <RefreshCw size={18} />
          </Button>
        </div>
        {cases.length === 0 ? (
          <Card><CardContent className="py-10 text-center text-sm text-slate-500">
            No case files on this device yet. Create a new case, or copy a .db file into the app cases folder.
          </CardContent></Card>
        ) : (
          <div className="space-y-3">
            {cases.map((item) => (
              <Card key={item.file_name}>
                <CardContent className="p-4">
                  <button
                    className="flex w-full items-center gap-3 text-left"
                    onClick={() => { setSelected(selected === item.file_name ? null : item.file_name); setPassword(''); }}
                  >
                    <Database size={22} className="flex-shrink-0 text-cyan-600" />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-medium text-slate-800">{item.file_name}</span>
                      <span className="block text-xs text-slate-500">
                        {formatSize(item.size_bytes)}{item.modified_at ? ` · ${new Date(item.modified_at).toLocaleString()}` : ''}
                      </span>
                    </span>
                  </button>
                  {selected === item.file_name && (
                    <form
                      className="mt-3 space-y-2 border-t pt-3"
                      onSubmit={(event) => { event.preventDefault(); void openCase(item.file_name); }}
                    >
                      <Label htmlFor={`unlock-${item.file_name}`}>Database file password</Label>
                      <Input
                        id={`unlock-${item.file_name}`}
                        type="password"
                        autoComplete="current-password"
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                      />
                      <Button type="submit" disabled={busy || !password} className="h-12 w-full bg-cyan-600 hover:bg-cyan-700">
                        {busy ? 'Unlocking…' : 'Unlock Case'}
                      </Button>
                    </form>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
