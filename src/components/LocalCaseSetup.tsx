/**
 * Case entry for the offline shells (desktop and Android), where a case is a
 * file the investigator picks through a native dialog and there is no session.
 * The browser shell uses `CaseSetup` instead, where unlocking a server-held
 * case *is* the login. `App` selects between them on `session.hasSessions`.
 */
import { useState } from 'react';
import { invoke } from '@/lib/api';
import { ArchiveRestore, FolderOpen, Loader2, LockKeyhole, Plus } from 'lucide-react';
import { toast } from 'sonner';
import TeamField from '@/components/TeamField';
import { rememberedTeam, rememberTeam } from '@/lib/teams';
import type { ApiResponse, RestoreSummary } from '@/types';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';

interface Props {
  mode: 'new' | 'open';
  onComplete: () => void;
  onCancel: () => void;
}

interface CommandResponse {
  success: boolean;
  data?: string;
  error?: string;
}

const MIN_PASSWORD_LENGTH = 6;

export default function CaseSetup({ mode, onComplete, onCancel }: Props) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [clientName, setClientName] = useState('');
  const [expertName, setExpertName] = useState(() => localStorage.getItem('dfir-expert-name') ?? '');
  const [team, setTeam] = useState(rememberedTeam);
  const [showRestore, setShowRestore] = useState(false);
  const [databasePassword, setDatabasePassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showLegacyConversion, setShowLegacyConversion] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const validateNewPassword = () => {
    if ([...databasePassword].length < MIN_PASSWORD_LENGTH) {
      return `Database password must contain at least ${MIN_PASSWORD_LENGTH} characters`;
    }
    if (databasePassword !== confirmPassword) return 'Database passwords do not match';
    return '';
  };

  const handleCreate = async () => {
    if (!name.trim() || !expertName.trim()) {
      setError('Case name and session expert name are required');
      return;
    }
    const passwordError = validateNewPassword();
    if (passwordError) {
      setError(passwordError);
      return;
    }
    setLoading(true);
    setError('');
    try {
      const response = await invoke<CommandResponse>('create_new_case', {
        name: name.trim(),
        description: description.trim(),
        clientName: clientName.trim(),
        expertName: expertName.trim(),
        databasePassword,
        team: team.trim() || null,
      });
      if (!response.success) throw new Error(response.error || 'Failed to create case');
      localStorage.setItem('dfir-expert-name', expertName.trim());
      rememberTeam(team);
      onComplete();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setDatabasePassword('');
      setConfirmPassword('');
      setLoading(false);
    }
  };

  const handleOpen = async () => {
    if (!databasePassword) {
      setError('Enter the database file password before selecting the case');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const response = await invoke<CommandResponse>('open_existing_case', { databasePassword });
      if (!response.success) throw new Error(response.error || 'Failed to open case');
      onComplete();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setDatabasePassword('');
      setLoading(false);
    }
  };

  // A full backup (or the master copy a lead redistributes) is checked against
  // its .sha256 manifest and password, copied to a new file, and opened.
  const handleRestore = async () => {
    if (!databasePassword) {
      setError('Enter the backup password before selecting the backup');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const response = await invoke<ApiResponse<RestoreSummary>>('restore_full_backup', { password: databasePassword });
      if (!response.success || !response.data) throw new Error(response.error || 'Failed to restore the backup');
      const { caseName, manifest, restoredEventLogs } = response.data;
      toast.success(`Restored ${caseName}${restoredEventLogs ? ' with its event logs' : ''}`, {
        description: manifest.status === 'verified'
          ? `Checksums verified for ${manifest.files.join(', ')}.`
          : 'No .sha256 file came with this backup, so its integrity was not checked.',
      });
      onComplete();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setDatabasePassword('');
      setLoading(false);
    }
  };

  const handleLegacyConversion = async () => {
    const passwordError = validateNewPassword();
    if (passwordError) {
      setError(passwordError);
      return;
    }
    setLoading(true);
    setError('');
    try {
      const response = await invoke<CommandResponse>('migrate_legacy_case', { databasePassword });
      if (!response.success) throw new Error(response.error || 'Failed to convert legacy case');
      onComplete();
    } catch (reason) {
      setError(String(reason));
    } finally {
      setDatabasePassword('');
      setConfirmPassword('');
      setLoading(false);
    }
  };

  return (
    <div className="flex h-full items-center justify-center overflow-auto p-8">
      <Card className="w-full max-w-xl">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            {mode === 'new' ? <><Plus size={20} className="text-cyan-600" />Create New Case</> : <><FolderOpen size={20} className="text-cyan-600" />Unlock Existing Case</>}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {mode === 'new' ? (
            <>
              <Field label="Case name *" htmlFor="case-name"><Input id="case-name" value={name} onChange={(event) => setName(event.target.value)} placeholder="e.g. ACME breach investigation" /></Field>
              <Field label="Client name" htmlFor="client"><Input id="client" value={clientName} onChange={(event) => setClientName(event.target.value)} placeholder="Client organization" /></Field>
              <Field label="Description" htmlFor="description"><Textarea id="description" value={description} onChange={(event) => setDescription(event.target.value)} rows={3} /></Field>
              <Field label="Session expert name *" htmlFor="expert-name"><Input id="expert-name" value={expertName} onChange={(event) => setExpertName(event.target.value)} placeholder="Name recorded on changes" /></Field>
              <p className="text-xs text-slate-500">This session name is recorded on changes. It is attribution only, is not checked against the password, and can change between sessions.</p>
              <TeamField value={team} onChange={setTeam} />
              <PasswordFields password={databasePassword} confirmation={confirmPassword} onPassword={setDatabasePassword} onConfirmation={setConfirmPassword} />
              <p className="text-xs text-slate-500">This password encrypts only the selected .db file. Copies initially share it; each copy can later be given a different password.</p>
              {error && <ErrorText text={error} />}
              <div className="flex gap-3 pt-2">
                <Button onClick={() => void handleCreate()} disabled={loading} className="flex-1 bg-cyan-600 hover:bg-cyan-700">{loading ? <Loader2 size={16} className="mr-2 animate-spin" /> : <Plus size={16} className="mr-2" />}Create Case</Button>
                <Button onClick={onCancel} variant="outline">Cancel</Button>
              </div>
            </>
          ) : (
            <>
              <p className="text-sm text-slate-600">Enter the password stored with the database file, then select that .db file.</p>
              <Field label="Database file password *" htmlFor="database-password"><Input id="database-password" type="password" autoComplete="current-password" value={databasePassword} onChange={(event) => setDatabasePassword(event.target.value)} /></Field>
              {!showLegacyConversion && <p className="text-xs text-slate-500">After the file unlocks, you will enter the expert name used only for audit attribution.</p>}
              {showLegacyConversion && (
                <>
                  <Field label="Confirm new database password *" htmlFor="confirm-password"><Input id="confirm-password" type="password" autoComplete="new-password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} /></Field>
                  <p className="rounded bg-amber-50 p-3 text-xs text-amber-800">Conversion preserves the original plaintext file and asks where to save a new encrypted copy.</p>
                </>
              )}
              {error && <ErrorText text={error} />}
              <div className="flex flex-wrap gap-3 pt-2">
                {showLegacyConversion ? (
                  <Button onClick={() => void handleLegacyConversion()} disabled={loading} className="flex-1 bg-cyan-600 hover:bg-cyan-700"><LockKeyhole size={16} className="mr-2" />Convert and Open Copy</Button>
                ) : showRestore ? (
                  <Button onClick={() => void handleRestore()} disabled={loading} className="flex-1 bg-cyan-600 hover:bg-cyan-700">{loading ? <Loader2 size={16} className="mr-2 animate-spin" /> : <ArchiveRestore size={16} className="mr-2" />}Select Backup and Restore</Button>
                ) : (
                  <Button onClick={() => void handleOpen()} disabled={loading} className="flex-1 bg-cyan-600 hover:bg-cyan-700">{loading ? <Loader2 size={16} className="mr-2 animate-spin" /> : <FolderOpen size={16} className="mr-2" />}Select and Unlock Case</Button>
                )}
                <Button onClick={onCancel} variant="outline">Cancel</Button>
              </div>
              {showRestore && <p className="rounded bg-cyan-50 p-3 text-xs text-cyan-900">Pick a full backup (.db). Its .sha256 checksum file is checked when present, then the backup is copied to a new file you choose and opened. The backup itself is never changed.</p>}
              <div className="flex flex-wrap gap-4">
                {!showRestore && (
                  <Button variant="link" className="h-auto p-0 text-xs" onClick={() => { setShowLegacyConversion((value) => !value); setError(''); setConfirmPassword(''); }}>
                    {showLegacyConversion ? 'Back to encrypted case login' : 'Convert a legacy unencrypted case'}
                  </Button>
                )}
                {!showLegacyConversion && (
                  <Button variant="link" className="h-auto p-0 text-xs" onClick={() => { setShowRestore((value) => !value); setError(''); }}>
                    {showRestore ? 'Back to encrypted case login' : 'Restore a full backup or redistributed master'}
                  </Button>
                )}
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function PasswordFields({ password, confirmation, onPassword, onConfirmation }: { password: string; confirmation: string; onPassword: (value: string) => void; onConfirmation: (value: string) => void }) {
  return <div className="grid gap-4 sm:grid-cols-2"><Field label="Database file password *" htmlFor="database-password"><Input id="database-password" type="password" autoComplete="new-password" value={password} onChange={(event) => onPassword(event.target.value)} /></Field><Field label="Confirm password *" htmlFor="confirm-password"><Input id="confirm-password" type="password" autoComplete="new-password" value={confirmation} onChange={(event) => onConfirmation(event.target.value)} /></Field></div>;
}

function Field({ label, htmlFor, children }: { label: string; htmlFor: string; children: React.ReactNode }) {
  return <div className="space-y-2"><Label htmlFor={htmlFor}>{label}</Label>{children}</div>;
}

function ErrorText({ text }: { text: string }) {
  return <p role="alert" className="text-sm text-red-600">{text}</p>;
}
