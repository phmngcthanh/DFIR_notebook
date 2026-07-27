import { useEffect, useState } from 'react';
import { FolderOpen, Loader2, Plus, ServerCog } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { createCase, listCases, unlockCase, type SessionPayload } from '@/lib/api';

interface Props {
  onSession: (session: SessionPayload) => void;
  onCancel?: () => void;
}

const MIN_PASSWORD_LENGTH = 6;

/**
 * The login screen. There is no username: the case database password is the
 * credential, and the expert name beside it is attribution only — the server
 * never checks one against the other.
 */
export default function CaseSetup({ onSession, onCancel }: Props) {
  const [mode, setMode] = useState<'open' | 'new'>('open');
  const [cases, setCases] = useState<string[]>([]);
  const [allowCreate, setAllowCreate] = useState(false);
  const [caseId, setCaseId] = useState('');
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [clientName, setClientName] = useState('');
  const [expertName, setExpertName] = useState(() => localStorage.getItem('dfir-expert-name') ?? '');
  const [databasePassword, setDatabasePassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    listCases()
      .then((listing) => {
        if (cancelled) return;
        setCases(listing.cases);
        setAllowCreate(listing.allowCreate);
        setCaseId((current) => current || listing.cases[0] || '');
        if (listing.cases.length === 0 && listing.allowCreate) setMode('new');
      })
      .catch((reason) => !cancelled && setError(String(reason)));
    return () => {
      cancelled = true;
    };
  }, []);

  const complete = (session: SessionPayload) => {
    localStorage.setItem('dfir-expert-name', session.expert.name);
    onSession(session);
  };

  const handleUnlock = async () => {
    if (!caseId) {
      setError('Select the case to unlock');
      return;
    }
    if (!expertName.trim()) {
      setError('Enter the expert name recorded on your changes');
      return;
    }
    if (!databasePassword) {
      setError('Enter the case database password');
      return;
    }
    setLoading(true);
    setError('');
    try {
      complete(await unlockCase({ caseId, password: databasePassword, expertName: expertName.trim() }));
    } catch (reason) {
      setError(String(reason instanceof Error ? reason.message : reason));
    } finally {
      setDatabasePassword('');
      setLoading(false);
    }
  };

  const handleCreate = async () => {
    if (!name.trim() || !expertName.trim()) {
      setError('Case name and session expert name are required');
      return;
    }
    if ([...databasePassword].length < MIN_PASSWORD_LENGTH) {
      setError(`Database password must contain at least ${MIN_PASSWORD_LENGTH} characters`);
      return;
    }
    if (databasePassword !== confirmPassword) {
      setError('Database passwords do not match');
      return;
    }
    setLoading(true);
    setError('');
    try {
      complete(
        await createCase({
          name: name.trim(),
          description: description.trim(),
          clientName: clientName.trim(),
          expertName: expertName.trim(),
          databasePassword,
        }),
      );
    } catch (reason) {
      setError(String(reason instanceof Error ? reason.message : reason));
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
            {mode === 'new' ? <><Plus size={20} className="text-cyan-600" />Create Case On This Server</> : <><ServerCog size={20} className="text-cyan-600" />Unlock A Case</>}
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
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Case database password *" htmlFor="database-password"><Input id="database-password" type="password" autoComplete="new-password" value={databasePassword} onChange={(event) => setDatabasePassword(event.target.value)} /></Field>
                <Field label="Confirm password *" htmlFor="confirm-password"><Input id="confirm-password" type="password" autoComplete="new-password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} /></Field>
              </div>
              <p className="text-xs text-slate-500">Everyone who works on this case shares this password. Because it now travels over the network, choose a long passphrase rather than the six-character minimum.</p>
              {error && <ErrorText text={error} />}
              <div className="flex gap-3 pt-2">
                <Button onClick={() => void handleCreate()} disabled={loading} className="flex-1 bg-cyan-600 hover:bg-cyan-700">{loading ? <Loader2 size={16} className="mr-2 animate-spin" /> : <Plus size={16} className="mr-2" />}Create Case</Button>
                {cases.length > 0 && <Button onClick={() => { setMode('open'); setError(''); }} variant="outline">Back to unlock</Button>}
                {onCancel && <Button onClick={onCancel} variant="outline">Cancel</Button>}
              </div>
            </>
          ) : (
            <>
              <p className="text-sm text-slate-600">Pick the case on this server, then enter the password stored with that case file.</p>
              <Field label="Case *" htmlFor="case-id">
                {cases.length === 0 ? (
                  <p className="rounded border border-dashed p-3 text-sm text-slate-500">This server has no case files yet.</p>
                ) : (
                  <select id="case-id" value={caseId} onChange={(event) => setCaseId(event.target.value)}
                    className="flex h-10 w-full rounded-md border border-slate-200 bg-white px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-cyan-600">
                    {cases.map((item) => <option key={item} value={item}>{item}</option>)}
                  </select>
                )}
              </Field>
              <Field label="Expert name *" htmlFor="expert-name"><Input id="expert-name" value={expertName} onChange={(event) => setExpertName(event.target.value)} placeholder="Name recorded on changes" /></Field>
              <Field label="Case database password *" htmlFor="database-password"><Input id="database-password" type="password" autoComplete="current-password" value={databasePassword} onChange={(event) => setDatabasePassword(event.target.value)} onKeyDown={(event) => event.key === 'Enter' && void handleUnlock()} /></Field>
              <p className="text-xs text-slate-500">Repeated wrong passwords from one address are locked out for a while.</p>
              {error && <ErrorText text={error} />}
              <div className="flex flex-wrap gap-3 pt-2">
                <Button onClick={() => void handleUnlock()} disabled={loading || cases.length === 0} className="flex-1 bg-cyan-600 hover:bg-cyan-700">{loading ? <Loader2 size={16} className="mr-2 animate-spin" /> : <FolderOpen size={16} className="mr-2" />}Unlock Case</Button>
                {onCancel && <Button onClick={onCancel} variant="outline">Cancel</Button>}
              </div>
              {allowCreate && (
                <Button variant="link" className="h-auto p-0 text-xs" onClick={() => { setMode('new'); setError(''); }}>
                  Create a new case on this server
                </Button>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function Field({ label, htmlFor, children }: { label: string; htmlFor: string; children: React.ReactNode }) {
  return <div className="space-y-2"><Label htmlFor={htmlFor}>{label}</Label>{children}</div>;
}

function ErrorText({ text }: { text: string }) {
  return <p role="alert" className="text-sm text-red-600">{text}</p>;
}
