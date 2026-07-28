import { useEffect, useMemo, useState } from 'react';
import { v4 as uuidv4 } from 'uuid';
import { AlertTriangle, CheckCircle2, Loader2, Plus, Route, Save, SearchCheck, Trash2, X, XCircle } from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  analyzeConnectivity,
  type ConnectivityAnalysis,
  type ConnectivityDirection,
  type ConnectivityInventory,
  type ConnectivityMode,
  type ConnectivityPolicy,
  evaluatePolicy,
  INTERNET_NODE_ID,
  metadataWithConnectivityPolicies,
  parseConnectivityPolicies,
  type PolicyEvaluation,
} from '@/lib/connectivity-analysis';
import { invoke } from '@/lib/api';
import type { ApiResponse, Case, PartialApplySummary, PartialImportPreview } from '@/types';

interface Props {
  caseInfo: Case;
  inventory: ConnectivityInventory;
  onChanged: () => Promise<void>;
  onClose: () => void;
}

interface PolicyForm {
  name: string;
  sourceNetworkId: string;
  target: string;
  direction: ConnectivityPolicy['direction'];
  mode: ConnectivityMode;
  expectation: ConnectivityPolicy['expectation'];
  description: string;
}

export default function ConnectivityVerifier({ caseInfo, inventory, onChanged, onClose }: Props) {
  const [tab, setTab] = useState('compliance');
  const [policies, setPolicies] = useState<ConnectivityPolicy[]>(() => parseConnectivityPolicies(caseInfo.metadata));
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState<PolicyForm>({
    name: '',
    sourceNetworkId: inventory.networks[0]?.id ?? '',
    target: 'internet',
    direction: 'bidirectional',
    mode: 'logical',
    expectation: 'blocked',
    description: '',
  });
  const [reachSource, setReachSource] = useState(inventory.networks[0]?.id ?? '');
  const [reachTarget, setReachTarget] = useState('internet');
  const [reachDirection, setReachDirection] = useState<ConnectivityDirection | 'bidirectional'>('bidirectional');
  const [reachResults, setReachResults] = useState<ConnectivityAnalysis[]>([]);

  useEffect(() => {
    if (!dirty) setPolicies(parseConnectivityPolicies(caseInfo.metadata));
  }, [caseInfo.metadata, dirty]);
  useEffect(() => {
    if (!form.sourceNetworkId && inventory.networks[0]) {
      setForm((value) => ({ ...value, sourceNetworkId: inventory.networks[0].id }));
      setReachSource(inventory.networks[0].id);
    }
  }, [form.sourceNetworkId, inventory.networks]);

  const evaluations = useMemo(
    () => policies.filter((item) => item.enabled).map((policy) => evaluatePolicy(inventory, policy)),
    [inventory, policies],
  );

  const addPolicy = () => {
    if (!form.name.trim() || !form.sourceNetworkId) {
      toast.error('Policy name and source network are required');
      return;
    }
    const targetKind = form.target === 'internet' ? 'internet' : 'network';
    setPolicies((items) => [...items, {
      id: uuidv4(),
      name: form.name.trim(),
      sourceNetworkId: form.sourceNetworkId,
      targetKind,
      targetNetworkId: targetKind === 'network' ? form.target : undefined,
      direction: form.direction,
      mode: form.mode,
      expectation: form.expectation,
      enabled: true,
      description: form.description.trim(),
    }]);
    setDirty(true);
    setForm((value) => ({ ...value, name: '', description: '' }));
  };

  const removePolicy = (id: string) => {
    setPolicies((items) => items.filter((item) => item.id !== id));
    setDirty(true);
  };

  const savePolicies = async () => {
    setBusy(true);
    try {
      const metadata = metadataWithConnectivityPolicies(caseInfo.metadata, policies);
      const document = JSON.stringify({
        format: 'dfir-investigator-partial',
        format_version: 1,
        case_id: caseInfo.id,
        source: 'Topology connectivity compliance policies',
        changes: [{
          change_id: 'connectivity-policies',
          entity_type: 'case',
          operation: 'update',
          target_id: caseInfo.id,
          values: { metadata, updated_at: new Date().toISOString() },
        }],
      });
      const previewResponse = await invoke<ApiResponse<PartialImportPreview>>('preview_partial_import_text', { jsonData: document });
      if (!previewResponse.success || !previewResponse.data) throw new Error(previewResponse.error || 'Could not prepare policy changes');
      const selected = previewResponse.data.changes
        .filter((item) => item.valid && ['create', 'update'].includes(item.operation))
        .map((item) => item.id);
      if (!selected.length) {
        await invoke<ApiResponse<boolean>>('discard_pending_partial_import', { previewId: previewResponse.data.preview_id });
        setDirty(false);
        toast.info('Connectivity policies are already up to date');
        return;
      }
      const response = await invoke<ApiResponse<PartialApplySummary>>('apply_pending_partial_import', {
        previewId: previewResponse.data.preview_id,
        selectedChangeIds: selected,
      });
      if (!response.success) throw new Error(response.error || 'Could not save connectivity policies');
      setDirty(false);
      await onChanged();
      toast.success('Connectivity compliance policies saved to the case');
    } catch (reason) {
      toast.error(String(reason));
    } finally {
      setBusy(false);
    }
  };

  const runReachability = () => {
    if (!reachSource) {
      toast.error('Select a source network');
      return;
    }
    const target = reachTarget === 'internet' ? INTERNET_NODE_ID : reachTarget;
    const directions: ConnectivityDirection[] = reachDirection === 'bidirectional'
      ? ['outbound', 'inbound']
      : [reachDirection];
    setReachResults(directions.map((direction) =>
      analyzeConnectivity(inventory, reachSource, target, direction, 'logical')));
  };

  return (
    <Card className="border-indigo-200 bg-indigo-50/30">
      <CardHeader className="flex flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2 text-base"><SearchCheck size={18} />Verify connect</CardTitle>
          <p className="mt-1 text-xs text-slate-500">Compliance assertions and evidence-based path discovery are intentionally separate.</p>
        </div>
        <Button size="sm" variant="ghost" aria-label="Close connectivity verifier" onClick={onClose}><X size={16} /></Button>
      </CardHeader>
      <CardContent>
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList>
            <TabsTrigger value="compliance">1. Compliance isolation</TabsTrigger>
            <TabsTrigger value="reachability">2. Actual path analysis</TabsTrigger>
          </TabsList>
          <TabsContent value="compliance" className="space-y-4">
            <p className="text-xs text-slate-600">Define what must be connected or isolated. Physical checks ignore ACLs/routes; logical checks use imported routing, ACL, NAT, and asserted-link evidence.</p>
            <div className="grid gap-3 rounded-md border bg-white p-3 md:grid-cols-3 xl:grid-cols-6">
              <Field label="Policy name"><Input value={form.name} onChange={(event) => setForm((value) => ({ ...value, name: event.target.value }))} placeholder="PCI VLAN isolation" /></Field>
              <Field label="Source VLAN / network"><NetworkSelect value={form.sourceNetworkId} networks={inventory.networks} onChange={(sourceNetworkId) => setForm((value) => ({ ...value, sourceNetworkId }))} /></Field>
              <Field label="Target"><TargetSelect value={form.target} sourceId={form.sourceNetworkId} networks={inventory.networks} onChange={(target) => setForm((value) => ({ ...value, target }))} /></Field>
              <Field label="Direction">
                <Select value={form.direction} onValueChange={(direction: ConnectivityPolicy['direction']) => setForm((value) => ({ ...value, direction }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="outbound">Outbound</SelectItem><SelectItem value="inbound">Inbound</SelectItem><SelectItem value="bidirectional">Both</SelectItem></SelectContent>
                </Select>
              </Field>
              <Field label="Check layer">
                <Select value={form.mode} onValueChange={(mode: ConnectivityMode) => setForm((value) => ({ ...value, mode }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="physical">Physical attachment</SelectItem><SelectItem value="logical">Logical reachability</SelectItem></SelectContent>
                </Select>
              </Field>
              <Field label="Requirement">
                <Select value={form.expectation} onValueChange={(expectation: ConnectivityPolicy['expectation']) => setForm((value) => ({ ...value, expectation }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="blocked">Must be blocked</SelectItem><SelectItem value="allowed">Must be allowed</SelectItem></SelectContent>
                </Select>
              </Field>
              <div className="md:col-span-2 xl:col-span-5"><Field label="Description (optional)"><Input value={form.description} onChange={(event) => setForm((value) => ({ ...value, description: event.target.value }))} /></Field></div>
              <div className="flex items-end"><Button onClick={addPolicy}><Plus size={16} />Add policy</Button></div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex gap-2 text-xs">
                <Badge variant="outline">{evaluations.filter((item) => item.status === 'pass').length} pass</Badge>
                <Badge variant="destructive">{evaluations.filter((item) => item.status === 'fail').length} fail</Badge>
                <Badge variant="outline">{evaluations.filter((item) => item.status === 'warning').length} review</Badge>
              </div>
              <Button size="sm" onClick={() => void savePolicies()} disabled={!dirty || busy}>
                {busy ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}Save policies to case
              </Button>
            </div>
            {policies.length ? (
              <div className="space-y-2">
                {policies.map((policy) => {
                  const evaluation = evaluations.find((item) => item.policy.id === policy.id);
                  return <PolicyRow key={policy.id} evaluation={evaluation} policy={policy} inventory={inventory} onRemove={() => removePolicy(policy.id)} />;
                })}
              </div>
            ) : <EmptyState text="No compliance assertions yet. Add the first required isolation or connectivity rule above." />}
          </TabsContent>

          <TabsContent value="reachability" className="space-y-4">
            <p className="text-xs text-slate-600">Find every simple path the normalized model can support. “Confirmed” needs explicit route/policy/NAT evidence; “possible” means an unresolved object or missing control still leaves a route plausible.</p>
            <div className="grid gap-3 rounded-md border bg-white p-3 md:grid-cols-[1fr_1fr_180px_auto]">
              <Field label="Investigated VLAN / network"><NetworkSelect value={reachSource} networks={inventory.networks} onChange={setReachSource} /></Field>
              <Field label="Internet or peer network"><TargetSelect value={reachTarget} sourceId={reachSource} networks={inventory.networks} onChange={setReachTarget} /></Field>
              <Field label="Direction">
                <Select value={reachDirection} onValueChange={(value: ConnectivityDirection | 'bidirectional') => setReachDirection(value)}>
                  <SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="outbound">Outbound</SelectItem><SelectItem value="inbound">Inbound</SelectItem><SelectItem value="bidirectional">Both</SelectItem></SelectContent>
                </Select>
              </Field>
              <div className="flex items-end"><Button onClick={runReachability}><Route size={16} />Find paths</Button></div>
            </div>
            {reachResults.length ? reachResults.map((analysis) => (
              <AnalysisResult key={analysis.direction} analysis={analysis} inventory={inventory} />
            )) : <EmptyState text="Choose a source and direction, then run path analysis." />}
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}

function PolicyRow({
  evaluation,
  policy,
  inventory,
  onRemove,
}: {
  evaluation?: PolicyEvaluation;
  policy: ConnectivityPolicy;
  inventory: ConnectivityInventory;
  onRemove: () => void;
}) {
  const source = inventory.networks.find((item) => item.id === policy.sourceNetworkId)?.name ?? 'Missing source';
  const target = policy.targetKind === 'internet'
    ? 'Internet'
    : inventory.networks.find((item) => item.id === policy.targetNetworkId)?.name ?? 'Missing target';
  return (
    <div className="rounded-md border bg-white p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 gap-2">
          <StatusIcon status={evaluation?.status ?? 'warning'} />
          <div>
            <div className="font-medium">{policy.name}</div>
            <div className="text-xs text-slate-600">{source} → {target} · {policy.direction} · {policy.mode} · must be {policy.expectation}</div>
            <div className="mt-1 text-xs">{evaluation?.summary ?? 'Disabled policy'}</div>
            {policy.description && <div className="mt-1 text-xs text-slate-400">{policy.description}</div>}
          </div>
        </div>
        <Button size="sm" variant="ghost" aria-label={`Delete ${policy.name}`} onClick={onRemove}><Trash2 size={15} /></Button>
      </div>
      {evaluation && evaluation.analyses.some((item) => item.paths.length > 0) && (
        <details className="mt-2 text-xs"><summary className="cursor-pointer text-indigo-700">Show detected paths</summary>
          <div className="mt-2 space-y-2">{evaluation.analyses.map((analysis) => <CompactPaths key={analysis.direction} analysis={analysis} inventory={inventory} />)}</div>
        </details>
      )}
    </div>
  );
}

function AnalysisResult({ analysis, inventory }: { analysis: ConnectivityAnalysis; inventory: ConnectivityInventory }) {
  return (
    <div className="rounded-md border bg-white p-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="font-medium capitalize">{analysis.direction}: {networkName(analysis.direction === 'outbound' ? analysis.sourceNetworkId : analysis.targetNetworkId, inventory)} → {networkName(analysis.direction === 'outbound' ? analysis.targetNetworkId : analysis.sourceNetworkId, inventory)}</div>
        <div className="flex gap-2">
          <Badge variant="outline">{analysis.paths.filter((item) => item.certainty === 'confirmed').length} confirmed</Badge>
          <Badge variant="outline">{analysis.paths.filter((item) => item.certainty === 'possible').length} possible</Badge>
        </div>
      </div>
      {analysis.paths.length ? <CompactPaths analysis={analysis} inventory={inventory} /> : <div className="rounded bg-slate-50 p-3 text-xs text-slate-500">No logical path was found in the imported model.</div>}
      {analysis.warnings.map((warning) => <div key={warning} className="mt-2 flex gap-1 text-xs text-amber-800"><AlertTriangle size={14} className="shrink-0" />{warning}</div>)}
    </div>
  );
}

function CompactPaths({ analysis, inventory }: { analysis: ConnectivityAnalysis; inventory: ConnectivityInventory }) {
  return <div className="space-y-2">{analysis.paths.map((path, pathIndex) => (
    <div key={path.id || pathIndex} className="rounded border p-2 text-xs">
      <div className="mb-1 flex items-center gap-2"><Badge variant={path.certainty === 'confirmed' ? 'default' : 'outline'}>{path.certainty}</Badge><span>Path {pathIndex + 1}</span></div>
      <div className="mb-2 font-medium text-slate-700">{path.networkIds.map((id) => networkName(id, inventory)).join(' → ')}</div>
      <ol className="space-y-1 border-l-2 border-indigo-100 pl-3">
        {path.steps.map((step, index) => (
          <li key={`${step.fromNetworkId}-${step.toNetworkId}-${step.via}-${index}`}>
            <span className="font-medium">{step.via}</span>: {step.evidence.join('; ')}
          </li>
        ))}
      </ol>
    </div>
  ))}</div>;
}

function networkName(id: string, inventory: ConnectivityInventory): string {
  if (id === INTERNET_NODE_ID) return 'Internet';
  return inventory.networks.find((item) => item.id === id)?.name ?? id;
}

function StatusIcon({ status }: { status: PolicyEvaluation['status'] }) {
  if (status === 'pass') return <CheckCircle2 size={20} className="shrink-0 text-emerald-600" />;
  if (status === 'fail') return <XCircle size={20} className="shrink-0 text-red-600" />;
  return <AlertTriangle size={20} className="shrink-0 text-amber-600" />;
}

function NetworkSelect({ value, networks, onChange }: { value: string; networks: ConnectivityInventory['networks']; onChange: (value: string) => void }) {
  return <Select value={value} onValueChange={onChange}><SelectTrigger><SelectValue placeholder="Select network" /></SelectTrigger><SelectContent>{networks.map((item) => <SelectItem key={item.id} value={item.id}>{item.name} {item.vlan_id ? `(VLAN ${item.vlan_id})` : ''}</SelectItem>)}</SelectContent></Select>;
}

function TargetSelect({ value, sourceId, networks, onChange }: { value: string; sourceId: string; networks: ConnectivityInventory['networks']; onChange: (value: string) => void }) {
  return <Select value={value} onValueChange={onChange}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="internet">Internet</SelectItem>{networks.filter((item) => item.id !== sourceId).map((item) => <SelectItem key={item.id} value={item.id}>{item.name}</SelectItem>)}</SelectContent></Select>;
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return <div className="space-y-1"><Label>{label}</Label>{children}</div>;
}

function EmptyState({ text }: { text: string }) {
  return <div className="rounded-md border border-dashed bg-white p-6 text-center text-sm text-slate-400">{text}</div>;
}
