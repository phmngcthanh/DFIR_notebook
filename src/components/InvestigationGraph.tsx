import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { invoke } from '@/lib/api';
import CytoscapeComponent from 'react-cytoscapejs';
import type cytoscape from 'cytoscape';
import { Crosshair, Download, Eye, Filter, Maximize2, RefreshCw, Route, Save, Trash2, ZoomIn, ZoomOut } from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { buildTopologyLayout } from '@/lib/topology-layout';
import {
  applyVisibility, buildInvestigationElements, DEFAULT_DISPLAY, DEFAULT_FILTERS,
  orderAttackPath, parseViewState, playbackSlice,
} from '@/lib/investigation-graph';
import AttackEdgeForm, { type EndpointRef } from '@/components/investigation/AttackEdgeForm';
import EntityInspector, { type SelectedEntity } from '@/components/investigation/EntityInspector';
import SightingForm from '@/components/investigation/SightingForm';
import type {
  ApiResponse, Asset, AttackEdge, CompromiseStatus, Firewall, FirewallInterface, InfectionSummary,
  InvestigationView, InvestigationViewDisplay, InvestigationViewFilters, InvestigationViewState,
  InvestigationViewSummary, Ioc, Network, NetworkConnection, NetworkInterface, SightingEntityKind,
  TimelineEvent, TopologyLayoutName, TopologyNodePosition,
} from '@/types';

interface Props { refreshTrigger: number }

const STYLESHEET: cytoscape.StylesheetJson = [
  { selector: 'node', style: { label: 'data(label)', 'text-valign': 'center', 'text-halign': 'center', 'text-wrap': 'wrap', 'text-max-width': '126px', 'font-size': 11, color: '#1e293b', 'text-outline-color': '#fff', 'text-outline-width': 2, 'border-width': 2 } },
  { selector: 'node.network', style: { shape: 'roundrectangle', 'background-color': '#f0f9ff', 'background-opacity': 0.78, 'border-color': '#0891b2', 'border-width': 3, padding: '28px', 'compound-sizing-wrt-labels': 'include', label: 'data(label)', 'text-valign': 'top', 'text-margin-y': -10, 'text-max-width': '220px', 'font-size': 13, 'font-weight': 600 } },
  { selector: 'node.network[kind="dmz"]', style: { 'background-color': '#fff7ed', 'border-color': '#ea580c' } },
  { selector: 'node.network[kind="dms"]', style: { 'background-color': '#fefce8', 'border-color': '#ca8a04' } },
  { selector: 'node.network[kind="wan"]', style: { 'background-color': '#eff6ff', 'border-color': '#2563eb' } },
  { selector: 'node.asset', style: { shape: 'roundrectangle', width: 128, height: 58, 'background-color': '#fff', 'border-color': '#64748b' } },
  { selector: 'node.asset[compromise="suspected"]', style: { 'background-color': '#fffbeb', 'border-color': '#d97706', 'border-width': 4 } },
  { selector: 'node.asset[compromise="infected"]', style: { 'background-color': '#fef2f2', 'border-color': '#dc2626', 'border-width': 4 } },
  { selector: 'node.firewall', style: { shape: 'hexagon', width: 126, height: 70, 'background-color': '#fef3c7', 'border-color': '#d97706', 'border-width': 3 } },
  { selector: 'node.external', style: { shape: 'ellipse', width: 120, height: 62, 'background-color': '#1e293b', 'border-color': '#dc2626', 'border-width': 3, color: '#f8fafc', 'text-outline-color': '#1e293b' } },
  { selector: 'node.layout-anchor', style: { width: 1, height: 1, opacity: 0, label: '' } },
  { selector: 'node.draw-source', style: { 'overlay-color': '#dc2626', 'overlay-opacity': 0.25, 'overlay-padding': 10 } },
  { selector: 'edge', style: { width: 2, 'line-color': '#94a3b8', 'target-arrow-color': '#94a3b8', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier', 'font-size': 9, color: '#334155', 'text-background-color': '#fff', 'text-background-opacity': 0.92, 'text-background-padding': '3px', 'text-rotation': 'autorotate' } },
  { selector: 'edge.network-link', style: { label: 'data(label)', 'line-style': 'dashed', 'line-color': '#0891b2', 'target-arrow-color': '#0891b2', width: 3, opacity: 0.5, 'curve-style': 'unbundled-bezier', 'control-point-distances': 55 } },
  { selector: 'edge.secondary-nic', style: { label: '', 'line-style': 'dotted', 'line-color': '#7c3aed', 'target-arrow-color': '#7c3aed', width: 2, opacity: 0.4 } },
  { selector: 'edge.firewall-nic', style: { label: '', 'line-style': 'dotted', 'line-color': '#d97706', 'target-arrow-color': '#d97706', width: 2, opacity: 0.45 } },
  { selector: 'edge.attack-edge', style: { label: 'data(label)', 'line-color': '#dc2626', 'target-arrow-color': '#dc2626', width: 4, 'font-size': 10, 'font-weight': 700, color: '#991b1b', 'z-index': 20, 'curve-style': 'unbundled-bezier', 'control-point-distances': -40 } },
  { selector: 'edge.attack-edge[confidence="probable"]', style: { 'line-style': 'dashed' } },
  { selector: 'edge.attack-edge[confidence="suspected"]', style: { 'line-style': 'dotted' } },
  { selector: 'edge.playback-dim', style: { opacity: 0.08, label: '' } },
  { selector: 'edge.playback-active', style: { width: 6, 'z-index': 30 } },
  { selector: 'edge:selected', style: { label: 'data(label)', opacity: 1, width: 5, 'z-index': 40 } },
  { selector: ':selected', style: { 'overlay-color': '#0ea5e9', 'overlay-opacity': 0.15, 'overlay-padding': 8 } },
];

const LAYOUT_LABELS: Record<TopologyLayoutName, string> = {
  dagre: 'Hierarchical', grid: 'Grid', circle: 'Circle', concentric: 'Concentric', breadthfirst: 'Breadth-first',
};
const COMPROMISE_OPTIONS: CompromiseStatus[] = ['unknown', 'clean', 'suspected', 'infected'];
const NO_VIEW = '__none__';

type EdgeFormState = { edge?: AttackEdge; prefill?: { source?: EndpointRef; target?: { kind: SightingEntityKind; id: string } } } | null;

export default function InvestigationGraph({ refreshTrigger }: Props) {
  const cyRef = useRef<cytoscape.Core | null>(null);
  const wiredCyRef = useRef<cytoscape.Core | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const applyingViewRef = useRef(false);
  const pendingViewRef = useRef<InvestigationViewState | null>(null);
  const drawSourceRef = useRef<SelectedEntity | null>(null);
  const drawModeRef = useRef(false);

  const [networks, setNetworks] = useState<Network[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [firewalls, setFirewalls] = useState<Firewall[]>([]);
  const [firewallInterfaces, setFirewallInterfaces] = useState<FirewallInterface[]>([]);
  const [iocs, setIocs] = useState<Ioc[]>([]);
  const [attackEdges, setAttackEdges] = useState<AttackEdge[]>([]);
  const [infection, setInfection] = useState<InfectionSummary>({ entities: [], iocs: [] });
  const [timelineEvents, setTimelineEvents] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState(false);

  const [layout, setLayout] = useState<TopologyLayoutName>('dagre');
  const [hiddenNetworkIds, setHiddenNetworkIds] = useState<string[]>([]);
  const [hiddenNodeIds, setHiddenNodeIds] = useState<string[]>([]);
  const [filters, setFilters] = useState<InvestigationViewFilters>({ ...DEFAULT_FILTERS });
  const [display, setDisplay] = useState<InvestigationViewDisplay>({ ...DEFAULT_DISPLAY });
  const [showFilters, setShowFilters] = useState(false);
  const [showHidden, setShowHidden] = useState(false);
  const [playStep, setPlayStep] = useState<number | null>(null);
  const [drawMode, setDrawMode] = useState(false);
  const [drawSource, setDrawSource] = useState<SelectedEntity | null>(null);
  const [selected, setSelected] = useState<SelectedEntity | null>(null);
  const [sightingTarget, setSightingTarget] = useState<SelectedEntity | null>(null);
  const [edgeForm, setEdgeForm] = useState<EdgeFormState>(null);
  const [inspectorToken, setInspectorToken] = useState(0);

  const [views, setViews] = useState<InvestigationViewSummary[]>([]);
  const [currentViewId, setCurrentViewId] = useState<string>(NO_VIEW);
  const [viewName, setViewName] = useState('');
  const [saving, setSaving] = useState(false);

  drawModeRef.current = drawMode;
  drawSourceRef.current = drawSource;

  const loadViews = useCallback(async () => {
    try {
      const response = await invoke<ApiResponse<InvestigationViewSummary[]>>('list_investigation_views');
      if (!response.success) throw new Error(response.error);
      setViews(response.data ?? []);
    } catch (reason) { toast.error(String(reason)); }
  }, []);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [networkR, assetR, interfaceR, connectionR, firewallR, firewallInterfaceR, iocR, edgeR, infectionR, timelineR] = await Promise.all([
        invoke<ApiResponse<Network[]>>('list_networks'),
        invoke<ApiResponse<Asset[]>>('list_assets'),
        invoke<ApiResponse<NetworkInterface[]>>('list_network_interfaces', { assetId: null }),
        invoke<ApiResponse<NetworkConnection[]>>('list_network_connections'),
        invoke<ApiResponse<Firewall[]>>('list_firewalls'),
        invoke<ApiResponse<FirewallInterface[]>>('list_firewall_interfaces', { firewallId: null }),
        invoke<ApiResponse<Ioc[]>>('list_iocs'),
        invoke<ApiResponse<AttackEdge[]>>('list_attack_edges'),
        invoke<ApiResponse<InfectionSummary>>('get_infection_summary'),
        invoke<ApiResponse<TimelineEvent[]>>('list_timeline_events'),
      ]);
      for (const response of [networkR, assetR, interfaceR, connectionR, firewallR, firewallInterfaceR, iocR, edgeR, infectionR, timelineR]) {
        if (!response.success) throw new Error(response.error);
      }
      setNetworks(networkR.data ?? []); setAssets(assetR.data ?? []); setInterfaces(interfaceR.data ?? []);
      setConnections(connectionR.data ?? []); setFirewalls(firewallR.data ?? []); setFirewallInterfaces(firewallInterfaceR.data ?? []);
      setIocs(iocR.data ?? []); setAttackEdges(edgeR.data ?? []); setInfection(infectionR.data ?? { entities: [], iocs: [] });
      setTimelineEvents(timelineR.data ?? []);
    } catch (reason) { toast.error(String(reason)); } finally { setLoading(false); }
  }, []);

  useEffect(() => { void loadData(); void loadViews(); }, [loadData, loadViews, refreshTrigger]);

  const reloadEvidence = useCallback(async () => {
    await loadData();
    setInspectorToken((value) => value + 1);
  }, [loadData]);

  const elements = useMemo(() => buildInvestigationElements({
    networks, assets, firewalls, connections, interfaces, firewallInterfaces, attackEdges, infection,
  }), [networks, assets, firewalls, connections, interfaces, firewallInterfaces, attackEdges, infection]);

  const orderedEdges = useMemo(() => orderAttackPath(attackEdges), [attackEdges]);

  const automaticLayout = useMemo(
    () => buildTopologyLayout(layout, { networks, assets, firewalls, connections }),
    [layout, networks, assets, firewalls, connections],
  );

  const visibility = useMemo(
    () => applyVisibility(elements, { hidden_network_ids: hiddenNetworkIds, hidden_node_ids: hiddenNodeIds, filters, display }),
    [elements, hiddenNetworkIds, hiddenNodeIds, filters, display],
  );

  const applyPositions = useCallback((view?: InvestigationViewState | null, fit = true) => {
    const cy = cyRef.current;
    if (!cy) return;
    applyingViewRef.current = true;
    const savedPositions = new Map((view?.positions ?? []).map((position) => [position.id, position]));
    cy.batch(() => {
      Object.entries(automaticLayout.networkBounds).forEach(([networkId, bounds]) => {
        const insetX = Math.max(1, bounds.width / 2 - 16);
        const insetY = Math.max(1, bounds.height / 2 - 16);
        const corners: Record<string, { x: number; y: number }> = {
          nw: { x: bounds.x - insetX, y: bounds.y - insetY }, ne: { x: bounds.x + insetX, y: bounds.y - insetY },
          sw: { x: bounds.x - insetX, y: bounds.y + insetY }, se: { x: bounds.x + insetX, y: bounds.y + insetY },
        };
        Object.entries(corners).forEach(([corner, position]) => cy.getElementById(`network-boundary-${networkId}-${corner}`).position(position));
      });
      Object.entries(automaticLayout.positions).forEach(([id, position]) => {
        const node = cy.getElementById(id);
        if (node.nonempty() && !node.isParent()) node.position(position);
      });
      // External origin nodes have no topology home: stack them above the graph.
      const externals = cy.nodes('.external');
      const top = Math.min(...Object.values(automaticLayout.positions).map((position) => position.y), 0) - 220;
      externals.forEach((node, index) => { node.position({ x: index * 220, y: top }); });
      savedPositions.forEach((position, id) => {
        const node = cy.getElementById(id);
        if (node.nonempty() && !node.isParent()) node.position({ x: position.x, y: position.y });
      });
    });
    cy.resize();
    if (view) {
      cy.zoom(view.zoom);
      cy.pan({ x: view.pan_x, y: view.pan_y });
    } else if (fit) {
      cy.fit(cy.elements().not('.layout-anchor'), 64);
    }
    window.requestAnimationFrame(() => { applyingViewRef.current = false; });
  }, [automaticLayout]);

  useEffect(() => {
    if (!cyRef.current || elements.length === 0) return;
    const frame = window.requestAnimationFrame(() => {
      const pending = pendingViewRef.current;
      pendingViewRef.current = null;
      applyPositions(pending, !pending);
    });
    return () => window.cancelAnimationFrame(frame);
  }, [applyPositions, elements, layout]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.elements().forEach((element) => {
        if (element.hasClass('layout-anchor')) return;
        element.style('display', visibility.visibleIds.has(element.id()) ? 'element' : 'none');
      });
    });
  }, [visibility, elements]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const active = playStep === null ? null : playbackSlice(orderedEdges, playStep);
    cy.batch(() => {
      cy.edges('.attack-edge').forEach((edge) => {
        edge.removeClass('playback-dim playback-active');
        if (active) edge.addClass(active.has(edge.id()) ? 'playback-active' : 'playback-dim');
      });
    });
  }, [playStep, orderedEdges, elements, visibility]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const observer = new ResizeObserver(() => cyRef.current?.resize());
    observer.observe(container);
    return () => observer.disconnect();
  }, []);

  const toSelected = (data: cytoscape.NodeDataDefinition): SelectedEntity | null => {
    const kind = data.entityKind as SelectedEntity['kind'] | undefined;
    if (!kind) return null;
    return {
      kind,
      id: String(data.entityId),
      label: String(data.label ?? '').split('\n')[0],
      nodeId: String(data.id),
      raw: data.rawData as Record<string, unknown> | undefined,
    };
  };

  const handleNodeTap = useCallback((data: cytoscape.NodeDataDefinition) => {
    const entity = toSelected(data);
    if (!entity) return;
    if (drawModeRef.current) {
      const source = drawSourceRef.current;
      if (!source) {
        setDrawSource(entity);
        cyRef.current?.getElementById(entity.nodeId).addClass('draw-source');
        toast.info(`Attack source: ${entity.label}. Now click the target.`);
        return;
      }
      if (entity.nodeId !== source.nodeId && entity.kind !== 'external') {
        setEdgeForm({
          prefill: {
            source: { kind: source.kind, id: source.id },
            target: { kind: entity.kind, id: entity.id },
          },
        });
      }
      cyRef.current?.getElementById(source.nodeId).removeClass('draw-source');
      setDrawSource(null);
      setDrawMode(false);
      return;
    }
    setSelected(entity);
  }, []);

  const wireCytoscape = (instance: cytoscape.Core) => {
    cyRef.current = instance;
    if (wiredCyRef.current === instance) return;
    wiredCyRef.current = instance;
    instance.on('tap', 'node:not(.layout-anchor)', (event) => handleNodeTap(event.target.data()));
    instance.on('tap', 'edge.attack-edge', (event) => {
      const edge = (event.target.data() as { rawData?: AttackEdge }).rawData;
      if (edge) setEdgeForm({ edge });
    });
    instance.on('tap', (event) => { if (event.target === instance) setSelected(null); });
  };

  const collectViewState = (): InvestigationViewState => {
    const cy = cyRef.current;
    const positions: TopologyNodePosition[] = [];
    let zoom = 1; let panX = 0; let panY = 0;
    if (cy) {
      (cy.nodes().not('.network').not('.layout-anchor') as cytoscape.NodeCollection).forEach((node) => {
        const position = node.position();
        positions.push({ id: node.id(), x: position.x, y: position.y });
      });
      zoom = cy.zoom();
      const pan = cy.pan();
      panX = pan.x; panY = pan.y;
    }
    return {
      version: 1,
      hidden_network_ids: hiddenNetworkIds,
      hidden_node_ids: hiddenNodeIds,
      filters,
      display,
      layout,
      positions,
      zoom,
      pan_x: panX,
      pan_y: panY,
    };
  };

  const saveView = async (asNew: boolean) => {
    const name = viewName.trim();
    if (!name) { toast.error('Give the view a name first'); return; }
    setSaving(true);
    try {
      const response = await invoke<ApiResponse<InvestigationView>>('save_investigation_view', {
        id: asNew || currentViewId === NO_VIEW ? null : currentViewId,
        name,
        description: '',
        viewState: collectViewState(),
      });
      if (!response.success) throw new Error(response.error || 'Could not save view');
      setCurrentViewId(response.data?.id ?? NO_VIEW);
      toast.success(`View "${name}" saved`);
      await loadViews();
    } catch (reason) { toast.error(String(reason)); } finally { setSaving(false); }
  };

  const loadView = async (id: string) => {
    setCurrentViewId(id);
    if (id === NO_VIEW) { setViewName(''); return; }
    try {
      const response = await invoke<ApiResponse<InvestigationView>>('get_investigation_view', { id });
      if (!response.success || !response.data) throw new Error(response.error || 'Could not load view');
      const state = parseViewState(response.data.state);
      setViewName(response.data.name);
      setHiddenNetworkIds(state.hidden_network_ids);
      setHiddenNodeIds(state.hidden_node_ids);
      setFilters(state.filters);
      setDisplay(state.display);
      pendingViewRef.current = state;
      setLayout(state.layout);
      // Same layout: the elements effect will not rerun, so apply directly.
      window.requestAnimationFrame(() => {
        if (pendingViewRef.current) {
          const pending = pendingViewRef.current;
          pendingViewRef.current = null;
          applyPositions(pending, false);
        }
      });
      toast.success(`View "${response.data.name}" loaded`);
    } catch (reason) { toast.error(String(reason)); }
  };

  const deleteView = async () => {
    if (currentViewId === NO_VIEW || !confirm('Delete this saved view?')) return;
    try {
      const response = await invoke<ApiResponse<boolean>>('remove_investigation_view', { id: currentViewId });
      if (!response.success) throw new Error(response.error || 'Could not delete view');
      setCurrentViewId(NO_VIEW);
      setViewName('');
      await loadViews();
      toast.success('View deleted');
    } catch (reason) { toast.error(String(reason)); }
  };

  const changeZoom = (amount: number) => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.zoom(Math.min(4, Math.max(0.2, cy.zoom() + amount)));
  };
  const fitView = () => cyRef.current?.fit(cyRef.current.elements().not('.layout-anchor').filter((element) => element.style('display') !== 'none'), 64);
  const exportPng = () => {
    if (!cyRef.current) return;
    const link = document.createElement('a');
    link.download = 'investigation-graph.png';
    link.href = cyRef.current.png({ bg: 'white', full: true, scale: 2 });
    link.click();
  };

  const toggleDrawMode = () => {
    if (drawMode && drawSource) cyRef.current?.getElementById(drawSource.nodeId).removeClass('draw-source');
    setDrawSource(null);
    setDrawMode((value) => !value);
    if (!drawMode) toast.info('Draw mode: click the source node, then the target node.');
  };

  const toggleCompromiseFilter = (status: CompromiseStatus) => setFilters((current) => ({
    ...current,
    compromise: current.compromise.includes(status)
      ? current.compromise.filter((item) => item !== status)
      : [...current.compromise, status],
  }));

  const sidePanel = sightingTarget
    ? <SightingForm entityKind={sightingTarget.kind as SightingEntityKind} entityId={sightingTarget.id} entityName={sightingTarget.label} iocs={iocs}
        onSaved={() => { setSightingTarget(null); void reloadEvidence(); }} onCancel={() => setSightingTarget(null)} />
    : edgeForm
      ? <AttackEdgeForm edge={edgeForm.edge} prefill={edgeForm.prefill} networks={networks} assets={assets} firewalls={firewalls} iocs={iocs} timelineEvents={timelineEvents}
          onSaved={() => { setEdgeForm(null); void reloadEvidence(); }} onCancel={() => setEdgeForm(null)} />
      : selected
        ? <EntityInspector entity={selected} attackEdges={attackEdges} timelineEvents={timelineEvents} refreshToken={inspectorToken}
            onHideNode={(nodeId) => { setHiddenNodeIds((current) => current.includes(nodeId) ? current : [...current, nodeId]); setSelected(null); }}
            onHideNetwork={(networkId) => { setHiddenNetworkIds((current) => current.includes(networkId) ? current : [...current, networkId]); setSelected(null); }}
            onRecordSighting={() => setSightingTarget(selected)}
            onDrawFromHere={() => { setDrawMode(true); setDrawSource(selected); cyRef.current?.getElementById(selected.nodeId).addClass('draw-source'); toast.info(`Attack source: ${selected.label}. Now click the target.`); }}
            onEditEdge={(edge) => setEdgeForm({ edge })}
            onSightingRemoved={() => void reloadEvidence()} />
        : null;

  return <div className="flex h-full flex-col space-y-3 p-6">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 className="flex items-center gap-2 text-2xl font-bold text-slate-800"><Route className="text-red-600" />Investigation Graph</h2>
        <p className="text-sm text-slate-500">Rebuild the intrusion: mark infected systems, draw attacker movement, and curate what the graph shows.</p>
      </div>
      <div className="flex flex-wrap items-center justify-end gap-2">
        <Select value={currentViewId} onValueChange={(value) => void loadView(value)}>
          <SelectTrigger className="w-44" aria-label="Saved view"><SelectValue placeholder="Saved views" /></SelectTrigger>
          <SelectContent>
            <SelectItem value={NO_VIEW}>No saved view</SelectItem>
            {views.map((view) => <SelectItem key={view.id} value={view.id}>{view.name}</SelectItem>)}
          </SelectContent>
        </Select>
        <Input className="w-40" placeholder="View name" value={viewName} onChange={(event) => setViewName(event.target.value)} aria-label="View name" />
        <Button size="sm" onClick={() => void saveView(false)} disabled={saving}><Save size={15} className="mr-1" />{currentViewId === NO_VIEW ? 'Save view' : 'Save'}</Button>
        {currentViewId !== NO_VIEW && <Button size="sm" variant="outline" onClick={() => void saveView(true)} disabled={saving}>Save as new</Button>}
        {currentViewId !== NO_VIEW && <Button size="sm" variant="outline" onClick={() => void deleteView()}><Trash2 size={15} className="text-red-500" /></Button>}
      </div>
    </div>

    <div className="flex flex-wrap items-center gap-2">
      <Button size="sm" variant={drawMode ? 'default' : 'outline'} className={drawMode ? 'bg-red-600 hover:bg-red-700' : ''} onClick={toggleDrawMode}><Crosshair size={15} className="mr-1" />{drawMode ? (drawSource ? 'Click target…' : 'Click source…') : 'Draw attack edge'}</Button>
      <Button size="sm" variant="outline" onClick={() => setEdgeForm({})}>Add attack edge</Button>
      <Button size="sm" variant={showFilters ? 'default' : 'outline'} onClick={() => setShowFilters((value) => !value)}><Filter size={15} className="mr-1" />Filters</Button>
      <Button size="sm" variant={showHidden ? 'default' : 'outline'} onClick={() => setShowHidden((value) => !value)}><Eye size={15} className="mr-1" />Hidden ({visibility.hiddenSummary.length})</Button>
      <Select value={layout} onValueChange={(value: TopologyLayoutName) => setLayout(value)}>
        <SelectTrigger className="w-36" aria-label="Graph layout"><SelectValue /></SelectTrigger>
        <SelectContent>{Object.entries(LAYOUT_LABELS).map(([value, label]) => <SelectItem key={value} value={value}>{label}</SelectItem>)}</SelectContent>
      </Select>
      <Button size="sm" variant="outline" title="Zoom in" aria-label="Zoom in" onClick={() => changeZoom(0.2)}><ZoomIn size={15} /></Button>
      <Button size="sm" variant="outline" title="Zoom out" aria-label="Zoom out" onClick={() => changeZoom(-0.2)}><ZoomOut size={15} /></Button>
      <Button size="sm" variant="outline" title="Fit graph" aria-label="Fit graph" onClick={fitView}><Maximize2 size={15} /></Button>
      <Button size="sm" variant="outline" title="Export PNG" aria-label="Export PNG" onClick={exportPng}><Download size={15} /></Button>
      <Button size="sm" variant="outline" title="Reload data" aria-label="Reload data" onClick={() => void reloadEvidence()} disabled={loading}><RefreshCw size={15} className={loading ? 'animate-spin' : ''} /></Button>
    </div>

    {showFilters && <Card><CardContent className="flex flex-wrap items-center gap-4 p-3 text-xs">
      <div className="flex items-center gap-2">
        <span className="font-semibold text-slate-600">Compromise:</span>
        {COMPROMISE_OPTIONS.map((status) => <label key={status} className="flex items-center gap-1">
          <input type="checkbox" checked={filters.compromise.includes(status)} onChange={() => toggleCompromiseFilter(status)} />{status}
        </label>)}
      </div>
      <label className="flex items-center gap-1"><input type="checkbox" checked={filters.only_with_sightings} onChange={(event) => setFilters((current) => ({ ...current, only_with_sightings: event.target.checked }))} />Only entities with IOC sightings</label>
      <div className="flex items-center gap-1">
        <Label className="text-xs">Min threat</Label>
        <Select value={filters.min_threat ?? 'any'} onValueChange={(value) => setFilters((current) => ({ ...current, min_threat: value === 'any' ? null : value }))}>
          <SelectTrigger className="h-8 w-24"><SelectValue /></SelectTrigger>
          <SelectContent>{['any', 'low', 'medium', 'high', 'critical'].map((value) => <SelectItem key={value} value={value}>{value}</SelectItem>)}</SelectContent>
        </Select>
      </div>
      <label className="flex items-center gap-1"><input type="checkbox" checked={display.show_topology_edges} onChange={(event) => setDisplay((current) => ({ ...current, show_topology_edges: event.target.checked }))} />Topology links</label>
      <label className="flex items-center gap-1"><input type="checkbox" checked={display.show_attack_edges} onChange={(event) => setDisplay((current) => ({ ...current, show_attack_edges: event.target.checked }))} />Attack edges</label>
      <Button size="sm" variant="ghost" onClick={() => { setFilters({ ...DEFAULT_FILTERS }); setDisplay({ ...DEFAULT_DISPLAY }); }}>Reset</Button>
    </CardContent></Card>}

    {showHidden && <Card><CardContent className="flex flex-wrap items-center gap-2 p-3 text-xs">
      {visibility.hiddenSummary.length === 0 ? <span className="text-slate-400">Nothing is hidden.</span> : visibility.hiddenSummary.map((item) => <Badge key={item.id} variant="outline" className="gap-1">
        {item.label}
        <span className="text-slate-400">({item.reason})</span>
        {item.reason !== 'filter' && <button className="ml-1 text-cyan-600 hover:underline" onClick={() => {
          if (item.reason === 'network') setHiddenNetworkIds((current) => current.filter((id) => id !== item.id.replace('network-', '')));
          else setHiddenNodeIds((current) => current.filter((id) => id !== item.id));
        }}>show</button>}
      </Badge>)}
      {(hiddenNodeIds.length > 0 || hiddenNetworkIds.length > 0) && <Button size="sm" variant="ghost" onClick={() => { setHiddenNodeIds([]); setHiddenNetworkIds([]); }}>Show all</Button>}
    </CardContent></Card>}

    <div className="flex min-h-0 flex-1 gap-4">
      <Card className="min-h-[520px] flex-1"><CardContent ref={containerRef} className="h-full overflow-hidden p-0">
        {elements.length
          ? <CytoscapeComponent elements={elements} stylesheet={STYLESHEET} style={{ width: '100%', height: '100%' }} layout={{ name: 'preset' }} minZoom={0.2} maxZoom={4} wheelSensitivity={0.25} cy={wireCytoscape} />
          : <div className="flex h-full items-center justify-center text-slate-400">Add networks and assets first, then rebuild the intrusion here.</div>}
      </CardContent></Card>
      {sidePanel && <div className="w-96 flex-shrink-0 overflow-y-auto">{sidePanel}</div>}
    </div>

    <Card><CardContent className="flex items-center gap-3 p-3 text-xs">
      <span className="font-semibold text-slate-600">Pathway playback</span>
      {orderedEdges.length === 0 ? <span className="text-slate-400">Draw attack edges to replay the intrusion.</span> : <>
        <input type="range" min={0} max={orderedEdges.length} value={playStep ?? orderedEdges.length} className="flex-1" aria-label="Playback step"
          onChange={(event) => setPlayStep(Number(event.target.value))} />
        <span className="w-28">{playStep === null ? `All ${orderedEdges.length} steps` : `Step ${playStep} / ${orderedEdges.length}`}</span>
        {playStep !== null && <span className="max-w-64 truncate text-slate-500">{playStep > 0 ? orderedEdges[playStep - 1]?.title : 'Before first step'}</span>}
        <Button size="sm" variant="ghost" onClick={() => setPlayStep(null)} disabled={playStep === null}>Clear</Button>
      </>}
    </CardContent></Card>
  </div>;
}
