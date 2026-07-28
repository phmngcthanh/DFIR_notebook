import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { invoke } from '@/lib/api';
import CytoscapeComponent from 'react-cytoscapejs';
import type cytoscape from 'cytoscape';
import { Download, FileUp, GitGraph, Maximize2, RefreshCw, RotateCcw, Save, SearchCheck, ZoomIn, ZoomOut } from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import ConfigImportPanel from '@/components/ConfigImportPanel';
import ConnectivityVerifier from '@/components/ConnectivityVerifier';
import ImportedDeviceDetails from '@/components/ImportedDeviceDetails';
import { buildTopologyLayout } from '@/lib/topology-layout';
import { readStoredDeviceConfig } from '@/lib/network-config';
import type {
  ApiResponse,
  Asset,
  Case,
  Firewall,
  FirewallInterface,
  FirewallNatRule,
  Network,
  NetworkConnection,
  NetworkInterface,
  TopologyLayoutName,
  TopologyNodePosition,
  TopologyViewState,
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
  { selector: 'node.asset.router', style: { shape: 'diamond', width: 116, height: 78, 'background-color': '#eef2ff', 'border-color': '#4f46e5', 'border-width': 3 } },
  { selector: 'node.asset.switch', style: { shape: 'rectangle', width: 132, height: 54, 'background-color': '#ecfeff', 'border-color': '#0e7490', 'border-width': 3 } },
  { selector: 'node.firewall', style: { shape: 'hexagon', width: 126, height: 70, 'background-color': '#fef3c7', 'border-color': '#d97706', 'border-width': 3 } },
  { selector: 'node.layout-anchor', style: { width: 1, height: 1, opacity: 0, label: '' } },
  { selector: 'edge', style: { width: 2, 'line-color': '#94a3b8', 'target-arrow-color': '#94a3b8', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier', 'font-size': 9, color: '#334155', 'text-background-color': '#fff', 'text-background-opacity': 0.92, 'text-background-padding': '3px', 'text-rotation': 'autorotate' } },
  { selector: 'edge.network-link', style: { label: 'data(label)', 'line-style': 'dashed', 'line-color': '#0891b2', 'target-arrow-color': '#0891b2', width: 4, 'curve-style': 'unbundled-bezier', 'control-point-distances': 55 } },
  { selector: 'edge.secondary-nic', style: { label: '', 'line-style': 'dotted', 'line-color': '#7c3aed', 'target-arrow-color': '#7c3aed', width: 2, opacity: 0.58 } },
  { selector: 'edge.firewall-nic', style: { label: '', 'line-style': 'dotted', 'line-color': '#d97706', 'target-arrow-color': '#d97706', width: 3, opacity: 0.68 } },
  { selector: 'edge:selected', style: { label: 'data(label)', opacity: 1, width: 5, 'z-index': 10 } },
  { selector: ':selected', style: { 'overlay-color': '#0ea5e9', 'overlay-opacity': 0.15, 'overlay-padding': 8 } },
];

const LAYOUT_LABELS: Record<TopologyLayoutName, string> = {
  dagre: 'Hierarchical',
  grid: 'Grid',
  circle: 'Circle',
  concentric: 'Concentric',
  breadthfirst: 'Breadth-first',
};

export default function NetworkTopology({ refreshTrigger }: Props) {
  const cyRef = useRef<cytoscape.Core | null>(null);
  const wiredCyRef = useRef<cytoscape.Core | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const applyingViewRef = useRef(false);
  const viewRequestRef = useRef(0);
  const [networks, setNetworks] = useState<Network[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [firewalls, setFirewalls] = useState<Firewall[]>([]);
  const [firewallInterfaces, setFirewallInterfaces] = useState<FirewallInterface[]>([]);
  const [firewallNatRules, setFirewallNatRules] = useState<FirewallNatRule[]>([]);
  const [caseInfo, setCaseInfo] = useState<Case | null>(null);
  const [layout, setLayout] = useState<TopologyLayoutName>('dagre');
  const [selectedNode, setSelectedNode] = useState<cytoscape.NodeDataDefinition | null>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [viewDirty, setViewDirty] = useState(false);
  const [hasSavedView, setHasSavedView] = useState(false);
  const [showImporter, setShowImporter] = useState(false);
  const [showVerifier, setShowVerifier] = useState(false);
  const [infrastructureOnly, setInfrastructureOnly] = useState(false);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [networkResponse, assetResponse, interfaceResponse, connectionResponse, firewallResponse, firewallInterfaceResponse, natResponse, caseResponse] = await Promise.all([
        invoke<ApiResponse<Network[]>>('list_networks'), invoke<ApiResponse<Asset[]>>('list_assets'),
        invoke<ApiResponse<NetworkInterface[]>>('list_network_interfaces', { assetId: null }),
        invoke<ApiResponse<NetworkConnection[]>>('list_network_connections'), invoke<ApiResponse<Firewall[]>>('list_firewalls'),
        invoke<ApiResponse<FirewallInterface[]>>('list_firewall_interfaces', { firewallId: null }),
        invoke<ApiResponse<FirewallNatRule[]>>('list_firewall_nat_rules', { firewallId: null }),
        invoke<ApiResponse<Case | null>>('get_current_case_info'),
      ]);
      for (const response of [networkResponse, assetResponse, interfaceResponse, connectionResponse, firewallResponse, firewallInterfaceResponse, natResponse, caseResponse]) {
        if (!response.success) throw new Error(response.error);
      }
      setNetworks(networkResponse.data ?? []); setAssets(assetResponse.data ?? []); setInterfaces(interfaceResponse.data ?? []);
      setConnections(connectionResponse.data ?? []); setFirewalls(firewallResponse.data ?? []);
      setFirewallInterfaces(firewallInterfaceResponse.data ?? []);
      setFirewallNatRules(natResponse.data ?? []);
      setCaseInfo(caseResponse.data ?? null);
    } catch (reason) { toast.error(String(reason)); } finally { setLoading(false); }
  }, []);

  useEffect(() => { void loadData(); }, [loadData, refreshTrigger]);

  const visibleAssets = useMemo(
    () => infrastructureOnly ? assets.filter((item) => ['router', 'switch'].includes(item.asset_type)) : assets,
    [assets, infrastructureOnly],
  );

  const automaticLayout = useMemo(
    () => buildTopologyLayout(layout, { networks, assets: visibleAssets, firewalls, connections }),
    [layout, networks, visibleAssets, firewalls, connections],
  );

  const elements = useMemo<cytoscape.ElementDefinition[]>(() => {
    const result: cytoscape.ElementDefinition[] = [];
    networks.forEach((network) => {
      const parent = `network-${network.id}`;
      result.push({ group: 'nodes', classes: 'network', data: { id: parent, label: `${network.name}\n${network.subnet || (network.vlan_id ? `VLAN ${network.vlan_id} · subnet unresolved` : 'Subnet unresolved')}`, kind: network.network_type.toLowerCase(), rawData: network } });
      for (const corner of ['nw', 'ne', 'sw', 'se']) {
        result.push({ group: 'nodes', classes: 'layout-anchor', selectable: false, grabbable: false, data: { id: `network-boundary-${network.id}-${corner}`, parent } });
      }
    });
    visibleAssets.forEach((asset) => result.push({ group: 'nodes', classes: `asset ${asset.asset_type}`, data: { id: `asset-${asset.id}`, label: `${asset.name}\n${['router', 'switch'].includes(asset.asset_type) ? asset.asset_type.toUpperCase() : asset.ip_address || 'No IP'}`, parent: asset.network_id ? `network-${asset.network_id}` : undefined, compromise: asset.compromise_status, rawData: asset } }));
    firewalls.forEach((firewall) => result.push({ group: 'nodes', classes: 'firewall', data: { id: `firewall-${firewall.id}`, label: `${firewall.name}\n${firewall.vendor ? `${firewall.vendor} ` : ''}Firewall`, parent: firewall.network_id ? `network-${firewall.network_id}` : undefined, rawData: firewall } }));
    connections.forEach((connection) => result.push({ group: 'edges', classes: 'network-link', data: { id: `connection-${connection.id}`, source: `network-${connection.source_network_id}`, target: `network-${connection.target_network_id}`, label: connection.device_name ? `${connection.connection_type} · ${connection.device_name}` : connection.connection_type, rawData: connection } }));
    const visibleAssetIds = new Set(visibleAssets.map((item) => item.id));
    interfaces.filter((item) => visibleAssetIds.has(item.asset_id) && !item.is_primary && item.network_id).forEach((item) => result.push({ group: 'edges', classes: 'secondary-nic', data: { id: `interface-edge-${item.id}`, source: `asset-${item.asset_id}`, target: `network-${item.network_id}`, label: `${item.name} · ${item.ip_address || 'L2'}`, rawData: item } }));
    firewallInterfaces.filter((item) => item.network_id && (!item.is_primary || !firewalls.find((firewall) => firewall.id === item.firewall_id)?.network_id)).forEach((item) => result.push({ group: 'edges', classes: 'firewall-nic', data: { id: `firewall-interface-edge-${item.id}`, source: `firewall-${item.firewall_id}`, target: `network-${item.network_id}`, label: `${item.name} · ${item.ip_addresses.join(', ')}`, rawData: item } }));
    return result;
  }, [networks, visibleAssets, firewalls, connections, interfaces, firewallInterfaces]);

  const applyPositions = useCallback((savedView?: TopologyViewState | null, fit = true) => {
    const cy = cyRef.current;
    if (!cy) return;
    applyingViewRef.current = true;
    const savedPositions = new Map((savedView?.positions ?? []).map((position) => [position.id, position]));
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
      savedPositions.forEach((position, id) => {
        const node = cy.getElementById(id);
        if (node.nonempty() && !node.isParent()) node.position({ x: position.x, y: position.y });
      });
    });
    cy.resize();
    if (savedView) {
      cy.zoom(savedView.zoom);
      cy.pan({ x: savedView.pan_x, y: savedView.pan_y });
    } else if (fit) {
      cy.fit(cy.elements().not('.layout-anchor'), 64);
    }
    window.requestAnimationFrame(() => { applyingViewRef.current = false; });
  }, [automaticLayout]);

  useEffect(() => {
    if (!cyRef.current || elements.length === 0) return;
    const requestId = ++viewRequestRef.current;
    const frame = window.requestAnimationFrame(() => {
      void invoke<ApiResponse<TopologyViewState | null>>('get_topology_view', { layout })
        .then((response) => {
          if (requestId !== viewRequestRef.current) return;
          if (!response.success) throw new Error(response.error);
          const saved = response.data ?? null;
          applyPositions(saved);
          setHasSavedView(Boolean(saved));
          setViewDirty(false);
        })
        .catch((reason) => toast.error(`Could not load ${LAYOUT_LABELS[layout]} view: ${String(reason)}`));
    });
    return () => window.cancelAnimationFrame(frame);
  }, [applyPositions, elements, layout]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const observer = new ResizeObserver(() => cyRef.current?.resize());
    observer.observe(container);
    return () => observer.disconnect();
  }, []);

  const saveView = async () => {
    const cy = cyRef.current;
    if (!cy) return;
    setSaving(true);
    try {
      const movableNodes = cy.nodes().not('.network') as cytoscape.NodeCollection;
      const positions: TopologyNodePosition[] = movableNodes.map((node) => {
        const position = node.position();
        return { id: node.id(), x: position.x, y: position.y };
      });
      const pan = cy.pan();
      const response = await invoke<ApiResponse<TopologyViewState>>('save_topology_view', {
        layout, positions, zoom: cy.zoom(), panX: pan.x, panY: pan.y,
      });
      if (!response.success) throw new Error(response.error);
      setHasSavedView(true);
      setViewDirty(false);
      toast.success(`${LAYOUT_LABELS[layout]} view saved to this case`);
    } catch (reason) { toast.error(`Could not save topology view: ${String(reason)}`); } finally { setSaving(false); }
  };

  const resetAutomaticLayout = () => {
    applyPositions(null);
    setViewDirty(true);
    toast.info('Automatic layout applied. Save to replace the stored view.');
  };

  const changeZoom = (amount: number) => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.zoom(Math.min(4, Math.max(0.2, cy.zoom() + amount)));
  };

  const fitView = () => cyRef.current?.fit(cyRef.current.elements().not('.layout-anchor'), 64);

  const exportPng = () => {
    if (!cyRef.current) return;
    const link = document.createElement('a'); link.download = 'network-topology.png'; link.href = cyRef.current.png({ bg: 'white', full: true, scale: 2 }); link.click();
  };

  const wireCytoscape = (instance: cytoscape.Core) => {
    cyRef.current = instance;
    if (wiredCyRef.current === instance) return;
    wiredCyRef.current = instance;
    instance.on('tap', 'node:not(.layout-anchor)', (event) => setSelectedNode(event.target.data()));
    instance.on('tap', (event) => { if (event.target === instance) setSelectedNode(null); });
    instance.on('dragfree', 'node:not(.layout-anchor)', () => {
      if (!applyingViewRef.current) setViewDirty(true);
    });
    instance.on('pan zoom', () => {
      if (!applyingViewRef.current) setViewDirty(true);
    });
  };

  const viewStatus = viewDirty ? 'Unsaved changes' : hasSavedView ? 'Saved view' : 'Automatic view';
  const selectedRawData = selectedNode?.rawData as Partial<Asset & Firewall> | undefined;
  const selectedConfig = readStoredDeviceConfig(selectedRawData?.properties ?? selectedRawData?.rules);
  const configInventory = caseInfo ? {
    caseId: caseInfo.id,
    networks,
    assets,
    networkInterfaces: interfaces,
    firewalls,
    firewallInterfaces,
    firewallNatRules,
  } : null;
  const connectivityInventory = {
    networks,
    connections,
    assets,
    networkInterfaces: interfaces,
    firewalls,
    firewallInterfaces,
    firewallNatRules,
  };

  return <div className="flex h-full flex-col space-y-4 p-6">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 className="flex items-center gap-2 text-2xl font-bold text-slate-800"><GitGraph className="text-cyan-600" />Network Topology</h2>
        <p className="text-sm text-slate-500">Zones are laid out independently to prevent overlap. Drag a device or an entire zone, then save this layout.</p>
      </div>
      <div className="flex flex-wrap items-center justify-end gap-2">
        <label className="flex items-center gap-1.5 rounded-md border px-2 py-1.5 text-xs text-slate-600"><input type="checkbox" checked={infrastructureOnly} onChange={(event) => setInfrastructureOnly(event.target.checked)} />Infrastructure only</label>
        <Button size="sm" variant={showImporter ? 'default' : 'outline'} onClick={() => { setShowImporter((value) => !value); setShowVerifier(false); }} disabled={!caseInfo}><FileUp size={16} />Import config</Button>
        <Button size="sm" variant={showVerifier ? 'default' : 'outline'} onClick={() => { setShowVerifier((value) => !value); setShowImporter(false); }} disabled={!caseInfo}><SearchCheck size={16} />Verify connect</Button>
        <Badge variant={viewDirty ? 'destructive' : 'outline'}>{viewStatus}</Badge>
        <Select value={layout} onValueChange={(value: TopologyLayoutName) => setLayout(value)}>
          <SelectTrigger className="w-36" aria-label="Topology layout"><SelectValue /></SelectTrigger>
          <SelectContent>{Object.entries(LAYOUT_LABELS).map(([value, label]) => <SelectItem key={value} value={value}>{label}</SelectItem>)}</SelectContent>
        </Select>
        <Button size="sm" variant="outline" title="Zoom in" aria-label="Zoom in" onClick={() => changeZoom(0.2)}><ZoomIn size={16} /></Button>
        <Button size="sm" variant="outline" title="Zoom out" aria-label="Zoom out" onClick={() => changeZoom(-0.2)}><ZoomOut size={16} /></Button>
        <Button size="sm" variant="outline" title="Fit topology" aria-label="Fit topology" onClick={fitView}><Maximize2 size={16} /></Button>
        <Button size="sm" variant="outline" title="Reset automatic layout" aria-label="Reset automatic layout" onClick={resetAutomaticLayout}><RotateCcw size={16} /></Button>
        <Button size="sm" variant="outline" title="Export PNG" aria-label="Export PNG" onClick={exportPng}><Download size={16} /></Button>
        <Button size="sm" variant="outline" title="Reload topology data" aria-label="Reload topology data" onClick={() => void loadData()} disabled={loading}><RefreshCw size={16} className={loading ? 'animate-spin' : ''} /></Button>
        <Button size="sm" title="Save positions and camera" onClick={() => void saveView()} disabled={saving || elements.length === 0}><Save size={16} />{saving ? 'Saving…' : 'Save view'}</Button>
      </div>
    </div>
    {showImporter && configInventory && <ConfigImportPanel inventory={configInventory} onApplied={loadData} onClose={() => setShowImporter(false)} />}
    {showVerifier && caseInfo && <ConnectivityVerifier caseInfo={caseInfo} inventory={connectivityInventory} onChanged={loadData} onClose={() => setShowVerifier(false)} />}
    <div className="flex min-h-0 flex-1 gap-4">
      <Card className="min-h-[600px] flex-1"><CardContent ref={containerRef} className="h-full overflow-hidden p-0">{elements.length ? <CytoscapeComponent elements={elements} stylesheet={STYLESHEET} style={{ width: '100%', height: '100%' }} layout={{ name: 'preset' }} minZoom={0.2} maxZoom={4} wheelSensitivity={0.25} cy={wireCytoscape} /> : <div className="flex h-full items-center justify-center text-slate-400">Add a network or asset to build the topology.</div>}</CardContent></Card>
      {selectedNode && <Card className="w-[430px] flex-shrink-0 overflow-hidden"><CardHeader><CardTitle className="text-sm">{String(selectedNode.label ?? 'Node details').split('\n')[0]}</CardTitle></CardHeader><CardContent className="max-h-[calc(100vh-240px)] space-y-3 overflow-auto text-xs"><Badge variant="outline">{selectedNode.compromise || selectedNode.kind || selectedConfig?.deviceType || 'network object'}</Badge>{selectedConfig && <ImportedDeviceDetails config={selectedConfig} />}{selectedNode.rawData && Object.entries(selectedNode.rawData as Record<string, unknown>).filter(([key, value]) => value != null && !['id', 'created_at', 'network_id', 'network_name', 'properties', 'rules', 'config_text'].includes(key)).map(([key, value]) => <div key={key} className="grid grid-cols-[110px_1fr] gap-2"><span className="text-slate-500">{key.replaceAll('_', ' ')}</span><span className="break-all font-mono">{String(value)}</span></div>)}</CardContent></Card>}
    </div>
  </div>;
}
