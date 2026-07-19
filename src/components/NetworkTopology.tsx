import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import CytoscapeComponent from 'react-cytoscapejs';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';
import { Download, GitGraph, RefreshCw, ZoomIn, ZoomOut } from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import type { ApiResponse, Asset, Firewall, FirewallInterface, Network, NetworkConnection, NetworkInterface } from '@/types';

cytoscape.use(dagre);

interface Props { refreshTrigger: number }
type LayoutName = 'dagre' | 'grid' | 'circle' | 'concentric' | 'breadthfirst';

const STYLESHEET: cytoscape.StylesheetJson = [
  { selector: 'node', style: { label: 'data(label)', 'text-valign': 'center', 'text-halign': 'center', 'text-wrap': 'wrap', 'text-max-width': '112px', 'font-size': 9, color: '#1e293b', 'text-outline-color': '#fff', 'text-outline-width': 2, 'border-width': 2 } },
  { selector: 'node.network', style: { shape: 'roundrectangle', 'background-color': '#f0f9ff', 'border-color': '#0891b2', 'border-width': 3, padding: '24px', 'compound-sizing-wrt-labels': 'include', label: 'data(label)', 'text-valign': 'top', 'text-max-width': '180px', 'font-size': 10 } },
  { selector: 'node.network[kind="dmz"]', style: { 'background-color': '#fff7ed', 'border-color': '#ea580c' } },
  { selector: 'node.network[kind="dms"]', style: { 'background-color': '#fefce8', 'border-color': '#ca8a04' } },
  { selector: 'node.network[kind="wan"]', style: { 'background-color': '#eff6ff', 'border-color': '#2563eb' } },
  { selector: 'node.asset', style: { shape: 'roundrectangle', width: 118, height: 52, 'background-color': '#f8fafc', 'border-color': '#64748b' } },
  { selector: 'node.asset[compromise="suspected"]', style: { 'background-color': '#fffbeb', 'border-color': '#d97706', 'border-width': 4 } },
  { selector: 'node.asset[compromise="infected"]', style: { 'background-color': '#fef2f2', 'border-color': '#dc2626', 'border-width': 4 } },
  { selector: 'node.firewall', style: { shape: 'hexagon', width: 112, height: 64, 'background-color': '#fef3c7', 'border-color': '#d97706', 'border-width': 3 } },
  { selector: 'edge', style: { width: 2, 'line-color': '#94a3b8', 'target-arrow-color': '#94a3b8', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier', label: 'data(label)', 'text-wrap': 'wrap', 'text-max-width': '120px', 'font-size': 8, color: '#475569', 'text-background-color': '#fff', 'text-background-opacity': 0.85, 'text-background-padding': '2px' } },
  { selector: 'edge.network-link', style: { 'line-style': 'dashed', 'line-color': '#0891b2', 'target-arrow-color': '#0891b2', width: 3 } },
  { selector: 'edge.secondary-nic', style: { 'line-style': 'dotted', 'line-color': '#7c3aed', 'target-arrow-color': '#7c3aed', width: 2 } },
  { selector: 'edge.firewall-nic', style: { 'line-style': 'dotted', 'line-color': '#d97706', 'target-arrow-color': '#d97706', width: 3 } },
  { selector: ':selected', style: { 'overlay-color': '#0ea5e9', 'overlay-opacity': 0.15, 'overlay-padding': 8 } },
];

export default function NetworkTopology({ refreshTrigger }: Props) {
  const cyRef = useRef<cytoscape.Core | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [networks, setNetworks] = useState<Network[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  const [firewalls, setFirewalls] = useState<Firewall[]>([]);
  const [firewallInterfaces, setFirewallInterfaces] = useState<FirewallInterface[]>([]);
  const [layout, setLayout] = useState<LayoutName>('dagre');
  const [selectedNode, setSelectedNode] = useState<cytoscape.NodeDataDefinition | null>(null);
  const [loading, setLoading] = useState(false);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [networkResponse, assetResponse, interfaceResponse, connectionResponse, firewallResponse, firewallInterfaceResponse] = await Promise.all([
        invoke<ApiResponse<Network[]>>('list_networks'), invoke<ApiResponse<Asset[]>>('list_assets'),
        invoke<ApiResponse<NetworkInterface[]>>('list_network_interfaces', { assetId: null }),
        invoke<ApiResponse<NetworkConnection[]>>('list_network_connections'), invoke<ApiResponse<Firewall[]>>('list_firewalls'),
        invoke<ApiResponse<FirewallInterface[]>>('list_firewall_interfaces', { firewallId: null }),
      ]);
      for (const response of [networkResponse, assetResponse, interfaceResponse, connectionResponse, firewallResponse, firewallInterfaceResponse]) {
        if (!response.success) throw new Error(response.error);
      }
      setNetworks(networkResponse.data ?? []); setAssets(assetResponse.data ?? []); setInterfaces(interfaceResponse.data ?? []);
      setConnections(connectionResponse.data ?? []); setFirewalls(firewallResponse.data ?? []);
      setFirewallInterfaces(firewallInterfaceResponse.data ?? []);
    } catch (reason) { toast.error(String(reason)); } finally { setLoading(false); }
  }, []);

  useEffect(() => { void loadData(); }, [loadData, refreshTrigger]);

  const elements = useMemo<cytoscape.ElementDefinition[]>(() => {
    const result: cytoscape.ElementDefinition[] = [];
    networks.forEach((network) => result.push({ group: 'nodes', classes: 'network', data: { id: `network-${network.id}`, label: `${network.name}\n${network.subnet}`, kind: network.network_type.toLowerCase(), rawData: network } }));
    assets.forEach((asset) => result.push({ group: 'nodes', classes: 'asset', data: { id: `asset-${asset.id}`, label: `${asset.name}\n${asset.ip_address || ''}`, parent: asset.network_id ? `network-${asset.network_id}` : undefined, compromise: asset.compromise_status, rawData: asset } }));
    firewalls.forEach((firewall) => result.push({ group: 'nodes', classes: 'firewall', data: { id: `firewall-${firewall.id}`, label: `${firewall.name}\nFW`, parent: firewall.network_id ? `network-${firewall.network_id}` : undefined, rawData: firewall } }));
    connections.forEach((connection) => result.push({ group: 'edges', classes: 'network-link', data: { id: `connection-${connection.id}`, source: `network-${connection.source_network_id}`, target: `network-${connection.target_network_id}`, label: connection.device_name ? `${connection.connection_type} · ${connection.device_name}` : connection.connection_type, rawData: connection } }));
    interfaces.filter((item) => !item.is_primary && item.network_id).forEach((item) => result.push({ group: 'edges', classes: 'secondary-nic', data: { id: `interface-edge-${item.id}`, source: `asset-${item.asset_id}`, target: `network-${item.network_id}`, label: `${item.name} · ${item.ip_address}`, rawData: item } }));
    firewallInterfaces.filter((item) => item.network_id && (!item.is_primary || !firewalls.find((firewall) => firewall.id === item.firewall_id)?.network_id)).forEach((item) => result.push({ group: 'edges', classes: 'firewall-nic', data: { id: `firewall-interface-edge-${item.id}`, source: `firewall-${item.firewall_id}`, target: `network-${item.network_id}`, label: `${item.name} · ${item.ip_addresses.join(', ')}`, rawData: item } }));
    return result;
  }, [networks, assets, firewalls, connections, interfaces, firewallInterfaces]);

  useEffect(() => {
    if (!cyRef.current || elements.length === 0) return;
    cyRef.current.layout({ name: layout, padding: 24, animate: true, animationDuration: 350 } as cytoscape.LayoutOptions).run();
  }, [elements, layout]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const observer = new ResizeObserver(() => {
      cyRef.current?.resize();
      cyRef.current?.fit(undefined, 40);
    });
    observer.observe(container);
    return () => observer.disconnect();
  }, []);

  const exportPng = () => {
    if (!cyRef.current) return;
    const link = document.createElement('a'); link.download = 'network-topology.png'; link.href = cyRef.current.png({ bg: 'white', full: true, scale: 2 }); link.click();
  };

  return <div className="flex h-full flex-col space-y-4 p-6">
    <div className="flex items-center justify-between"><div><h2 className="flex items-center gap-2 text-2xl font-bold text-slate-800"><GitGraph className="text-cyan-600" />Network Topology</h2><p className="text-sm text-slate-500">Purple dotted edges show asset NICs; amber dotted edges show firewall interfaces.</p></div><div className="flex gap-2"><Select value={layout} onValueChange={(value: LayoutName) => setLayout(value)}><SelectTrigger className="w-36"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="dagre">Hierarchical</SelectItem><SelectItem value="grid">Grid</SelectItem><SelectItem value="circle">Circle</SelectItem><SelectItem value="concentric">Concentric</SelectItem><SelectItem value="breadthfirst">Breadth-first</SelectItem></SelectContent></Select><Button size="sm" variant="outline" onClick={() => cyRef.current?.zoom(cyRef.current.zoom() + 0.2)}><ZoomIn size={16} /></Button><Button size="sm" variant="outline" onClick={() => cyRef.current?.zoom(cyRef.current.zoom() - 0.2)}><ZoomOut size={16} /></Button><Button size="sm" variant="outline" onClick={() => cyRef.current?.fit(undefined, 40)}><RefreshCw size={16} /></Button><Button size="sm" variant="outline" onClick={exportPng}><Download size={16} /></Button><Button size="sm" onClick={() => void loadData()} disabled={loading}>{<RefreshCw size={16} className={loading ? 'animate-spin' : ''} />}</Button></div></div>
    <div className="flex min-h-0 flex-1 gap-4"><Card className="min-h-[600px] flex-1"><CardContent ref={containerRef} className="h-full overflow-hidden p-0">{elements.length ? <CytoscapeComponent elements={elements} stylesheet={STYLESHEET} style={{ width: '100%', height: '100%' }} layout={{ name: layout, padding: 40, nodeSep: 80, rankSep: 100 } as cytoscape.LayoutOptions} minZoom={0.2} maxZoom={4} wheelSensitivity={0.25} cy={(instance) => { cyRef.current = instance; instance.off('tap'); instance.on('tap', 'node', (event) => setSelectedNode(event.target.data())); instance.on('tap', (event) => { if (event.target === instance) setSelectedNode(null); }); }} /> : <div className="flex h-full items-center justify-center text-slate-400">Add a network or asset to build the topology.</div>}</CardContent></Card>
      {selectedNode && <Card className="w-80 flex-shrink-0"><CardHeader><CardTitle className="text-sm">{String(selectedNode.label ?? 'Node details').split('\n')[0]}</CardTitle></CardHeader><CardContent className="space-y-2 text-xs"><Badge variant="outline">{selectedNode.compromise || selectedNode.kind || 'network object'}</Badge>{selectedNode.rawData && Object.entries(selectedNode.rawData as Record<string, unknown>).filter(([key,value]) => value != null && !['id','created_at','network_id','network_name'].includes(key)).map(([key,value]) => <div key={key} className="grid grid-cols-[110px_1fr] gap-2"><span className="text-slate-500">{key.replaceAll('_',' ')}</span><span className="break-all font-mono">{String(value)}</span></div>)}</CardContent></Card>}
    </div>
  </div>;
}
