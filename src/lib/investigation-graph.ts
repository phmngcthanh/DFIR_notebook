import type cytoscape from 'cytoscape';
import type {
  Asset,
  AttackEdge,
  CompromiseStatus,
  Firewall,
  InfectionSummary,
  InvestigationViewDisplay,
  InvestigationViewFilters,
  InvestigationViewState,
  Network,
  NetworkConnection,
  NetworkInterface,
  FirewallInterface,
  TopologyLayoutName,
} from '@/types';

export interface InvestigationElementsInput {
  networks: Network[];
  assets: Asset[];
  firewalls: Firewall[];
  connections: NetworkConnection[];
  interfaces: NetworkInterface[];
  firewallInterfaces: FirewallInterface[];
  attackEdges: AttackEdge[];
  infection: InfectionSummary;
}

export type HiddenReason = 'manual' | 'network' | 'filter';

export interface HiddenItem {
  id: string;
  label: string;
  reason: HiddenReason;
}

const THREAT_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export function externalNodeId(label: string): string {
  return `external-${label.trim()}`;
}

/** Canonical pathway order: sequence, then occurred_at (nulls last), then created_at. */
export function orderAttackPath(edges: AttackEdge[]): AttackEdge[] {
  return [...edges].sort((left, right) => {
    if (left.sequence !== right.sequence) return left.sequence - right.sequence;
    if (Boolean(left.occurred_at) !== Boolean(right.occurred_at)) return left.occurred_at ? -1 : 1;
    if (left.occurred_at && right.occurred_at && left.occurred_at !== right.occurred_at) {
      return left.occurred_at < right.occurred_at ? -1 : 1;
    }
    return left.created_at < right.created_at ? -1 : left.created_at > right.created_at ? 1 : 0;
  });
}

/** Edge ids visible at playback position `step` (0 = none, edges.length = all). */
export function playbackSlice(orderedEdges: AttackEdge[], step: number): Set<string> {
  const bounded = Math.max(0, Math.min(orderedEdges.length, Math.floor(step)));
  return new Set(orderedEdges.slice(0, bounded).map((edge) => `attack-${edge.id}`));
}

function graphNodeId(kind: string, id: string): string {
  return kind === 'external' ? externalNodeId(id) : `${kind}-${id}`;
}

export function buildInvestigationElements(input: InvestigationElementsInput): cytoscape.ElementDefinition[] {
  const result: cytoscape.ElementDefinition[] = [];
  const infectionByEntity = new Map(
    input.infection.entities.map((entry) => [`${entry.entity_kind}-${entry.entity_id}`, entry]),
  );
  const badge = (kind: string, id: string) => {
    const entry = infectionByEntity.get(`${kind}-${id}`);
    return entry ? { sightingCount: entry.sighting_count, maxThreat: entry.max_threat_level } : { sightingCount: 0, maxThreat: '' };
  };

  input.networks.forEach((network) => {
    const parent = `network-${network.id}`;
    const overlay = badge('network', network.id);
    result.push({
      group: 'nodes',
      classes: 'network',
      data: {
        id: parent,
        label: `${network.name}\n${network.subnet}${overlay.sightingCount ? `  ⚠${overlay.sightingCount}` : ''}`,
        kind: network.network_type.toLowerCase(),
        entityKind: 'network',
        entityId: network.id,
        ...overlay,
        rawData: network,
      },
    });
    for (const corner of ['nw', 'ne', 'sw', 'se']) {
      result.push({
        group: 'nodes',
        classes: 'layout-anchor',
        selectable: false,
        grabbable: false,
        data: { id: `network-boundary-${network.id}-${corner}`, parent },
      });
    }
  });
  input.assets.forEach((asset) => {
    const overlay = badge('asset', asset.id);
    result.push({
      group: 'nodes',
      classes: 'asset',
      data: {
        id: `asset-${asset.id}`,
        label: `${asset.name}\n${asset.ip_address || 'No IP'}${overlay.sightingCount ? `  ⚠${overlay.sightingCount}` : ''}`,
        parent: asset.network_id ? `network-${asset.network_id}` : undefined,
        compromise: asset.compromise_status,
        entityKind: 'asset',
        entityId: asset.id,
        ...overlay,
        rawData: asset,
      },
    });
  });
  input.firewalls.forEach((firewall) => {
    const overlay = badge('firewall', firewall.id);
    result.push({
      group: 'nodes',
      classes: 'firewall',
      data: {
        id: `firewall-${firewall.id}`,
        label: `${firewall.name}\nFirewall${overlay.sightingCount ? `  ⚠${overlay.sightingCount}` : ''}`,
        parent: firewall.network_id ? `network-${firewall.network_id}` : undefined,
        entityKind: 'firewall',
        entityId: firewall.id,
        ...overlay,
        rawData: firewall,
      },
    });
  });

  // One synthetic origin node per distinct external label used by the pathway.
  const externalLabels = new Set(
    input.attackEdges.filter((edge) => edge.source_kind === 'external').map((edge) => edge.source_id.trim()),
  );
  externalLabels.forEach((label) => {
    result.push({
      group: 'nodes',
      classes: 'external',
      data: { id: externalNodeId(label), label: `☁ ${label}`, entityKind: 'external', entityId: label },
    });
  });

  input.connections.forEach((connection) => result.push({
    group: 'edges',
    classes: 'network-link topo-edge',
    data: {
      id: `connection-${connection.id}`,
      source: `network-${connection.source_network_id}`,
      target: `network-${connection.target_network_id}`,
      label: connection.device_name ? `${connection.connection_type} · ${connection.device_name}` : connection.connection_type,
      rawData: connection,
    },
  }));
  input.interfaces
    .filter((item) => !item.is_primary && item.network_id)
    .forEach((item) => result.push({
      group: 'edges',
      classes: 'secondary-nic topo-edge',
      data: {
        id: `interface-edge-${item.id}`,
        source: `asset-${item.asset_id}`,
        target: `network-${item.network_id}`,
        label: `${item.name} · ${item.ip_address}`,
        rawData: item,
      },
    }));
  input.firewallInterfaces
    .filter((item) => item.network_id && (!item.is_primary || !input.firewalls.find((firewall) => firewall.id === item.firewall_id)?.network_id))
    .forEach((item) => result.push({
      group: 'edges',
      classes: 'firewall-nic topo-edge',
      data: {
        id: `firewall-interface-edge-${item.id}`,
        source: `firewall-${item.firewall_id}`,
        target: `network-${item.network_id}`,
        label: `${item.name} · ${item.ip_addresses.join(', ')}`,
        rawData: item,
      },
    }));

  const ordered = orderAttackPath(input.attackEdges);
  ordered.forEach((edge, index) => {
    result.push({
      group: 'edges',
      classes: 'attack-edge',
      data: {
        id: `attack-${edge.id}`,
        source: graphNodeId(edge.source_kind, edge.source_id),
        target: graphNodeId(edge.target_kind, edge.target_id),
        label: `${index + 1}. ${edge.title}`,
        stepNumber: index + 1,
        edgeType: edge.edge_type,
        confidence: edge.confidence,
        rawData: edge,
      },
    });
  });
  return result;
}

export interface VisibilityState {
  hidden_network_ids: string[];
  hidden_node_ids: string[];
  filters: InvestigationViewFilters;
  display: InvestigationViewDisplay;
}

export interface VisibilityResult {
  visibleIds: Set<string>;
  hiddenSummary: HiddenItem[];
}

interface NodeInfo {
  id: string;
  label: string;
  parent?: string;
  isNetwork: boolean;
  isExternal: boolean;
  isAnchor: boolean;
  compromise?: CompromiseStatus;
  sightingCount: number;
  maxThreat: string;
}

function edgeWithinWindow(edge: AttackEdge, filters: InvestigationViewFilters): boolean {
  if (!filters.time_from && !filters.time_to) return true;
  if (!edge.occurred_at) return true;
  if (filters.time_from && edge.occurred_at < filters.time_from) return false;
  if (filters.time_to && edge.occurred_at > filters.time_to) return false;
  return true;
}

/**
 * Decide which element ids stay visible. Hiding a network hides its members;
 * an edge needs both endpoints; filters never remove an endpoint of a visible
 * analyst-drawn attack edge (pathway integrity) unless it was hidden manually.
 */
export function applyVisibility(
  elements: cytoscape.ElementDefinition[],
  state: VisibilityState,
): VisibilityResult {
  const nodes: NodeInfo[] = [];
  const manualHidden = new Set(state.hidden_node_ids);
  const hiddenNetworks = new Set(state.hidden_network_ids);
  elements.forEach((element) => {
    const data = element.data as Record<string, unknown>;
    if (typeof data.source === 'string') return;
    const classes = String(element.classes ?? '');
    nodes.push({
      id: String(data.id),
      label: String(data.label ?? data.id).split('\n')[0],
      parent: typeof data.parent === 'string' ? data.parent : undefined,
      isNetwork: classes.includes('network'),
      isExternal: classes.includes('external'),
      isAnchor: classes.includes('layout-anchor'),
      compromise: data.compromise as CompromiseStatus | undefined,
      sightingCount: Number(data.sightingCount ?? 0),
      maxThreat: String(data.maxThreat ?? ''),
    });
  });

  const hiddenSummary: HiddenItem[] = [];
  const hiddenNodes = new Map<string, HiddenReason>();
  const hideNode = (node: NodeInfo, reason: HiddenReason) => {
    if (!hiddenNodes.has(node.id)) hiddenNodes.set(node.id, reason);
  };

  const { filters } = state;
  const minThreatRank = filters.min_threat ? THREAT_RANK[filters.min_threat] ?? 0 : 0;
  nodes.forEach((node) => {
    if (node.isAnchor) return;
    const networkId = node.isNetwork ? node.id.replace('network-', '') : node.parent?.replace('network-', '');
    if (node.isNetwork && hiddenNetworks.has(networkId ?? '')) { hideNode(node, 'network'); return; }
    if (manualHidden.has(node.id)) { hideNode(node, 'manual'); return; }
    if (!node.isNetwork && networkId && hiddenNetworks.has(networkId)) { hideNode(node, 'network'); return; }
    if (node.isNetwork || node.isExternal) return;
    if (filters.compromise.length && node.compromise && !filters.compromise.includes(node.compromise)) {
      hideNode(node, 'filter');
      return;
    }
    if (filters.only_with_sightings && node.sightingCount === 0) { hideNode(node, 'filter'); return; }
    if (minThreatRank > 0 && (THREAT_RANK[node.maxThreat] ?? 0) < minThreatRank) hideNode(node, 'filter');
  });

  // Pathway integrity: attack-edge endpoints stay unless hidden manually or by network.
  if (state.display.show_attack_edges) {
    elements.forEach((element) => {
      const classes = String(element.classes ?? '');
      if (!classes.includes('attack-edge')) return;
      const data = element.data as Record<string, unknown>;
      const edge = data.rawData as AttackEdge;
      if (!edgeWithinWindow(edge, filters)) return;
      for (const endpoint of [String(data.source), String(data.target)]) {
        if (hiddenNodes.get(endpoint) === 'filter') hiddenNodes.delete(endpoint);
      }
    });
  }

  const visibleIds = new Set<string>();
  nodes.forEach((node) => {
    const reason = hiddenNodes.get(node.id);
    if (reason) {
      if (!node.isAnchor) hiddenSummary.push({ id: node.id, label: node.label, reason });
      return;
    }
    // Anchors follow their parent network.
    if (node.isAnchor && node.parent && hiddenNodes.has(node.parent)) return;
    visibleIds.add(node.id);
  });

  elements.forEach((element) => {
    const data = element.data as Record<string, unknown>;
    if (typeof data.source !== 'string') return;
    const classes = String(element.classes ?? '');
    const isAttack = classes.includes('attack-edge');
    if (isAttack && !state.display.show_attack_edges) return;
    if (!isAttack && !state.display.show_topology_edges) return;
    if (isAttack && !edgeWithinWindow((data.rawData as AttackEdge), state.filters)) return;
    if (visibleIds.has(String(data.source)) && visibleIds.has(String(data.target))) {
      visibleIds.add(String(data.id));
    }
  });

  // External origins with no visible attack edge disappear with their pathway.
  nodes.filter((node) => node.isExternal).forEach((node) => {
    const hasVisibleEdge = elements.some((element) => {
      const data = element.data as Record<string, unknown>;
      return String(element.classes ?? '').includes('attack-edge')
        && visibleIds.has(String(data.id))
        && (String(data.source) === node.id || String(data.target) === node.id);
    });
    if (!hasVisibleEdge) visibleIds.delete(node.id);
  });

  return { visibleIds, hiddenSummary };
}

export const DEFAULT_FILTERS: InvestigationViewFilters = {
  compromise: [],
  only_with_sightings: false,
  min_threat: null,
  time_from: null,
  time_to: null,
};

export const DEFAULT_DISPLAY: InvestigationViewDisplay = {
  show_topology_edges: true,
  show_attack_edges: true,
  show_ioc_badges: true,
  show_step_numbers: true,
};

export function defaultViewState(): InvestigationViewState {
  return {
    version: 1,
    hidden_network_ids: [],
    hidden_node_ids: [],
    filters: { ...DEFAULT_FILTERS },
    display: { ...DEFAULT_DISPLAY },
    layout: 'dagre',
    positions: [],
    zoom: 1,
    pan_x: 0,
    pan_y: 0,
  };
}

const LAYOUTS: TopologyLayoutName[] = ['dagre', 'grid', 'circle', 'concentric', 'breadthfirst'];
const COMPROMISE: CompromiseStatus[] = ['unknown', 'clean', 'suspected', 'infected'];

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

function finiteNumber(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

/** Defensive parse of a stored view state: unknown fields drop, bad values fall back. */
export function parseViewState(raw: unknown): InvestigationViewState {
  const state = defaultViewState();
  if (typeof raw !== 'object' || raw === null) return state;
  const value = raw as Record<string, unknown>;
  state.hidden_network_ids = stringArray(value.hidden_network_ids);
  state.hidden_node_ids = stringArray(value.hidden_node_ids);
  if (typeof value.layout === 'string' && (LAYOUTS as string[]).includes(value.layout)) {
    state.layout = value.layout as TopologyLayoutName;
  }
  state.zoom = finiteNumber(value.zoom, 1);
  state.pan_x = finiteNumber(value.pan_x, 0);
  state.pan_y = finiteNumber(value.pan_y, 0);
  if (Array.isArray(value.positions)) {
    state.positions = value.positions.flatMap((item) => {
      if (typeof item !== 'object' || item === null) return [];
      const entry = item as Record<string, unknown>;
      if (typeof entry.id !== 'string') return [];
      const x = finiteNumber(entry.x, Number.NaN);
      const y = finiteNumber(entry.y, Number.NaN);
      return Number.isNaN(x) || Number.isNaN(y) ? [] : [{ id: entry.id, x, y }];
    });
  }
  if (typeof value.filters === 'object' && value.filters !== null) {
    const filters = value.filters as Record<string, unknown>;
    state.filters = {
      compromise: stringArray(filters.compromise).filter((item): item is CompromiseStatus => (COMPROMISE as string[]).includes(item)),
      only_with_sightings: filters.only_with_sightings === true,
      min_threat: typeof filters.min_threat === 'string' && filters.min_threat in THREAT_RANK ? filters.min_threat : null,
      time_from: typeof filters.time_from === 'string' ? filters.time_from : null,
      time_to: typeof filters.time_to === 'string' ? filters.time_to : null,
    };
  }
  if (typeof value.display === 'object' && value.display !== null) {
    const display = value.display as Record<string, unknown>;
    state.display = {
      show_topology_edges: display.show_topology_edges !== false,
      show_attack_edges: display.show_attack_edges !== false,
      show_ioc_badges: display.show_ioc_badges !== false,
      show_step_numbers: display.show_step_numbers !== false,
    };
  }
  return state;
}
