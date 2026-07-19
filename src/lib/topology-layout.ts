import type { Asset, Firewall, Network, NetworkConnection, TopologyLayoutName } from '@/types';
export type { TopologyLayoutName } from '@/types';

export interface TopologyPoint {
  x: number;
  y: number;
}

export interface TopologyLayoutInput {
  networks: Network[];
  assets: Asset[];
  firewalls: Firewall[];
  connections: NetworkConnection[];
}

export interface TopologyLayoutResult {
  positions: Record<string, TopologyPoint>;
  networkBounds: Record<string, { x: number; y: number; width: number; height: number }>;
}

const NODE_X_GAP = 158;
const NODE_Y_GAP = 104;
const ZONE_GAP = 220;

interface ZonePlan {
  network: Network;
  width: number;
  height: number;
  localPositions: Record<string, TopologyPoint>;
}

function planZone(network: Network, assets: Asset[], firewalls: Firewall[]): ZonePlan {
  const zoneAssets = assets
    .filter((asset) => asset.network_id === network.id)
    .sort((left, right) => left.name.localeCompare(right.name));
  const zoneFirewalls = firewalls
    .filter((firewall) => firewall.network_id === network.id)
    .sort((left, right) => left.name.localeCompare(right.name));
  const columns = Math.min(5, Math.max(1, Math.ceil(Math.sqrt(zoneAssets.length * 1.5))));
  const assetRows = Math.ceil(zoneAssets.length / columns);
  const firewallRows = zoneFirewalls.length ? Math.ceil(zoneFirewalls.length / columns) : 0;
  const contentRows = Math.max(1, assetRows + firewallRows);
  const width = Math.max(330, columns * NODE_X_GAP + 110);
  const height = Math.max(230, contentRows * NODE_Y_GAP + 130);
  const localPositions: Record<string, TopologyPoint> = {};
  const placeRow = (items: Array<{ id: string }>, rowOffset: number) => {
    items.forEach((item, index) => {
      const row = rowOffset + Math.floor(index / columns);
      const column = index % columns;
      const itemsInRow = Math.min(columns, items.length - Math.floor(index / columns) * columns);
      localPositions[item.id] = {
        x: (column - (itemsInRow - 1) / 2) * NODE_X_GAP,
        y: (row - (contentRows - 1) / 2) * NODE_Y_GAP + 20,
      };
    });
  };

  placeRow(zoneFirewalls.map((item) => ({ id: `firewall-${item.id}` })), 0);
  placeRow(zoneAssets.map((item) => ({ id: `asset-${item.id}` })), firewallRows);
  return { network, width, height, localPositions };
}

function networkDegrees(networks: Network[], connections: NetworkConnection[]) {
  const degree = new Map(networks.map((network) => [network.id, 0]));
  connections.forEach((connection) => {
    degree.set(connection.source_network_id, (degree.get(connection.source_network_id) ?? 0) + 1);
    degree.set(connection.target_network_id, (degree.get(connection.target_network_id) ?? 0) + 1);
  });
  return degree;
}

function chooseRoot(networks: Network[], connections: NetworkConnection[]) {
  const degree = networkDegrees(networks, connections);
  return [...networks].sort((left, right) => {
    const leftWan = /wan|internet|external|isp/i.test(left.network_type) ? 1 : 0;
    const rightWan = /wan|internet|external|isp/i.test(right.network_type) ? 1 : 0;
    return rightWan - leftWan || (degree.get(right.id) ?? 0) - (degree.get(left.id) ?? 0) || left.name.localeCompare(right.name);
  })[0];
}

function breadthLevels(networks: Network[], connections: NetworkConnection[], directed: boolean): Network[][] {
  if (!networks.length) return [];
  const byId = new Map(networks.map((network) => [network.id, network]));
  const adjacency = new Map(networks.map((network) => [network.id, [] as string[]]));
  connections.forEach((connection) => {
    if (byId.has(connection.source_network_id) && byId.has(connection.target_network_id)) {
      adjacency.get(connection.source_network_id)?.push(connection.target_network_id);
      if (!directed) adjacency.get(connection.target_network_id)?.push(connection.source_network_id);
    }
  });
  const roots = directed
    ? networks.filter((network) => !connections.some((connection) => connection.target_network_id === network.id))
    : [];
  const preferred = chooseRoot(networks, connections);
  const queue: Array<{ id: string; level: number }> = [];
  if (preferred) queue.push({ id: preferred.id, level: 0 });
  roots.forEach((network) => {
    if (network.id !== preferred?.id) queue.push({ id: network.id, level: 0 });
  });
  const visited = new Set<string>();
  const result: Network[][] = [];

  const drain = () => {
    while (queue.length) {
      const current = queue.shift();
      if (!current || visited.has(current.id)) continue;
      visited.add(current.id);
      const network = byId.get(current.id);
      if (!network) continue;
      (result[current.level] ??= []).push(network);
      adjacency.get(current.id)?.forEach((id) => {
        if (!visited.has(id)) queue.push({ id, level: current.level + 1 });
      });
    }
  };
  drain();
  networks.forEach((network) => {
    if (!visited.has(network.id)) {
      queue.push({ id: network.id, level: result.length });
      drain();
    }
  });
  return result;
}

function placeLinearGroups(
  levels: Network[][],
  plans: Map<string, ZonePlan>,
  vertical: boolean,
): Record<string, TopologyPoint> {
  const centers: Record<string, TopologyPoint> = {};
  let primary = 0;
  levels.forEach((level) => {
    const plansInLevel = level.map((network) => plans.get(network.id)).filter((plan): plan is ZonePlan => Boolean(plan));
    const primarySize = Math.max(...plansInLevel.map((plan) => vertical ? plan.height : plan.width), 0);
    const secondarySize = plansInLevel.reduce((sum, plan) => sum + (vertical ? plan.width : plan.height), 0)
      + Math.max(0, plansInLevel.length - 1) * ZONE_GAP;
    let secondary = -secondarySize / 2;
    plansInLevel.forEach((plan) => {
      const itemSecondary = vertical ? plan.width : plan.height;
      centers[plan.network.id] = vertical
        ? { x: secondary + itemSecondary / 2, y: primary + primarySize / 2 }
        : { x: primary + primarySize / 2, y: secondary + itemSecondary / 2 };
      secondary += itemSecondary + ZONE_GAP;
    });
    primary += primarySize + ZONE_GAP;
  });
  return centers;
}

function placeNetworkCenters(layout: TopologyLayoutName, plans: ZonePlan[], connections: NetworkConnection[]) {
  const centers: Record<string, TopologyPoint> = {};
  const maxWidth = Math.max(...plans.map((plan) => plan.width), 330);
  const maxHeight = Math.max(...plans.map((plan) => plan.height), 230);
  if (layout === 'dagre' || layout === 'breadthfirst') {
    const levels = breadthLevels(plans.map((plan) => plan.network), connections, layout === 'dagre');
    return placeLinearGroups(levels, new Map(plans.map((plan) => [plan.network.id, plan])), layout === 'dagre');
  }
  if (layout === 'grid') {
    const columns = Math.max(1, Math.ceil(Math.sqrt(plans.length)));
    plans.forEach((plan, index) => {
      centers[plan.network.id] = {
        x: (index % columns) * (maxWidth + ZONE_GAP),
        y: Math.floor(index / columns) * (maxHeight + ZONE_GAP),
      };
    });
    return centers;
  }
  const degrees = networkDegrees(plans.map((plan) => plan.network), connections);
  const ordered = [...plans].sort((left, right) =>
    (degrees.get(right.network.id) ?? 0) - (degrees.get(left.network.id) ?? 0)
      || left.network.name.localeCompare(right.network.name));
  if (layout === 'concentric' && ordered.length) {
    centers[ordered[0].network.id] = { x: 0, y: 0 };
    ordered.shift();
  }
  if (!ordered.length) return centers;
  if (ordered.length === 1) {
    centers[ordered[0].network.id] = layout === 'concentric'
      ? { x: maxWidth + ZONE_GAP, y: 0 }
      : { x: 0, y: 0 };
    return centers;
  }
  const minimumChord = Math.hypot(maxWidth, maxHeight) + ZONE_GAP;
  const radius = Math.max(maxWidth + ZONE_GAP, minimumChord / (2 * Math.sin(Math.PI / ordered.length)));
  ordered.forEach((plan, index) => {
    const angle = -Math.PI / 2 + index * (Math.PI * 2 / ordered.length);
    centers[plan.network.id] = { x: Math.cos(angle) * radius, y: Math.sin(angle) * radius };
  });
  return centers;
}

export function buildTopologyLayout(layout: TopologyLayoutName, input: TopologyLayoutInput): TopologyLayoutResult {
  const plans = input.networks.map((network) => planZone(network, input.assets, input.firewalls));
  const centers = placeNetworkCenters(layout, plans, input.connections);
  const positions: Record<string, TopologyPoint> = {};
  const networkBounds: TopologyLayoutResult['networkBounds'] = {};
  plans.forEach((plan) => {
    const center = centers[plan.network.id] ?? { x: 0, y: 0 };
    networkBounds[plan.network.id] = { ...center, width: plan.width, height: plan.height };
    positions[`network-${plan.network.id}`] = center;
    Object.entries(plan.localPositions).forEach(([id, point]) => {
      positions[id] = { x: center.x + point.x, y: center.y + point.y };
    });
  });

  const orphanAssets = input.assets.filter((asset) => !asset.network_id || !networkBounds[asset.network_id]);
  const orphanFirewalls = input.firewalls.filter((firewall) => !firewall.network_id || !networkBounds[firewall.network_id]);
  const orphans = [
    ...orphanFirewalls.map((item) => `firewall-${item.id}`),
    ...orphanAssets.map((item) => `asset-${item.id}`),
  ];
  const bottom = Math.max(...Object.values(networkBounds).map((bounds) => bounds.y + bounds.height / 2), 0) + ZONE_GAP;
  const orphanColumns = Math.min(6, Math.max(1, Math.ceil(Math.sqrt(orphans.length))));
  orphans.forEach((id, index) => {
    positions[id] = {
      x: (index % orphanColumns - (orphanColumns - 1) / 2) * NODE_X_GAP,
      y: bottom + Math.floor(index / orphanColumns) * NODE_Y_GAP,
    };
  });
  return { positions, networkBounds };
}
