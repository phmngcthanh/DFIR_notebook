import { describe, expect, it } from 'vitest';
import { buildTopologyLayout, type TopologyLayoutName } from './topology-layout';
import type { Asset, Firewall, Network, NetworkConnection } from '@/types';

const networks: Network[] = [
  { id: 'wan', name: 'Internet', subnet: '203.0.113.0/24', network_type: 'WAN', description: '', created_at: '' },
  { id: 'dmz', name: 'DMZ', subnet: '10.20.0.0/24', network_type: 'DMZ', description: '', created_at: '' },
  { id: 'lan', name: 'Corporate', subnet: '10.30.0.0/24', network_type: 'LAN', description: '', created_at: '' },
  { id: 'lab', name: 'Lab', subnet: '10.40.0.0/24', network_type: 'LAN', description: '', created_at: '' },
];
const assets: Asset[] = Array.from({ length: 18 }, (_, index) => ({
  id: `asset-${index}`, network_id: index < 10 ? 'lan' : index < 15 ? 'dmz' : 'lab', name: `Host ${index}`,
  ip_address: `10.0.0.${index + 1}`, asset_type: 'server', suspicious: false,
  compromise_status: 'unknown', investigation_status: 'not_started', created_at: '',
}));
const firewalls: Firewall[] = [
  { id: 'edge', network_id: 'wan', name: 'Edge firewall', created_at: '' },
  { id: 'internal', network_id: 'dmz', name: 'Internal firewall', created_at: '' },
];
const connections: NetworkConnection[] = [
  { id: 'one', source_network_id: 'wan', target_network_id: 'dmz', connection_type: 'routed', description: '' },
  { id: 'two', source_network_id: 'dmz', target_network_id: 'lan', connection_type: 'filtered', description: '' },
  { id: 'three', source_network_id: 'lan', target_network_id: 'lab', connection_type: 'routed', description: '' },
];

const modes: TopologyLayoutName[] = ['dagre', 'grid', 'circle', 'concentric', 'breadthfirst'];

describe('buildTopologyLayout', () => {
  it.each(modes)('keeps every zone separate and every device positioned in %s mode', (mode) => {
    const result = buildTopologyLayout(mode, { networks, assets, firewalls, connections });
    expect(Object.keys(result.networkBounds)).toHaveLength(networks.length);
    for (const asset of assets) expect(Number.isFinite(result.positions[`asset-${asset.id}`]?.x)).toBe(true);
    for (const firewall of firewalls) expect(Number.isFinite(result.positions[`firewall-${firewall.id}`]?.y)).toBe(true);

    const bounds = Object.values(result.networkBounds);
    for (let leftIndex = 0; leftIndex < bounds.length; leftIndex += 1) {
      for (let rightIndex = leftIndex + 1; rightIndex < bounds.length; rightIndex += 1) {
        const left = bounds[leftIndex];
        const right = bounds[rightIndex];
        const separated = Math.abs(left.x - right.x) >= (left.width + right.width) / 2
          || Math.abs(left.y - right.y) >= (left.height + right.height) / 2;
        expect(separated).toBe(true);
      }
    }
  });

  it('gives devices within a busy zone distinct, readable positions', () => {
    const result = buildTopologyLayout('grid', { networks, assets, firewalls, connections });
    const lanPositions = assets.filter((asset) => asset.network_id === 'lan').map((asset) => result.positions[`asset-${asset.id}`]);
    expect(new Set(lanPositions.map((position) => `${position.x}:${position.y}`)).size).toBe(lanPositions.length);
  });

  it('places a WAN root above downstream zones in hierarchical mode', () => {
    const result = buildTopologyLayout('dagre', { networks, assets, firewalls, connections });
    expect(result.networkBounds.wan.y).toBeLessThan(result.networkBounds.dmz.y);
    expect(result.networkBounds.dmz.y).toBeLessThan(result.networkBounds.lan.y);
  });
});
