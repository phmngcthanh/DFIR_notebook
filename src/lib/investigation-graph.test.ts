import { describe, expect, it } from 'vitest';
import {
  applyVisibility,
  buildInvestigationElements,
  defaultViewState,
  externalNodeId,
  orderAttackPath,
  parseViewState,
  playbackSlice,
} from './investigation-graph';
import type { Asset, AttackEdge, Firewall, InfectionSummary, Network } from '@/types';

const networks: Network[] = [
  { id: 'dmz', name: 'DMZ', subnet: '10.20.0.0/24', network_type: 'DMZ', description: '', created_at: '' },
  { id: 'lan', name: 'Corporate', subnet: '10.30.0.0/24', network_type: 'LAN', description: '', created_at: '' },
];
const assets: Asset[] = [
  { id: 'web', network_id: 'dmz', name: 'WEB-01', ip_address: '10.20.0.5', asset_type: 'server', suspicious: true, compromise_status: 'infected', investigation_status: 'in_progress', created_at: '' },
  { id: 'dc', network_id: 'lan', name: 'DC-01', ip_address: '10.30.0.5', asset_type: 'server', suspicious: false, compromise_status: 'clean', investigation_status: 'not_started', created_at: '' },
];
const firewalls: Firewall[] = [{ id: 'edge', network_id: 'dmz', name: 'Edge', created_at: '' }];

function edge(partial: Partial<AttackEdge>): AttackEdge {
  return {
    id: 'edge-1', source_kind: 'external', source_id: 'Internet', target_kind: 'asset', target_id: 'web',
    title: 'Initial access', description: '', edge_type: 'initial_access', confidence: 'confirmed',
    sequence: 0, ioc_ids: [], created_at: '2026-07-21T00:00:00Z', ...partial,
  };
}

const attackEdges: AttackEdge[] = [
  edge({ id: 'step-2', source_kind: 'asset', source_id: 'web', target_id: 'dc', title: 'Lateral movement', sequence: 2, occurred_at: '2026-07-20T03:00:00Z' }),
  edge({ id: 'step-1', sequence: 1, occurred_at: '2026-07-20T02:00:00Z' }),
];

const infection: InfectionSummary = {
  entities: [{ entity_kind: 'asset', entity_id: 'web', entity_name: 'WEB-01', sighting_count: 2, max_threat_level: 'high', ioc_ids: ['ioc-1'] }],
  iocs: [{ ioc_id: 'ioc-1', entity_count: 1, entities: [{ entity_kind: 'asset', entity_id: 'web', entity_name: 'WEB-01' }] }],
};

function elements() {
  return buildInvestigationElements({
    networks, assets, firewalls, connections: [], interfaces: [], firewallInterfaces: [], attackEdges, infection,
  });
}

describe('orderAttackPath and playback', () => {
  it('orders by sequence, then time, then creation, and slices playback steps', () => {
    const unordered = [
      edge({ id: 'c', sequence: 1, occurred_at: null, created_at: '2026-01-02T00:00:00Z' }),
      edge({ id: 'a', sequence: 1, occurred_at: '2026-01-01T00:00:00Z' }),
      edge({ id: 'b', sequence: 1, occurred_at: '2026-01-05T00:00:00Z' }),
      edge({ id: 'd', sequence: 0 }),
    ];
    const ordered = orderAttackPath(unordered).map((item) => item.id);
    expect(ordered).toEqual(['d', 'a', 'b', 'c']);
    expect(playbackSlice(orderAttackPath(unordered), 2)).toEqual(new Set(['attack-d', 'attack-a']));
    expect(playbackSlice(orderAttackPath(unordered), 0).size).toBe(0);
  });
});

describe('buildInvestigationElements', () => {
  it('adds infection badges, external origins, and numbered attack edges', () => {
    const built = elements();
    const web = built.find((item) => item.data.id === 'asset-web');
    expect(web?.data.sightingCount).toBe(2);
    expect(String(web?.data.label)).toContain('⚠2');
    expect(built.some((item) => item.data.id === externalNodeId('Internet'))).toBe(true);
    const steps = built
      .filter((item) => String(item.classes ?? '').includes('attack-edge'))
      .map((item) => [item.data.stepNumber, item.data.id]);
    expect(steps).toEqual([[1, 'attack-step-1'], [2, 'attack-step-2']]);
  });
});

describe('applyVisibility', () => {
  it('hides a network with its members and drops edges missing an endpoint', () => {
    const state = defaultViewState();
    state.hidden_network_ids = ['dmz'];
    const { visibleIds, hiddenSummary } = applyVisibility(elements(), state);
    expect(visibleIds.has('network-dmz')).toBe(false);
    expect(visibleIds.has('asset-web')).toBe(false);
    expect(visibleIds.has('firewall-edge')).toBe(false);
    expect(visibleIds.has('asset-dc')).toBe(true);
    // Both attack edges touch hidden WEB-01, so neither shows and the external origin follows.
    expect(visibleIds.has('attack-step-1')).toBe(false);
    expect(visibleIds.has('attack-step-2')).toBe(false);
    expect(visibleIds.has(externalNodeId('Internet'))).toBe(false);
    expect(hiddenSummary.filter((item) => item.reason === 'network').length).toBeGreaterThanOrEqual(3);
  });

  it('keeps filtered nodes that anchor a visible attack edge (pathway integrity)', () => {
    const state = defaultViewState();
    state.filters.compromise = ['infected'];
    const { visibleIds } = applyVisibility(elements(), state);
    // DC-01 is clean but is the target of a drawn attack edge, so it survives the filter.
    expect(visibleIds.has('asset-dc')).toBe(true);
    expect(visibleIds.has('attack-step-2')).toBe(true);
  });

  it('manual hiding beats pathway integrity and display toggles remove edge classes', () => {
    const state = defaultViewState();
    state.hidden_node_ids = ['asset-dc'];
    const manual = applyVisibility(elements(), state);
    expect(manual.visibleIds.has('asset-dc')).toBe(false);
    expect(manual.visibleIds.has('attack-step-2')).toBe(false);
    expect(manual.hiddenSummary.find((item) => item.id === 'asset-dc')?.reason).toBe('manual');

    const noAttack = defaultViewState();
    noAttack.display.show_attack_edges = false;
    const hiddenAttack = applyVisibility(elements(), noAttack);
    expect(hiddenAttack.visibleIds.has('attack-step-1')).toBe(false);
    expect(hiddenAttack.visibleIds.has(externalNodeId('Internet'))).toBe(false);
  });
});

describe('parseViewState', () => {
  it('recovers defaults from malformed input and keeps valid fields', () => {
    expect(parseViewState(null)).toEqual(defaultViewState());
    const parsed = parseViewState({
      version: 1,
      layout: 'grid',
      zoom: 2,
      pan_x: 'broken',
      hidden_node_ids: ['asset-x', 7],
      positions: [{ id: 'asset-x', x: 1, y: 2 }, { id: 3, x: 1, y: 2 }, { id: 'bad', x: Number.NaN, y: 0 }],
      filters: { compromise: ['infected', 'bogus'], min_threat: 'high' },
      display: { show_topology_edges: false },
      unknown_field: 'dropped',
    });
    expect(parsed.layout).toBe('grid');
    expect(parsed.zoom).toBe(2);
    expect(parsed.pan_x).toBe(0);
    expect(parsed.hidden_node_ids).toEqual(['asset-x']);
    expect(parsed.positions).toEqual([{ id: 'asset-x', x: 1, y: 2 }]);
    expect(parsed.filters.compromise).toEqual(['infected']);
    expect(parsed.filters.min_threat).toBe('high');
    expect(parsed.display.show_topology_edges).toBe(false);
    expect(parsed.display.show_attack_edges).toBe(true);
    expect('unknown_field' in parsed).toBe(false);
  });
});
