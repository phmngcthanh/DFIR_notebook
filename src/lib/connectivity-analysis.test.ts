import { describe, expect, it } from 'vitest';
import {
  analyzeConnectivity,
  evaluatePolicy,
  INTERNET_NODE_ID,
  metadataWithConnectivityPolicies,
  parseConnectivityPolicies,
  type ConnectivityInventory,
  type ConnectivityPolicy,
} from './connectivity-analysis';
import type { ParsedDeviceConfig } from './network-config';

const firewallConfig: ParsedDeviceConfig = {
  schema: 'dfir-network-config-v1',
  profile: 'palo_alto_firewall',
  vendor: 'Palo Alto',
  deviceType: 'firewall',
  hostname: 'edge-fw',
  rawConfig: 'fixture',
  interfaces: [
    { name: 'ethernet1/1', addresses: ['203.0.113.2/24'], zone: 'untrust', role: 'wan', enabled: true },
    { name: 'ethernet1/2', addresses: ['10.10.10.1/24'], zone: 'trust', role: 'lan', enabled: true },
  ],
  vlans: [],
  routes: [{ name: 'default', destination: '0.0.0.0/0', nextHop: '203.0.113.1', interface: 'ethernet1/1', protocol: 'static', active: true }],
  aclRules: [
    { name: 'allow-out', sequence: 10, action: 'allow', protocol: 'any', source: 'any', destination: 'any', fromZone: 'trust', toZone: 'untrust', enabled: true },
    { name: 'deny-in', sequence: 20, action: 'deny', protocol: 'any', source: 'any', destination: 'any', fromZone: 'untrust', toZone: 'trust', enabled: true },
  ],
  natRules: [{ name: 'outbound-snat', natType: 'snat', protocol: 'any', source: '10.10.10.0/24', translatedSource: '203.0.113.2', enabled: true }],
  warnings: [],
};

function inventory(config = firewallConfig): ConnectivityInventory {
  return {
    networks: [
      { id: 'lan', name: 'Users', subnet: '10.10.10.0/24', network_type: 'LAN', vlan_id: '10', description: '', created_at: '' },
      { id: 'wan', name: 'WAN', subnet: '203.0.113.0/24', network_type: 'WAN', description: '', created_at: '' },
    ],
    connections: [],
    assets: [],
    networkInterfaces: [],
    firewalls: [{ id: 'fw', name: 'edge-fw', vendor: 'Palo Alto', rules: JSON.stringify(config), config_text: 'fixture', created_at: '' }],
    firewallInterfaces: [
      { id: 'fi-wan', firewall_id: 'fw', name: 'ethernet1/1', ip_addresses: ['203.0.113.2/24'], network_id: 'wan', role: 'wan', is_primary: true, description: '' },
      { id: 'fi-lan', firewall_id: 'fw', name: 'ethernet1/2', ip_addresses: ['10.10.10.1/24'], network_id: 'lan', role: 'lan', is_primary: false, description: '' },
    ],
    firewallNatRules: [],
  };
}

describe('connectivity analysis', () => {
  it('finds a confirmed outbound path through explicit route, policy, and source NAT', () => {
    const result = analyzeConnectivity(inventory(), 'lan', INTERNET_NODE_ID, 'outbound', 'logical');
    expect(result.paths.length).toBeGreaterThan(0);
    expect(result.paths.some((path) => path.certainty === 'confirmed')).toBe(true);
    expect(result.paths[0].networkIds).toEqual(['lan', 'wan', INTERNET_NODE_ID]);
    expect(result.paths[0].steps.flatMap((step) => step.evidence).join(' ')).toContain('allow-out');
  });

  it('does not invent an inbound route through an explicit deny and missing DNAT', () => {
    const result = analyzeConnectivity(inventory(), 'lan', INTERNET_NODE_ID, 'inbound', 'logical');
    expect(result.paths).toHaveLength(0);
  });

  it('reports physical attachment separately from logical reachability', () => {
    const physical = analyzeConnectivity(inventory(), 'lan', INTERNET_NODE_ID, 'inbound', 'physical');
    const logical = analyzeConnectivity(inventory(), 'lan', INTERNET_NODE_ID, 'inbound', 'logical');
    expect(physical.paths.length).toBeGreaterThan(0);
    expect(logical.paths).toHaveLength(0);
  });

  it('marks unresolved filtering as possible instead of claiming it is confirmed', () => {
    const config: ParsedDeviceConfig = {
      ...firewallConfig,
      aclRules: [],
      natRules: [],
      warnings: ['No ACL recognized'],
    };
    const result = analyzeConnectivity(inventory(config), 'lan', INTERNET_NODE_ID, 'outbound', 'logical');
    expect(result.paths.length).toBeGreaterThan(0);
    expect(result.paths.every((path) => path.certainty === 'possible')).toBe(true);
  });

  it('evaluates isolation policies with pass/fail/review semantics', () => {
    const policy: ConnectivityPolicy = {
      id: 'policy-1',
      name: 'No user Internet',
      sourceNetworkId: 'lan',
      targetKind: 'internet',
      direction: 'outbound',
      mode: 'logical',
      expectation: 'blocked',
      enabled: true,
      description: '',
    };
    const result = evaluatePolicy(inventory(), policy);
    expect(result.status).toBe('fail');
    expect(result.analyses[0].paths.some((path) => path.certainty === 'confirmed')).toBe(true);
  });

  it('preserves unrelated case metadata when policies are serialized', () => {
    const policy: ConnectivityPolicy = {
      id: 'policy-1',
      name: 'Isolation',
      sourceNetworkId: 'lan',
      targetKind: 'internet',
      direction: 'bidirectional',
      mode: 'physical',
      expectation: 'blocked',
      enabled: true,
      description: '',
    };
    const metadata = metadataWithConnectivityPolicies('{"owner":"IR"}', [policy]);
    expect(JSON.parse(metadata)).toMatchObject({ owner: 'IR' });
    expect(parseConnectivityPolicies(metadata)).toEqual([policy]);
  });
});
