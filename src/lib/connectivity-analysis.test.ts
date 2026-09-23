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
import { parseDeviceConfig, type ParsedDeviceConfig } from './network-config';

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

describe('FortiGate configuration analysis', () => {
  const fortios = parseDeviceConfig('fortigate_firewall', `
#config-version=FG10E1-7.0.12-FW-build0523-230606:opmode=0:vdom=1:user=admin
config system global
    set hostname "HN-22HV-FW-01"
end
config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.248
        set role wan
    next
    edit "port2"
        set ip 10.30.0.1 255.255.255.0
        set role lan
    next
end
config system vlan
    edit "vlan30"
        set vlanid 30
        set interface "port2"
        set ip 10.30.30.1 255.255.255.0
        set role lan
    next
end
config system zone
    edit "INTERNAL"
        set member "port2" "vlan30"
    next
end
config router static
    edit 1
        set gateway 203.0.113.1
        set device "wan1"
    next
end
config firewall address
    edit "LAN_NET"
        set subnet 10.30.0.0 255.255.255.0
    next
end
config firewall policy
    edit 1
        set name "lan-out"
        set srcintf "INTERNAL"
        set dstintf "wan1"
        set srcaddr "LAN_NET"
        set dstaddr "all"
        set action accept
        set service "ALL"
        set nat enable
    next
    edit 2
        set name "vip-in"
        set srcintf "wan1"
        set dstintf "INTERNAL"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
    edit 3
        set name "block-rest"
        set srcintf "wan1"
        set dstintf "INTERNAL"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
    next
end
config firewall vip
    edit "VIP_WEB"
        set extip 203.0.113.5
        set extintf "wan1"
        set portforward enable
        set mappedip "10.30.0.10"
        set extport 443
        set mappedport 8443
    next
end
`);

  function fortiInventory(): ConnectivityInventory {
    return {
      networks: [
        { id: 'lan', name: 'Users', subnet: '10.30.0.0/24', network_type: 'LAN', description: '', created_at: '' },
        { id: 'vlan30', name: 'Servers', subnet: '10.30.30.0/24', network_type: 'LAN', vlan_id: '30', description: '', created_at: '' },
        { id: 'wan', name: 'WAN', subnet: '203.0.113.0/29', network_type: 'WAN', description: '', created_at: '' },
      ],
      connections: [],
      assets: [],
      networkInterfaces: [],
      firewalls: [{ id: 'fw', name: fortios.hostname, vendor: 'Fortinet', rules: JSON.stringify(fortios), config_text: 'fixture', created_at: '' }],
      firewallInterfaces: [
        { id: 'fi-wan', firewall_id: 'fw', name: 'wan1', ip_addresses: ['203.0.113.2/29'], network_id: 'wan', role: 'wan', is_primary: true, description: '' },
        { id: 'fi-lan', firewall_id: 'fw', name: 'port2', ip_addresses: ['10.30.0.1/24'], network_id: 'lan', role: 'lan', is_primary: false, description: '' },
        { id: 'fi-vlan30', firewall_id: 'fw', name: 'vlan30', ip_addresses: ['10.30.30.1/24'], network_id: 'vlan30', role: 'lan', is_primary: false, description: '' },
      ],
      firewallNatRules: [],
    };
  }

  it('finds a confirmed LAN-to-Internet path through policy, default route, and NAT', () => {
    const result = analyzeConnectivity(fortiInventory(), 'lan', INTERNET_NODE_ID, 'outbound', 'logical');
    expect(result.paths.some((path) => path.certainty === 'confirmed')).toBe(true);
    expect(result.paths[0].networkIds).toEqual(['lan', 'wan', INTERNET_NODE_ID]);
    expect(result.paths[0].steps.flatMap((step) => step.evidence).join(' ')).toContain('lan-out');
  });

  it('keeps VLAN 30 off the Internet when no policy covers its subnet', () => {
    const result = analyzeConnectivity(fortiInventory(), 'vlan30', INTERNET_NODE_ID, 'outbound', 'logical');
    expect(result.paths).toHaveLength(0);
  });

  it('confirms inbound reachability only through the published VIP', () => {
    const result = analyzeConnectivity(fortiInventory(), 'lan', INTERNET_NODE_ID, 'inbound', 'logical');
    expect(result.paths.length).toBeGreaterThan(0);
    // The generic Internet→WAN ingress edge is always "possible"; the
    // policy-gated WAN→LAN step is what cites the VIP and its DNAT.
    const wanToLan = result.paths[0].steps.find((step) => step.fromNetworkId === 'wan' && step.toNetworkId === 'lan');
    expect(wanToLan).toBeDefined();
    expect(wanToLan!.evidence.join(' ')).toContain('vip-in');
    expect(wanToLan!.evidence.join(' ')).toContain('destination NAT');
  });
});
