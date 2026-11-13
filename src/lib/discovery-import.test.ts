import { describe, expect, it } from 'vitest';
import type { Asset, Network, NetworkInterface } from '@/types';
import { buildDiscoveryImport, planDiscovery, type DiscoveryInventory } from './discovery-import';
import { parseDiscovery } from './discovery-parse';

const office = { id: 'net-office', name: 'Office LAN', subnet: '10.0.0.0/24' } as Network;

function asset(overrides: Partial<Asset> & { id: string; name: string }): Asset {
  return { ip_address: '', asset_type: 'server', suspicious: false, compromise_status: 'unknown', investigation_status: 'not_started', created_at: '', ...overrides };
}

function nic(assetId: string, overrides: Partial<NetworkInterface>): NetworkInterface {
  return { id: `nic-${assetId}-${overrides.ip_address}`, asset_id: assetId, name: 'Primary', ip_address: '', is_primary: true, ...overrides };
}

const inventory = (assets: Asset[], interfaces: NetworkInterface[], networks: Network[] = [office]): DiscoveryInventory => ({
  caseId: 'case-1', assets, networks, networkInterfaces: interfaces,
});

const NOW = '2026-11-13T09:00:00.000Z';
const options = { observedAt: NOW, sourceLabel: 'ARP / neighbor table' };

function changesOf(built: ReturnType<typeof buildDiscoveryImport>) {
  return (JSON.parse(built.document) as { changes: { change_id: string; entity_type: string; operation: string; target_id?: string; values: Record<string, unknown> }[] }).changes;
}

const ARP_LINES = [
  '10.0.0.40 dev eth0 lladdr aa:bb:cc:dd:ee:40 REACHABLE',
  '10.0.0.99 dev eth0 lladdr aa:bb:cc:dd:ee:99 REACHABLE',
];
const ARP = ARP_LINES.join('\n');

describe('planDiscovery', () => {
  const app = asset({ id: 'app', name: 'APP01', ip_address: '10.0.0.40' });
  const known = inventory([app], [nic('app', { ip_address: '10.0.0.40' })]);

  it('adds what is new and updates what the address says is already there', () => {
    const rows = planDiscovery(parseDiscovery(ARP), known);
    expect(rows.map((row) => [row.name, row.action, row.match?.asset.name])).toEqual([
      ['10.0.0.40', 'update', 'APP01'],
      ['10.0.0.99', 'create', undefined],
    ]);
  });

  it('does not trust an address from DHCP history, or one that now has a different MAC', () => {
    const lease = 'lease 10.0.0.40 {\n starts 4 2026/11/12 08:00:00;\n hardware ethernet aa:bb:cc:dd:ee:40;\n}\n';
    expect(planDiscovery(parseDiscovery(lease), known)[0].action).toBe('skip');

    const withMac = inventory([asset({ id: 'app', name: 'APP01', ip_address: '10.0.0.40', mac_address: '00:11:22:33:44:55' })], [nic('app', { ip_address: '10.0.0.40', mac_address: '00:11:22:33:44:55' })]);
    const [row] = planDiscovery(parseDiscovery(ARP_LINES[0]), withMac);
    expect(row.match).toEqual(expect.objectContaining({ strength: 'weak', macConflict: true }));
    expect(row.action).toBe('skip');
  });

  it('trusts a shared MAC address, and leaves gateways named only by another host unticked', () => {
    const byMac = inventory([asset({ id: 'old', name: 'OLD-NAME', ip_address: '10.0.0.7', mac_address: 'aa:bb:cc:dd:ee:40' })], []);
    expect(planDiscovery(parseDiscovery(ARP_LINES[0]), byMac)[0]).toEqual(expect.objectContaining({ action: 'update' }));
    const ipconfig = 'Windows IP Configuration\n   Host Name . . . . : WS1\nEthernet adapter E:\n   Physical Address. . . : AA-BB-CC-00-00-01\n   IPv4 Address. . . . . : 10.0.0.5(Preferred)\n   Default Gateway . . . : 10.0.0.1\n';
    expect(planDiscovery(parseDiscovery(ipconfig), inventory([], [])).map((row) => [row.name, row.action])).toEqual([['WS1', 'create'], ['10.0.0.1', 'skip']]);
  });
});

describe('buildDiscoveryImport', () => {
  it('records a new host as discovered, typed other, in its subnet, with the time it was seen', () => {
    const rows = planDiscovery(parseDiscovery(ARP_LINES[1]), inventory([], []));
    const changes = changesOf(buildDiscoveryImport(rows, inventory([], []), options));
    expect(changes).toHaveLength(2);
    expect(changes[0]).toEqual(expect.objectContaining({ entity_type: 'asset', operation: 'upsert', target_id: expect.any(String) }));
    expect(changes[0].values).toEqual({
      name: '10.0.0.99', asset_type: 'other', ip_address: '10.0.0.99', mac_address: 'AA:BB:CC:DD:EE:99', network_id: 'net-office',
      os: null, origin: 'discovered', last_observed: NOW, scan_results: null,
    });
    expect(changes[1].values).toEqual({
      asset_id: changes[0].target_id, name: 'Primary', ip_address: '10.0.0.99', mac_address: 'AA:BB:CC:DD:EE:99', network_id: 'net-office', is_primary: true,
    });
  });

  it('only adds to an asset already in the case: the time, the MAC on its interface, and never its origin', () => {
    const app = asset({ id: 'app', name: 'APP01', ip_address: '10.0.0.40', origin: 'client_inventory', last_observed: '2026-11-01T00:00:00.000Z' });
    const known = inventory([app], [nic('app', { ip_address: '10.0.0.40' })]);
    const rows = planDiscovery(parseDiscovery(ARP_LINES[0]), known);
    const changes = changesOf(buildDiscoveryImport(rows, known, options));
    expect(changes).toEqual([
      expect.objectContaining({ entity_type: 'asset', operation: 'update', target_id: 'app', values: { last_observed: NOW } }),
      expect.objectContaining({ entity_type: 'network_interface', operation: 'update', target_id: 'nic-app-10.0.0.40', values: { mac_address: 'AA:BB:CC:DD:EE:40' } }),
    ]);
  });

  it('adds an interface the asset lacks, and refuses to build an import that would change nothing', () => {
    const app = asset({ id: 'app', name: 'APP01', ip_address: '10.0.0.40', mac_address: 'AA:BB:CC:DD:EE:40', last_observed: '2026-12-01T00:00:00.000Z' });
    const known = inventory([app], [nic('app', { ip_address: '10.0.0.40', mac_address: 'AA:BB:CC:DD:EE:40' })]);
    // Observed earlier than what is stored, and nothing new: nothing to record.
    expect(() => buildDiscoveryImport(planDiscovery(parseDiscovery(ARP_LINES[0]), known), known, options)).toThrow(/Nothing to record/);

    const second = parseDiscovery('Windows IP Configuration\n   Host Name . . . . : APP01\nEthernet adapter E1:\n   Physical Address. . . : AA-BB-CC-DD-EE-40\n   IPv4 Address. . . . . : 10.0.0.40(Preferred)\nEthernet adapter E2:\n   Physical Address. . . : AA-BB-CC-DD-EE-41\n   IPv4 Address. . . . . : 10.0.1.40(Preferred)\n');
    const rows = planDiscovery(second, known).filter((row) => !row.host.reference);
    expect(rows[0].action).toBe('update');
    const changes = changesOf(buildDiscoveryImport(rows, known, options));
    const added = changes.filter((change) => change.entity_type === 'network_interface');
    expect(added).toEqual([expect.objectContaining({ operation: 'upsert', values: expect.objectContaining({ asset_id: 'app', name: 'E2', ip_address: '10.0.1.40', mac_address: 'AA:BB:CC:DD:EE:41', is_primary: false }) })]);
  });

  it('keeps an asset\'s own scan results but replaces an earlier nmap result, and records open ports', () => {
    const scan = '# Nmap 7.94 scan initiated Thu Nov 12 10:00:00 2026 as: nmap\nNmap scan report for 10.0.0.40\nHost is up.\n22/tcp open ssh\nMAC Address: AA:BB:CC:DD:EE:40 (Dell)\n';
    const withNotes = inventory([asset({ id: 'app', name: 'APP01', ip_address: '10.0.0.40', scan_results: '{"from":"vuln scanner"}' })], [nic('app', { ip_address: '10.0.0.40' })]);
    const kept = buildDiscoveryImport(planDiscovery(parseDiscovery(scan), withNotes), withNotes, options);
    expect(changesOf(kept)[0].values).not.toHaveProperty('scan_results');
    expect(kept.warnings).toEqual([expect.stringContaining('kept its existing scan results')]);

    const earlier = inventory([asset({ id: 'app', name: 'APP01', ip_address: '10.0.0.40', scan_results: '{"source":"nmap","open_ports":[]}' })], [nic('app', { ip_address: '10.0.0.40' })]);
    const replaced = changesOf(buildDiscoveryImport(planDiscovery(parseDiscovery(scan), earlier), earlier, options))[0].values.scan_results as string;
    expect(JSON.parse(replaced)).toEqual(expect.objectContaining({ source: 'nmap', open_ports: [{ port: 22, protocol: 'tcp', service: 'ssh' }], mac_vendor: 'Dell' }));
  });

  it('types a Windows machine from ipconfig and reports subnets it cannot choose between', () => {
    const ipconfig = parseDiscovery('Windows IP Configuration\n   Host Name . . . . : WS-FIN-12\nEthernet adapter E0:\n   Physical Address. . . : AA-BB-CC-00-00-12\n   IPv4 Address. . . . . : 10.0.0.12(Preferred)\n');
    const twin = { id: 'net-twin', name: 'Site B LAN', subnet: '10.0.0.0/24' } as Network;
    const crowded = inventory([], [], [office, twin]);
    const built = buildDiscoveryImport(planDiscovery(ipconfig, crowded), crowded, options);
    const [created] = changesOf(built);
    expect(created.values).toEqual(expect.objectContaining({ name: 'WS-FIN-12', asset_type: 'workstation', os: 'Windows', network_id: null }));
    expect(built.warnings.some((warning) => warning.includes('fits 2 networks with the same subnet (Office LAN, Site B LAN)'))).toBe(true);
  });

  it('lets the investigator rename a new asset before it is recorded', () => {
    const rows = planDiscovery(parseDiscovery(ARP_LINES[1]), inventory([], []));
    rows[0].name = 'PRINTER-3F';
    expect(changesOf(buildDiscoveryImport(rows, inventory([], []), options))[0].values.name).toBe('PRINTER-3F');
  });
});
