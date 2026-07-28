import { describe, expect, it } from 'vitest';
import { buildConfigImport, type ConfigImportInventory } from './config-import';
import { parseDeviceConfig } from './network-config';

function emptyInventory(): ConfigImportInventory {
  return {
    caseId: 'case-1',
    networks: [],
    assets: [],
    networkInterfaces: [],
    firewalls: [],
    firewallInterfaces: [],
    firewallNatRules: [],
  };
}

describe('configuration import document builder', () => {
  it('creates a topology VLAN with an unresolved subnet instead of inventing an address', () => {
    const config = parseDeviceConfig('cisco_network', `
hostname ACCESS-01
vlan 20
 name CAMERAS
!
interface GigabitEthernet1/0/10
 switchport access vlan 20
!`);
    const built = buildConfigImport(config, emptyInventory());
    const document = JSON.parse(built.document) as {
      changes: Array<{ entity_type: string; target_id: string; values: Record<string, unknown> }>;
    };
    const network = document.changes.find((item) => item.entity_type === 'network');
    const asset = document.changes.find((item) => item.entity_type === 'asset');
    const networkInterface = document.changes.find((item) => item.entity_type === 'network_interface');
    expect(network?.values).toMatchObject({ subnet: '', vlan_id: '20', network_type: 'LAN' });
    expect(asset?.values).toMatchObject({ name: 'ACCESS-01', asset_type: 'switch' });
    expect(networkInterface?.values.network_id).toBe(network?.target_id);
  });

  it('reuses uniquely matching case networks and device ids on repeated import', () => {
    const config = parseDeviceConfig('openwrt_network', `
config system
 option hostname 'edge'
config interface 'lan'
 option device 'br-lan'
 option ipaddr '10.0.0.1'
 option netmask '255.255.255.0'
config route
 option target '0.0.0.0/0'
 option gateway '10.0.0.254'
 option interface 'lan'
`);
    const inventory: ConfigImportInventory = {
      ...emptyInventory(),
      networks: [{ id: 'net-existing', name: 'Existing LAN', subnet: '10.0.0.0/24', network_type: 'LAN', description: '', created_at: '' }],
      assets: [{
        id: 'asset-existing',
        network_id: 'net-existing',
        name: 'edge',
        ip_address: '10.0.0.1',
        asset_type: 'router',
        suspicious: false,
        compromise_status: 'unknown',
        investigation_status: 'not_started',
        properties: '{"site":"HQ"}',
        created_at: '',
      }],
      networkInterfaces: [{
        id: 'if-existing',
        asset_id: 'asset-existing',
        name: 'br-lan',
        ip_address: '10.0.0.1',
        network_id: 'net-existing',
        is_primary: true,
      }],
    };
    const document = JSON.parse(buildConfigImport(config, inventory).document) as {
      changes: Array<{ entity_type: string; target_id: string; values: Record<string, unknown> }>;
    };
    expect(document.changes.some((item) => item.entity_type === 'network')).toBe(false);
    expect(document.changes.find((item) => item.entity_type === 'asset')?.target_id).toBe('asset-existing');
    expect(document.changes.find((item) => item.entity_type === 'network_interface')?.target_id).toBe('if-existing');
    expect(document.changes.find((item) => item.entity_type === 'asset')?.values.properties).toMatchObject({
      legacyProperties: { site: 'HQ' },
    });
  });
});
