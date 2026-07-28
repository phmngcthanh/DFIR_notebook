import { describe, expect, it } from 'vitest';
import {
  buildVmInventoryImport,
  parseCsv,
  parseVmInventory,
  type VmImportInventory,
} from './vm-inventory';

function emptyInventory(): VmImportInventory {
  return {
    caseId: 'case-1',
    assets: [],
    networks: [],
    networkInterfaces: [],
  };
}

describe('VM inventory parsing', () => {
  it('parses native ESXi vim-cmd inventory and scopes its host-local VMid', () => {
    const parsed = parseVmInventory('esxi', [
      'Vmid   Name               File                                      Guest OS        Version   Annotation',
      '2      Domain Controller  [datastore1] DC01/DC01.vmx                windows9_64Guest vmx-19    Core identity',
    ].join('\n'), { inventoryScope: 'esx-01' });
    expect(parsed.sourceFormat).toBe('native');
    expect(parsed.records[0]).toMatchObject({
      nativeId: '2',
      name: 'Domain Controller',
      inventoryScope: 'esx-01',
      configPath: '[datastore1] DC01/DC01.vmx',
      guestOs: 'windows9_64Guest',
      version: 'vmx-19',
    });
    expect(parsed.records[0].identityKey).toBe('esxi:scope:esx-01:id:2');
  });

  it('parses quoted PowerCLI CSV fields and normalizes IP and MAC arrays', () => {
    const parsed = parseVmInventory('esxi', [
      '"Id","Name","PowerState","NumCpu","MemoryGB","GuestOS","VMHost","IPAddress","MacAddress"',
      '"VirtualMachine-vm-42","Web, Production","PoweredOn","4","8","Ubuntu Linux","esx-02","10.20.0.8;fe80::8","00:50:56:AA:BB:CC"',
    ].join('\r\n'), { sourceFile: 'vms.csv' });
    expect(parsed.records[0]).toMatchObject({
      nativeId: 'VirtualMachine-vm-42',
      name: 'Web, Production',
      state: 'PoweredOn',
      cpuCount: 4,
      memoryBytes: 8 * 1024 ** 3,
      hypervisor: 'esx-02',
      ipAddresses: ['10.20.0.8', 'fe80::8'],
      macAddresses: ['00:50:56:AA:BB:CC'],
    });
  });

  it('parses Proxmox cluster-resource JSON and excludes non-guest resources', () => {
    const parsed = parseVmInventory('proxmox', JSON.stringify([
      { type: 'qemu', vmid: 101, name: 'mail', node: 'pve-a', status: 'running', maxcpu: 4, maxmem: 4294967296, maxdisk: 34359738368 },
      { type: 'lxc', vmid: 102, name: 'dns', node: 'pve-b', status: 'stopped', maxcpu: 2, maxmem: 1073741824 },
      { type: 'node', node: 'pve-a', status: 'online' },
    ]), { inventoryScope: 'cluster-east' });
    expect(parsed.records).toHaveLength(2);
    expect(parsed.records[0]).toMatchObject({
      nativeId: '101',
      name: 'mail',
      hypervisor: 'pve-a',
      cpuCount: 4,
      memoryBytes: 4294967296,
    });
    expect(parsed.records[1].kind).toBe('container');
    expect(parsed.warnings[0]).toContain('Skipped 1 Proxmox cluster resource');
  });

  it('parses Proxmox qm list native tables', () => {
    const parsed = parseVmInventory('proxmox', [
      ' VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID',
      '  200 evidence-server      running       4096           80.00 2255',
    ].join('\n'));
    expect(parsed.records[0]).toMatchObject({
      nativeId: '200',
      name: 'evidence-server',
      state: 'running',
      memoryBytes: 4096 * 1024 ** 2,
      diskBytes: 80 * 1024 ** 3,
    });
  });

  it('parses Hyper-V CSV with stable VMId and host data', () => {
    const parsed = parseVmInventory('hyperv', [
      '"VMId","Name","State","ComputerName","ProcessorCount","MemoryAssigned","Generation","Version","IPAddress","MacAddress"',
      '"b3d3d8ec-370e-4e50-8cb7-2b5ef3a12345","IR-Collector","Running","HV-01","8","8589934592","2","10.0","192.168.50.12;fe80::12","00155D010203"',
    ].join('\n'));
    expect(parsed.records[0]).toMatchObject({
      nativeId: 'b3d3d8ec-370e-4e50-8cb7-2b5ef3a12345',
      name: 'IR-Collector',
      hypervisor: 'HV-01',
      cpuCount: 8,
      memoryBytes: 8589934592,
      generation: '2',
      ipAddresses: ['192.168.50.12', 'fe80::12'],
      macAddresses: ['00:15:5D:01:02:03'],
    });
  });

  it('handles escaped quotes, embedded newlines, and UTF-8 BOM in CSV', () => {
    const rows = parseCsv('\uFEFF"VMId","Name","Note"\r\n"1","VM ""Blue""","first\r\nsecond"\r\n');
    expect(rows[0]).toEqual({ VMId: '1', Name: 'VM "Blue"', Note: 'first\r\nsecond' });
  });
});
describe('VM inventory import builder', () => {
  it('reuses imported asset and NIC ids, preserves investigation state, and attaches a known subnet', () => {
    const initial = parseVmInventory('hyperv', JSON.stringify([{
      VMId: 'vm-guid-1',
      Name: 'Case-Server',
      State: 'Running',
      ComputerName: 'HV-01',
      ProcessorCount: 4,
      MemoryAssigned: 4294967296,
      IPAddress: '10.50.0.20',
      MacAddress: '00155D010203',
    }]), { inventoryScope: 'site-a' });
    const inventory: VmImportInventory = {
      ...emptyInventory(),
      networks: [{ id: 'network-50', name: 'Server VLAN', subnet: '10.50.0.0/24', network_type: 'LAN', description: '', vlan_id: '50', created_at: '' }],
      assets: [{
        id: 'asset-existing',
        network_id: 'network-50',
        name: 'Case-Server',
        ip_address: '10.50.0.20',
        mac_address: '00:15:5D:01:02:03',
        asset_type: 'vm',
        os: 'Windows Server',
        suspicious: true,
        compromise_status: 'suspected',
        investigation_status: 'in_progress',
        properties: JSON.stringify(initial.records[0]),
        scan_results: '{"edr":"queued"}',
        created_at: '',
      }],
      networkInterfaces: [{
        id: 'nic-existing',
        asset_id: 'asset-existing',
        name: 'Inventory NIC 1',
        ip_address: '10.50.0.20',
        mac_address: '00:15:5D:01:02:03',
        network_id: 'network-50',
        is_primary: true,
      }],
    };
    const refreshed = parseVmInventory('hyperv', JSON.stringify([{
      VMId: 'vm-guid-1',
      Name: 'Case-Server-Renamed',
      State: 'Off',
      ComputerName: 'HV-01',
      ProcessorCount: 8,
      MemoryAssigned: 8589934592,
      IPAddress: '10.50.0.21',
      MacAddress: '00155D010203',
    }]), { inventoryScope: 'site-a' });
    const document = JSON.parse(buildVmInventoryImport(refreshed, inventory).document) as {
      changes: Array<{ entity_type: string; target_id: string; values: Record<string, unknown> }>;
    };
    const asset = document.changes.find((item) => item.entity_type === 'asset');
    const nic = document.changes.find((item) => item.entity_type === 'network_interface');
    expect(asset?.target_id).toBe('asset-existing');
    expect(asset?.values).toMatchObject({
      name: 'Case-Server-Renamed',
      network_id: 'network-50',
      compromise_status: 'suspected',
      investigation_status: 'in_progress',
      scan_results: '{"edr":"queued"}',
    });
    expect(nic).toMatchObject({
      target_id: 'nic-existing',
      values: { ip_address: '10.50.0.21', network_id: 'network-50', is_primary: true },
    });
  });

  it('does not overwrite a manually-created VM merely because its name matches', () => {
    const parsed = parseVmInventory('proxmox', '[{"type":"qemu","vmid":101,"name":"mail"}]');
    const inventory: VmImportInventory = {
      ...emptyInventory(),
      assets: [{
        id: 'manual-asset',
        name: 'mail',
        ip_address: '',
        asset_type: 'vm',
        suspicious: false,
        compromise_status: 'unknown',
        investigation_status: 'not_started',
        created_at: '',
      }],
    };
    const document = JSON.parse(buildVmInventoryImport(parsed, inventory).document) as {
      changes: Array<{ entity_type: string; target_id: string }>;
    };
    expect(document.changes.find((item) => item.entity_type === 'asset')?.target_id).not.toBe('manual-asset');
  });
});
