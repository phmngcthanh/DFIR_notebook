import { describe, expect, it } from 'vitest';
import type { Asset } from '@/types';
import {
  buildVmHostTree,
  buildVmInventoryImport,
  classifyGuestOs,
  groupVmsByHost,
  parseCsv,
  parseVmInventory,
  VM_INVENTORY_SCHEMA,
  type ImportedVmInventory,
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

describe('mobile and generic batch imports', () => {
  function assetChanges(parsed: ReturnType<typeof parseVmInventory>, inventory?: Partial<VmImportInventory>) {
    const document = JSON.parse(buildVmInventoryImport(parsed, { ...emptyInventory(), ...inventory }).document) as {
      changes: Array<{ entity_type: string; values: Record<string, unknown> }>;
    };
    return document.changes.filter((item) => item.entity_type === 'asset').map((item) => item.values);
  }

  it('classifies mobile guest OSes and keeps PC/other-OS guests as vm', () => {
    expect(classifyGuestOs('Android (x86) 14')).toBe('mobile');
    expect(classifyGuestOs('iOS 17.2')).toBe('mobile');
    expect(classifyGuestOs('HarmonyOS 4.0')).toBe('mobile');
    expect(classifyGuestOs('Cisco IOS-XE')).toBeUndefined();
    expect(classifyGuestOs('Microsoft Windows Server 2022')).toBeUndefined();
    expect(classifyGuestOs(undefined)).toBeUndefined();

    const parsed = parseVmInventory('hyperv', JSON.stringify([
      { VMId: 'guid-android', Name: 'Lab Phone', State: 'Running', GuestOS: 'Android 14', IPAddress: '192.168.1.50' },
      { VMId: 'guid-win', Name: 'Analyst VM', State: 'Running', GuestOS: 'Windows 11', IPAddress: '192.168.1.51' },
    ]));
    const values = assetChanges(parsed);
    expect(values.find((item) => item.name === 'Lab Phone')?.asset_type).toBe('mobile');
    expect(values.find((item) => item.name === 'Analyst VM')?.asset_type).toBe('vm');
  });

  it('honors explicit type and user columns in a generic CSV and warns on unknown types', () => {
    const parsed = parseVmInventory('generic', [
      '"Name","IPAddress","OS","Type","User"',
      '"SM-A528B","10.1.2.3","Android 14","phone","n.tran"',
      '"fin-ws-01","10.1.2.4","Windows 11","pc","t.nguyen"',
      '"lab-console","10.1.2.5","","gaming-console",""',
    ].join('\r\n'));
    expect(parsed.sourceFormat).toBe('csv');
    const values = assetChanges(parsed);
    expect(values.find((item) => item.name === 'SM-A528B')).toMatchObject({ asset_type: 'mobile', os: 'Android 14', user_name: 'n.tran' });
    expect(values.find((item) => item.name === 'fin-ws-01')).toMatchObject({ asset_type: 'workstation', os: 'Windows 11', user_name: 't.nguyen' });
    expect(values.find((item) => item.name === 'lab-console')?.asset_type).toBe('workstation');
    expect(parsed.warnings.join('\n')).toContain('gaming-console');
  });

  it('parses plain hostname lists and positional name, ip, mac, os, type lines', () => {
    const parsed = parseVmInventory('generic', [
      'web01',
      'web02, web03',
      'tablet-01,10.9.0.21,AA:BB:CC:DD:EE:01,iPadOS 17,',
      'srv-01,10.9.0.30,,,server',
    ].join('\n'));
    expect(parsed.sourceFormat).toBe('native');
    expect(parsed.records.map((record) => record.name)).toEqual(['web01', 'web02', 'web03', 'tablet-01', 'srv-01']);
    const values = assetChanges(parsed);
    expect(values.find((item) => item.name === 'web01')?.asset_type).toBe('workstation');
    expect(values.find((item) => item.name === 'tablet-01')).toMatchObject({ asset_type: 'mobile', ip_address: '10.9.0.21' });
    expect(values.find((item) => item.name === 'srv-01')?.asset_type).toBe('server');
  });

  it('parses adb devices -l output into mobile assets keyed by serial', () => {
    const parsed = parseVmInventory('generic', [
      '* daemon not running; starting now at tcp:5037',
      '* daemon started successfully',
      '',
      'List of devices attached',
      'emulator-5554          device transport_id:1',
      '29HXAZ123456           device product:a52xq model:SM_A528B device:a52x transport_id:2',
      'R58RA0ABCDEF           unauthorized transport_id:3',
      '',
    ].join('\n'));
    expect(parsed.sourceFormat).toBe('native');
    expect(parsed.records.map((record) => record.nativeId)).toEqual(['emulator-5554', '29HXAZ123456', 'R58RA0ABCDEF']);
    expect(parsed.records[1]).toMatchObject({ name: 'SM A528B', guestOs: 'Android' });
    expect(parsed.records.map((record) => record.identityKey)).toEqual([
      'generic:id:emulator-5554',
      'generic:id:29hxaz123456',
      'generic:id:r58ra0abcdef',
    ]);
    const values = assetChanges(parsed);
    expect(values.every((item) => item.asset_type === 'mobile')).toBe(true);
    expect(values.every((item) => item.os === 'Android')).toBe(true);
  });

  it('preserves an analyst-retyped asset_type when the guest OS is not mobile', () => {
    const initial = parseVmInventory('hyperv', JSON.stringify([{ VMId: 'guid-9', Name: 'Mail', ComputerName: 'HV-01' }]), { inventoryScope: 'site-a' });
    const inventory: VmImportInventory = {
      ...emptyInventory(),
      assets: [{
        id: 'asset-9',
        name: 'Mail',
        ip_address: '',
        asset_type: 'server',
        suspicious: false,
        compromise_status: 'unknown',
        investigation_status: 'not_started',
        properties: JSON.stringify(initial.records[0]),
        created_at: '',
      }],
    };
    const refreshed = parseVmInventory('hyperv', JSON.stringify([
      { VMId: 'guid-9', Name: 'Mail', ComputerName: 'HV-01', GuestOS: 'Ubuntu Linux (64-bit)' },
    ]), { inventoryScope: 'site-a' });
    const values = assetChanges(refreshed, inventory);
    expect(values[0].asset_type).toBe('server');
  });
});

describe('VM host grouping and XMind export', () => {
  function vmAsset(id: string, name: string, overrides: {
    host?: string; scope?: string; platform?: ImportedVmInventory['platform']; ips?: string[]; state?: string;
    status?: Asset['compromise_status']; assetIp?: string;
  } = {}): Asset {
    const inventory: ImportedVmInventory = {
      schema: VM_INVENTORY_SCHEMA,
      platform: overrides.platform ?? 'esxi',
      kind: 'virtual-machine',
      identityKey: `key-${id}`,
      name,
      ...(overrides.scope ? { inventoryScope: overrides.scope } : {}),
      ...(overrides.host ? { hypervisor: overrides.host } : {}),
      ...(overrides.state ? { state: overrides.state } : {}),
      ipAddresses: overrides.ips ?? [],
      macAddresses: [],
      sourceFormat: 'csv',
      raw: {},
    };
    return {
      id, name, ip_address: overrides.assetIp ?? '', asset_type: 'vm', suspicious: false,
      compromise_status: overrides.status ?? 'unknown', investigation_status: 'not_started', created_at: '',
      properties: JSON.stringify(inventory),
    };
  }

  it('groups VMs under their hypervisor host, sorted, with unassigned last', () => {
    const groups = groupVmsByHost([
      vmAsset('a', 'web-02', { host: 'esx-10', ips: ['10.0.0.2'] }),
      vmAsset('b', 'app-01', { host: 'esx-02', ips: ['10.0.1.2'] }),
      vmAsset('c', 'app-02', { host: 'ESX-02', ips: ['10.0.1.3'] }),
      vmAsset('d', 'orphan-vm', { scope: undefined, ips: [] }),
      { id: 'e', name: 'plain-laptop', ip_address: '10.9.9.9', asset_type: 'laptop', suspicious: false, compromise_status: 'unknown', investigation_status: 'not_started', created_at: '' },
    ]);
    expect(groups.map((group) => group.host)).toEqual(['esx-02', 'esx-10', '']);
    expect(groups[0].entries.map((entry) => entry.inventory.name)).toEqual(['app-01', 'app-02']);
    expect(groups[0].entries).toHaveLength(2);
    expect(groups[2].entries.map((entry) => entry.inventory.name)).toEqual(['orphan-vm']);
  });

  it('falls back to the inventory scope when no hypervisor was recorded', () => {
    const groups = groupVmsByHost([vmAsset('a', 'dc-01', { scope: 'esx-99', ips: ['10.5.0.10'] })]);
    expect(groups[0].host).toBe('esx-99');
  });

  it('builds the XMind tree with hosts as branches and hostname · IP leaves', () => {
    const tree = buildVmHostTree([
      vmAsset('a', 'web-01', { host: 'esx-02', ips: ['10.0.0.2', '10.0.0.3'], state: 'PoweredOn' }),
      vmAsset('b', 'sql-01', { host: 'esx-02', ips: [], assetIp: '10.0.0.50', status: 'infected' }),
      vmAsset('c', 'mail-01', { host: 'esx-10', platform: 'proxmox', ips: ['10.1.0.7'] }),
    ]);
    expect(tree).not.toBeNull();
    expect(tree!.title).toBe('VM inventory · 3 VMs on 2 hosts');
    const hosts = tree!.children ?? [];
    expect(hosts.map((host) => host.title)).toEqual(['esx-02 · 2 VMs', 'esx-10 · 1 VM']);
    expect(hosts[0].labels).toEqual(['VMware ESXi / vSphere']);
    expect(hosts[0].children?.map((leaf) => leaf.title)).toEqual(['sql-01 · 10.0.0.50 · infected', 'web-01 · 10.0.0.2, 10.0.0.3']);
    expect(hosts[0].children?.[1].labels).toEqual(['PoweredOn']);
    expect(hosts[1].labels).toEqual(['Proxmox VE']);
  });

  it('returns null when no assets carry a VM inventory', () => {
    expect(buildVmHostTree([])).toBeNull();
    expect(buildVmHostTree([
      { id: 'x', name: 'laptop', ip_address: '', asset_type: 'laptop', suspicious: false, compromise_status: 'unknown', investigation_status: 'not_started', created_at: '' },
    ])).toBeNull();
  });
});
