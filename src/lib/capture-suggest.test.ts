import { describe, expect, it } from 'vitest';
import type { Asset, Network, NetworkInterface } from '@/types';
import { iocKey } from './ioc-detect';
import { captureAssetChanges, suggestFromCapture } from './capture-suggest';

describe('suggestFromCapture', () => {
  it('turns a field note into a ticked asset and an unticked host mention', () => {
    const { assets, iocs } = suggestFromCapture('APP01, 10.0.0.15, probably on ESX03. Finance says they own it. Ask infrastructure team for logs.');
    expect(assets).toEqual([
      expect.objectContaining({ name: 'APP01', ipAddress: '10.0.0.15', selected: true, existing: false }),
      expect.objectContaining({ name: 'ESX03', ipAddress: '', selected: false }),
    ]);
    expect(iocs).toEqual([]);
  });

  it('pairs a name in parentheses after the address', () => {
    const { assets } = suggestFromCapture('Beacon from 10.20.1.44 (WS-FIN-12) every 60 s');
    expect(assets[0]).toEqual(expect.objectContaining({ name: 'WS-FIN-12', ipAddress: '10.20.1.44', selected: true }));
  });

  it('pairs a name and an address joined by a few describing words', () => {
    const { assets } = suggestFromCapture('Infra e-mail: APP01 also answers on 10.0.0.16. DB02 at 10.0.0.40 talks to it nightly. 10.0.0.77 is FS01.', {
      existingAssetNames: ['APP01'],
    });
    expect(assets).toEqual([
      expect.objectContaining({ name: 'APP01', ipAddress: '10.0.0.16', existing: true, selected: false }),
      expect.objectContaining({ name: 'DB02', ipAddress: '10.0.0.40', existing: false, selected: true }),
      expect.objectContaining({ name: 'FS01', ipAddress: '10.0.0.77', selected: true }),
    ]);
  });

  it('does not give a host the address of something it talks to, or cross a sentence', () => {
    const { assets } = suggestFromCapture('APP01 talks to 10.0.0.40 nightly. Finance owns SRV2. 10.0.0.41 was quiet.');
    expect(assets).toEqual([
      expect.objectContaining({ name: '10.0.0.40', ipAddress: '10.0.0.40', selected: false }),
      expect.objectContaining({ name: '10.0.0.41', ipAddress: '10.0.0.41', selected: false }),
      expect.objectContaining({ name: 'APP01', ipAddress: '', selected: false }),
      expect.objectContaining({ name: 'SRV2', ipAddress: '', selected: false }),
    ]);
  });

  it('ticks defanged values and hard indicators, and leaves context unticked', () => {
    const { assets, iocs } = suggestFromCapture('Reverse team: sample talks to evil[.]example and 198.51.100.7, hash 44d88612fea8a8f36de82e1278abb02f. Contact ops@client.example.');
    expect(assets).toEqual([]);
    expect(iocs).toEqual([
      expect.objectContaining({ type: 'Domain', value: 'evil.example', selected: true }),
      expect.objectContaining({ type: 'IP', value: '198.51.100.7', selected: false }),
      expect.objectContaining({ type: 'Hash', value: '44d88612fea8a8f36de82e1278abb02f', selected: true }),
      expect.objectContaining({ type: 'Email', value: 'ops@client.example', selected: false }),
    ]);
  });

  it('marks what the case already has and never ticks it', () => {
    const { assets, iocs } = suggestFromCapture('APP01 10.0.0.15 dropped evil[.]example', {
      existingAssetNames: ['app01'],
      existingIocKeys: [iocKey('Domain', 'evil.example')],
    });
    expect(assets[0]).toEqual(expect.objectContaining({ name: 'APP01', existing: true, selected: false }));
    expect(iocs[0]).toEqual(expect.objectContaining({ existing: true, selected: false }));
  });

  it('ignores identifiers that only look like hostnames', () => {
    const { assets } = suggestFromCapture('Exploited CVE-2021-44228, technique T1059.001 over SMBv1 on Win10 in Q3');
    expect(assets).toEqual([]);
  });
});

describe('captureAssetChanges', () => {
  const office = { id: 'net-office', name: 'Office LAN', subnet: '10.0.0.0/24' } as Network;
  const asset = (overrides: Partial<Asset>) => ({ id: 'asset-app01', name: 'APP01', ip_address: '', ...overrides }) as Asset;
  const nic = (overrides: Partial<NetworkInterface>) => ({ id: 'nic-1', asset_id: 'asset-app01', name: 'Primary', ip_address: '', ...overrides }) as NetworkInterface;

  it('records a new host as type "other" with a primary interface in its subnet, and nothing more', () => {
    const plan = captureAssetChanges([{ name: ' APP01 ', ipAddress: '10.0.0.15' }], { assets: [], networks: [office], networkInterfaces: [] });
    const [planned] = plan.planned;
    expect(plan.changes).toEqual([
      {
        change_id: 'capture-asset-0', entity_type: 'asset', operation: 'upsert', target_id: planned.assetId,
        values: { name: 'APP01', asset_type: 'other', ip_address: '10.0.0.15', network_id: 'net-office' },
      },
      {
        change_id: 'capture-interface-0', entity_type: 'network_interface', operation: 'upsert', target_id: expect.any(String),
        values: { asset_id: planned.assetId, name: 'Primary', ip_address: '10.0.0.15', network_id: 'net-office', is_primary: true },
      },
    ]);
    expect(planned).toEqual(expect.objectContaining({ name: 'APP01', existing: false, changeIds: ['capture-asset-0', 'capture-interface-0'] }));
    expect(plan.warnings).toEqual([]);
  });

  it('records a host named without an address as just its name', () => {
    const plan = captureAssetChanges([{ name: 'ESX03', ipAddress: '' }], { assets: [], networks: [office], networkInterfaces: [] });
    expect(plan.changes).toHaveLength(1);
    expect(plan.changes[0].values).toEqual({ name: 'ESX03', asset_type: 'other', ip_address: '', network_id: null });
  });

  it('leaves the subnet open when two networks fit equally', () => {
    const siteB = { id: 'net-b', name: 'Site B LAN', subnet: '10.0.0.0/24' } as Network;
    const plan = captureAssetChanges([{ name: 'APP01', ipAddress: '10.0.0.15' }], { assets: [], networks: [office, siteB], networkInterfaces: [] });
    expect(plan.changes.map((change) => change.values.network_id)).toEqual([null, null]);
    expect(plan.warnings).toEqual([expect.stringContaining('fits 2 networks with the same subnet (Office LAN, Site B LAN)')]);
  });

  it('only adds an address an existing asset lacks, and never rewrites the asset', () => {
    const bare = captureAssetChanges([{ name: 'app01', ipAddress: '10.0.0.15' }], { assets: [asset({})], networks: [office], networkInterfaces: [] });
    expect(bare.changes).toEqual([expect.objectContaining({
      entity_type: 'network_interface',
      values: { asset_id: 'asset-app01', name: 'From capture', ip_address: '10.0.0.15', network_id: 'net-office', is_primary: true },
    })]);
    expect(bare.planned).toEqual([expect.objectContaining({ assetId: 'asset-app01', name: 'APP01', existing: true })]);

    const withNic = captureAssetChanges([{ name: 'APP01', ipAddress: '10.0.0.15' }], {
      assets: [asset({ ip_address: '192.168.5.4' })], networks: [office], networkInterfaces: [nic({ ip_address: '192.168.5.4' })],
    });
    expect(withNic.changes[0].values.is_primary).toBe(false);
  });

  it('links an existing asset that already has the address without changing anything', () => {
    const plan = captureAssetChanges([{ name: 'APP01', ipAddress: '10.0.0.15' }, { name: 'App01', ipAddress: '' }], {
      assets: [asset({ ip_address: '10.0.0.15' })], networks: [office], networkInterfaces: [nic({ ip_address: '10.0.0.15' })],
    });
    expect(plan.changes).toEqual([]);
    expect(plan.planned).toEqual([expect.objectContaining({ assetId: 'asset-app01', existing: true, changeIds: [] })]);
    expect(plan.warnings).toEqual(['APP01 is already in the case with 10.0.0.15; it is linked to the capture and left unchanged.']);
  });
});
