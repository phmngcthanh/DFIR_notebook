import { describe, expect, it } from 'vitest';
import type { Asset, NetworkInterface } from '@/types';
import { describeReasons, findAssetMatches, findDuplicatePairs, normalizeMac, shortName } from './asset-match';

function asset(overrides: Partial<Asset> & { id: string; name: string }): Asset {
  return {
    ip_address: '', asset_type: 'server', suspicious: false, compromise_status: 'unknown',
    investigation_status: 'not_started', created_at: '', ...overrides,
  };
}

function nic(assetId: string, overrides: Partial<NetworkInterface>): NetworkInterface {
  return { id: `${assetId}-nic-${overrides.ip_address ?? overrides.mac_address}`, asset_id: assetId, name: 'eth0', ip_address: '', is_primary: false, ...overrides };
}

describe('normalizeMac and shortName', () => {
  it('reads every common MAC notation and rejects anything that is not 48 bits', () => {
    expect(normalizeMac('AA-BB-CC-DD-EE-FF')).toBe('aabbccddeeff');
    expect(normalizeMac('aa:bb:cc:dd:ee:ff')).toBe('aabbccddeeff');
    expect(normalizeMac('aabb.ccdd.eeff')).toBe('aabbccddeeff');
    expect(normalizeMac('aa:bb:cc')).toBe('');
    expect(normalizeMac(null)).toBe('');
  });

  it('drops the domain from a host name but keeps an address whole', () => {
    expect(shortName('APP01.corp.local')).toBe('app01');
    expect(shortName(' app01 ')).toBe('app01');
    expect(shortName('10.0.0.5')).toBe('10.0.0.5');
    expect(shortName(undefined)).toBe('');
  });
});

describe('findAssetMatches', () => {
  const app01 = asset({ id: 'a1', name: 'APP01', ip_address: '10.0.0.5', mac_address: 'AA:BB:CC:DD:EE:01' });
  const db02 = asset({ id: 'a2', name: 'DB02', ip_address: '10.0.0.40' });
  const interfaces = [
    nic('a1', { ip_address: '10.0.0.5', mac_address: 'AA:BB:CC:DD:EE:01', is_primary: true }),
    nic('a1', { name: 'mgmt', ip_address: '172.16.0.5', mac_address: 'AA:BB:CC:DD:EE:02' }),
    nic('a2', { ip_address: '10.0.0.40', is_primary: true }),
  ];
  const find = (candidate: Parameters<typeof findAssetMatches>[0]) => findAssetMatches(candidate, [app01, db02], interfaces);

  it('treats a shared MAC on any NIC as the same machine, whatever the name', () => {
    const [match] = find({ name: 'something-else', macs: ['aa-bb-cc-dd-ee-02'] });
    expect(match).toEqual(expect.objectContaining({ strength: 'strong', reasons: ['mac'] }));
    expect(match.asset.id).toBe('a1');
  });

  it('treats the same name at the same address as the same machine, FQDN or not', () => {
    const [match] = find({ name: 'app01.corp.local', ips: ['10.0.0.5'] });
    expect(match).toEqual(expect.objectContaining({ strength: 'strong', reasons: ['ip', 'name'] }));
  });

  it('only asks about an address alone or a short name alone', () => {
    expect(find({ ips: ['10.0.0.40'] })).toEqual([expect.objectContaining({ strength: 'weak', reasons: ['ip'] })]);
    expect(find({ name: 'db02.other-site.example' })).toEqual([expect.objectContaining({ strength: 'weak', reasons: ['name'] })]);
  });

  it('treats the identical full name as the same machine unless hardware addresses disagree', () => {
    expect(find({ name: 'APP01' })[0].strength).toBe('strong');
    // Same name and address, different NIC: a replaced card or two machines, so ask.
    expect(find({ name: 'APP01', ips: ['10.0.0.5'], macs: ['00:11:22:33:44:55'] })[0].strength).toBe('weak');
  });

  it('does not compare a candidate that is named by its address', () => {
    expect(find({ name: '10.0.0.77', ips: ['10.0.0.77'] })).toEqual([]);
  });

  it('finds nothing when nothing agrees', () => {
    expect(find({ name: 'WS-FIN-12', ips: ['10.9.9.9'], macs: ['de:ad:be:ef:00:01'] })).toEqual([]);
  });
});

describe('findDuplicatePairs', () => {
  it('pairs assets that share a MAC across NICs and ranks them above address-only pairs', () => {
    const assets = [
      asset({ id: 'a', name: 'APP01', ip_address: '10.0.0.5' }),
      asset({ id: 'b', name: 'app01.corp.local', ip_address: '10.0.0.6' }),
      asset({ id: 'c', name: 'PRINTER', ip_address: '10.0.0.5' }),
      asset({ id: 'd', name: 'LONER', ip_address: '10.9.9.9' }),
    ];
    const interfaces = [
      nic('a', { ip_address: '10.0.0.5', mac_address: 'aa:bb:cc:00:00:01' }),
      nic('b', { ip_address: '10.0.0.6', mac_address: 'AA-BB-CC-00-00-01' }),
    ];
    const pairs = findDuplicatePairs(assets, interfaces);
    expect(pairs.map((pair) => [pair.first.id, pair.second.id, pair.strength, pair.reasons])).toEqual([
      ['a', 'b', 'strong', ['mac', 'name']],
      ['a', 'c', 'weak', ['ip']],
    ]);
  });

  it('ignores a value shared by too many assets to identify anything', () => {
    const assets = Array.from({ length: 30 }, (_, index) => asset({ id: `g${index}`, name: `GUEST${index}`, ip_address: '0.0.0.0' }));
    expect(findDuplicatePairs(assets, [])).toEqual([]);
  });

  it('describes why two assets look alike', () => {
    expect(describeReasons(['mac'])).toBe('same MAC address');
    expect(describeReasons(['mac', 'ip', 'name'])).toBe('same MAC address, IP address and name');
  });
});
