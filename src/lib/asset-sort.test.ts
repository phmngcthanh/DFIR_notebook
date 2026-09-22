import { describe, expect, it } from 'vitest';
import { compareIpAddresses, sortAssets, type AssetSort } from './asset-sort';
import type { Asset } from '@/types';

function asset(overrides: Partial<Asset>): Asset {
  return {
    id: `asset-${overrides.name ?? 'x'}`, name: 'x', ip_address: '', asset_type: 'workstation',
    suspicious: false, compromise_status: 'unknown', investigation_status: 'not_started', created_at: '',
    ...overrides, id: overrides.id ?? `asset-${overrides.name ?? 'x'}`,
  };
}

describe('compareIpAddresses', () => {
  it('orders dotted quads numerically instead of alphabetically', () => {
    expect(compareIpAddresses('10.0.0.9', '10.0.0.10')).toBeLessThan(0);
    expect(compareIpAddresses('10.0.1.2', '10.0.0.10')).toBeGreaterThan(0);
    expect(compareIpAddresses('192.168.0.1', '10.0.0.1')).toBeGreaterThan(0);
    expect(compareIpAddresses('10.0.0.1', '10.0.0.1')).toBe(0);
  });

  it('sorts non-IPv4 values after IPv4 addresses and compares them as text', () => {
    expect(compareIpAddresses('10.0.0.1', 'fe80::1')).toBeLessThan(0);
    expect(compareIpAddresses(undefined, '10.0.0.1')).toBeGreaterThan(0);
    expect(compareIpAddresses(undefined, undefined)).toBe(0);
  });
});

describe('sortAssets', () => {
  const assets = [
    asset({ id: 'a', name: 'web-02', ip_address: '10.0.0.10', network_name: 'DMZ', asset_type: 'server', os: 'Linux', compromise_status: 'infected' }),
    asset({ id: 'b', name: 'web-1', ip_address: '10.0.0.9', network_name: 'LAN', asset_type: 'workstation', os: 'Windows', compromise_status: 'clean' }),
    asset({ id: 'c', name: 'dc', ip_address: '10.0.0.2', network_name: 'DMZ', asset_type: 'server', os: 'Windows', compromise_status: 'suspected' }),
  ];
  const nicCounts = new Map([['a', 2], ['b', 1], ['c', 3]]);
  const names = (sort: AssetSort | null) => sortAssets(assets, nicCounts, sort).map((item) => item.name);

  it('returns the input order untouched when no sort is active', () => {
    expect(names(null)).toEqual(['web-02', 'web-1', 'dc']);
  });

  it('sorts by name with numeric awareness and flips direction on demand', () => {
    expect(names({ key: 'name', direction: 'asc' })).toEqual(['dc', 'web-1', 'web-02']);
    expect(names({ key: 'name', direction: 'desc' })).toEqual(['web-02', 'web-1', 'dc']);
  });

  it('sorts IP addresses as numbers, not strings', () => {
    expect(names({ key: 'ip', direction: 'asc' })).toEqual(['dc', 'web-1', 'web-02']);
  });

  it('orders compromise status by severity', () => {
    expect(names({ key: 'compromise', direction: 'asc' })).toEqual(['web-1', 'dc', 'web-02']);
    expect(names({ key: 'compromise', direction: 'desc' })).toEqual(['web-02', 'dc', 'web-1']);
  });

  it('sorts by network name and falls back to the name on ties', () => {
    expect(names({ key: 'network', direction: 'asc' })).toEqual(['dc', 'web-02', 'web-1']);
  });

  it('sorts by NIC count', () => {
    expect(names({ key: 'nics', direction: 'desc' })).toEqual(['dc', 'web-02', 'web-1']);
  });
});
