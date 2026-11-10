import { describe, expect, it } from 'vitest';
import { matchNetworkForIp } from './subnet-match';
import type { Network } from '@/types';

const network = (id: string, subnet: string): Network => ({
  id, name: id, subnet, network_type: 'LAN', description: '', created_at: '',
});

describe('matchNetworkForIp', () => {
  it('places an address in the most specific containing subnet', () => {
    const networks = [network('corp', '10.0.0.0/16'), network('servers', '10.0.1.0/24')];
    expect(matchNetworkForIp(networks, '10.0.1.20')).toEqual({ kind: 'unique', network: networks[1] });
    expect(matchNetworkForIp(networks, '10.0.9.20')).toEqual({ kind: 'unique', network: networks[0] });
    expect(matchNetworkForIp(networks, '192.168.1.1')).toEqual({ kind: 'none' });
  });

  it('treats equally specific subnets as ambiguous instead of picking the first', () => {
    const siteA = network('site-a', '10.0.0.0/24');
    const siteB = network('site-b', '10.0.0.0/24');
    expect(matchNetworkForIp([siteA, siteB], '10.0.0.15')).toEqual({ kind: 'ambiguous', candidates: [siteA, siteB] });
    // A strictly narrower subnet still resolves the tie.
    const servers = network('servers', '10.0.0.0/25');
    expect(matchNetworkForIp([siteA, siteB, servers], '10.0.0.15')).toEqual({ kind: 'unique', network: servers });
  });

  it('matches IPv6 by family and ignores malformed input and unresolved L2 networks', () => {
    const v6 = network('v6', '2001:db8::/32');
    const l2 = network('camera-vlan', '');
    const v4 = network('v4', '0.0.0.0/0');
    expect(matchNetworkForIp([v6, l2, v4], '2001:db8:0:1::5')).toEqual({ kind: 'unique', network: v6 });
    expect(matchNetworkForIp([v6, l2], '::ffff:10.0.0.1')).toEqual({ kind: 'none' });
    expect(matchNetworkForIp([v6, l2, v4], '10.0.0.300')).toEqual({ kind: 'none' });
    expect(matchNetworkForIp([v6, l2, v4], 'not-an-address')).toEqual({ kind: 'none' });
    expect(matchNetworkForIp([v6, l2, v4], '')).toEqual({ kind: 'none' });
  });
});
