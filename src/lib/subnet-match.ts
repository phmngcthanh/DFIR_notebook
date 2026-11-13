/**
 * Places an address among the case's recorded subnets the same way the core
 * does when it auto-links an endpoint (`match_network_for_ip` in `db.rs`): the
 * most specific containing subnet wins, and two or more equally specific
 * candidates are ambiguous. Isolated sites often reuse one private range, so an
 * ambiguous address is left for the investigator instead of being given to
 * whichever network was recorded first.
 */
import type { Network } from '@/types';

export type SubnetMatch =
  | { kind: 'none' }
  | { kind: 'unique'; network: Network }
  | { kind: 'ambiguous'; candidates: Network[] };

interface Address {
  family: 4 | 6;
  value: bigint;
}

function parseIpv4(text: string): bigint | null {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = (value << 8n) | BigInt(octet);
  }
  return value;
}

function parseIpv6(text: string): bigint | null {
  const address = text.split('%')[0];
  const halves = address.split('::');
  if (halves.length > 2) return null;
  const groups = (part: string): number[] | null => {
    if (!part) return [];
    const result: number[] = [];
    const pieces = part.split(':');
    for (let index = 0; index < pieces.length; index += 1) {
      const piece = pieces[index];
      if (index === pieces.length - 1 && piece.includes('.')) {
        const embedded = parseIpv4(piece);
        if (embedded === null) return null;
        result.push(Number(embedded >> 16n), Number(embedded & 0xffffn));
        continue;
      }
      if (!/^[0-9a-f]{1,4}$/i.test(piece)) return null;
      result.push(Number.parseInt(piece, 16));
    }
    return result;
  };
  const head = groups(halves[0]);
  const tail = halves.length === 2 ? groups(halves[1]) : [];
  if (!head || !tail) return null;
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  const all = [...head, ...Array<number>(Math.max(missing, 0)).fill(0), ...tail];
  return all.reduce((value, group) => (value << 16n) | BigInt(group), 0n);
}

function parseAddress(text: string): Address | null {
  const trimmed = text.trim();
  if (!trimmed) return null;
  if (trimmed.includes(':')) {
    const value = parseIpv6(trimmed);
    return value === null ? null : { family: 6, value };
  }
  const value = parseIpv4(trimmed);
  return value === null ? null : { family: 4, value };
}

function parseCidr(subnet: string): { family: 4 | 6; network: bigint; prefix: number } | null {
  const [addressText, prefixText, extra] = subnet.trim().split('/');
  if (extra !== undefined || prefixText === undefined || !/^\d{1,3}$/.test(prefixText)) return null;
  const address = parseAddress(addressText);
  if (!address) return null;
  const prefix = Number(prefixText);
  const bits = address.family === 4 ? 32 : 128;
  if (prefix > bits) return null;
  return { family: address.family, network: address.value >> BigInt(bits - prefix), prefix };
}

function contains(cidr: { family: 4 | 6; network: bigint; prefix: number }, address: Address): boolean {
  if (cidr.family !== address.family) return false;
  const bits = address.family === 4 ? 32 : 128;
  return address.value >> BigInt(bits - cidr.prefix) === cidr.network;
}

/** True for a plain IPv4 or IPv6 address (no prefix length). */
export function isIpAddress(text: string): boolean {
  return parseAddress(text) !== null;
}

/** True for addresses in private, loopback, link-local, or CGNAT space. */
export function isPrivateAddress(text: string): boolean {
  const address = parseAddress(text);
  if (!address) return false;
  const ranges = address.family === 4
    ? ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '100.64.0.0/10']
    : ['fc00::/7', 'fe80::/10', '::1/128'];
  return ranges.some((range) => {
    const cidr = parseCidr(range);
    return cidr !== null && contains(cidr, address);
  });
}

/** Which recorded network an address belongs to, if exactly one is the most specific fit. */
export function matchNetworkForIp(networks: Network[], ipAddress: string): SubnetMatch {
  const address = parseAddress(ipAddress);
  if (!address) return { kind: 'none' };
  let bestPrefix = -1;
  let best: Network[] = [];
  for (const network of networks) {
    const cidr = parseCidr(network.subnet);
    if (!cidr || !contains(cidr, address)) continue;
    if (cidr.prefix > bestPrefix) {
      bestPrefix = cidr.prefix;
      best = [network];
    } else if (cidr.prefix === bestPrefix) {
      best.push(network);
    }
  }
  if (best.length === 0) return { kind: 'none' };
  if (best.length === 1) return { kind: 'unique', network: best[0] };
  return { kind: 'ambiguous', candidates: best };
}
