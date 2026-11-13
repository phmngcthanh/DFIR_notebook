/**
 * Is this the machine we already have? One recognizer for everything that
 * records assets: the Add Asset form, the hypervisor and discovery importers,
 * and the "possible duplicates" scan.
 *
 * Evidence, strongest first: a shared hardware (MAC) address on any NIC; the
 * same name and the same address; the same full name. An address alone, or a
 * short name alone ("app01" against "app01.corp.local"), is only worth asking
 * about, because addresses are reused (DHCP, isolated sites with the same
 * range) and short names collide across sites. Two different MAC addresses
 * mean two machines (or a replaced card) whatever else agrees, so they cap
 * the match at "worth asking".
 */
import { isIpAddress } from '@/lib/subnet-match';
import type { Asset, NetworkInterface } from '@/types';

export type MatchReason = 'mac' | 'ip' | 'name';
export type MatchStrength = 'strong' | 'weak';

export interface MatchCandidate {
  name?: string | null;
  ips?: (string | null | undefined)[];
  macs?: (string | null | undefined)[];
}

export interface AssetMatch {
  asset: Asset;
  reasons: MatchReason[];
  strength: MatchStrength;
  /** Both sides have hardware addresses and none agree: two machines, or a replaced card. */
  macConflict: boolean;
}

export interface DuplicatePair {
  first: Asset;
  second: Asset;
  reasons: MatchReason[];
  strength: MatchStrength;
}

/** Hex digits only, lower case; empty unless it is a full 48-bit address. */
export function normalizeMac(value?: string | null): string {
  const digits = (value ?? '').replace(/[^0-9a-f]/gi, '').toLowerCase();
  return digits.length === 12 ? digits : '';
}

function normalizeIp(value?: string | null): string {
  const text = (value ?? '').trim().toLowerCase();
  return isIpAddress(text) ? text : '';
}

/** `app01.corp.local` → `app01`; a name that is an address stays whole. */
export function shortName(value?: string | null): string {
  const text = (value ?? '').trim().toLowerCase();
  if (!text || isIpAddress(text)) return text;
  return text.split('.')[0];
}

function fullName(value?: string | null): string {
  return (value ?? '').trim().toLowerCase();
}

/** The identifiers one asset is known by: its own row and every NIC. */
interface Identity {
  asset: Asset;
  macs: Set<string>;
  ips: Set<string>;
  short: string;
  full: string;
}

function identities(assets: Asset[], interfaces: NetworkInterface[]): Identity[] {
  const byAsset = new Map<string, NetworkInterface[]>();
  for (const item of interfaces) {
    const list = byAsset.get(item.asset_id) ?? [];
    list.push(item);
    byAsset.set(item.asset_id, list);
  }
  return assets.map((asset) => {
    const nics = byAsset.get(asset.id) ?? [];
    const macs = new Set([asset.mac_address, ...nics.map((nic) => nic.mac_address)].map(normalizeMac).filter(Boolean));
    const ips = new Set([asset.ip_address, ...nics.map((nic) => nic.ip_address)].map(normalizeIp).filter(Boolean));
    return { asset, macs, ips, short: shortName(asset.name), full: fullName(asset.name) };
  });
}

function intersects(left: Set<string>, right: Set<string>): boolean {
  for (const value of left) if (right.has(value)) return true;
  return false;
}

/** Both sides have hardware addresses and none agree. */
function macsConflict(left: Set<string>, right: Set<string>): boolean {
  return left.size > 0 && right.size > 0 && !intersects(left, right);
}

function judge(reasons: MatchReason[], conflict: boolean, sameFullName: boolean): MatchStrength {
  if (reasons.includes('mac')) return 'strong';
  if (conflict) return 'weak';
  if (reasons.includes('name') && reasons.includes('ip')) return 'strong';
  if (sameFullName && reasons.includes('name')) return 'strong';
  return 'weak';
}

/** Existing assets that may be the candidate, strongest first. */
export function findAssetMatches(candidate: MatchCandidate, assets: Asset[], interfaces: NetworkInterface[]): AssetMatch[] {
  const macs = new Set((candidate.macs ?? []).map(normalizeMac).filter(Boolean));
  const ips = new Set((candidate.ips ?? []).map(normalizeIp).filter(Boolean));
  const short = shortName(candidate.name);
  const full = fullName(candidate.name);
  // A candidate named by an address (an ARP entry) has no name to compare.
  const nameCounts = Boolean(short) && !isIpAddress(short);
  const matches: AssetMatch[] = [];
  for (const known of identities(assets, interfaces)) {
    const reasons: MatchReason[] = [];
    if (intersects(macs, known.macs)) reasons.push('mac');
    if (intersects(ips, known.ips)) reasons.push('ip');
    if (nameCounts && known.short && known.short === short) reasons.push('name');
    if (!reasons.length) continue;
    const macConflict = macsConflict(macs, known.macs);
    matches.push({
      asset: known.asset,
      reasons,
      strength: judge(reasons, macConflict, nameCounts && known.full === full),
      macConflict,
    });
  }
  return matches.sort((left, right) => rank(right) - rank(left) || left.asset.name.localeCompare(right.asset.name));
}

function rank(match: { strength: MatchStrength; reasons: MatchReason[] }): number {
  return (match.strength === 'strong' ? 10 : 0) + match.reasons.length;
}

/** Buckets larger than this share a value that identifies nothing (a gateway, 0.0.0.0). */
const MAX_BUCKET = 25;

/** Pairs of existing assets that look like the same machine, strongest first. */
export function findDuplicatePairs(assets: Asset[], interfaces: NetworkInterface[]): DuplicatePair[] {
  const known = identities(assets, interfaces);
  const buckets = new Map<string, number[]>();
  const add = (key: string, index: number) => {
    const list = buckets.get(key) ?? [];
    if (!list.includes(index)) list.push(index);
    buckets.set(key, list);
  };
  known.forEach((item, index) => {
    item.macs.forEach((mac) => add(`mac:${mac}`, index));
    item.ips.forEach((ip) => add(`ip:${ip}`, index));
    if (item.short && !isIpAddress(item.short)) add(`name:${item.short}`, index);
  });
  const pairs = new Map<string, Set<MatchReason>>();
  for (const [key, members] of buckets) {
    if (members.length < 2 || members.length > MAX_BUCKET) continue;
    const reason = key.slice(0, key.indexOf(':')) as MatchReason;
    for (let a = 0; a < members.length; a += 1) {
      for (let b = a + 1; b < members.length; b += 1) {
        const id = `${members[a]}:${members[b]}`;
        const reasons = pairs.get(id) ?? new Set<MatchReason>();
        reasons.add(reason);
        pairs.set(id, reasons);
      }
    }
  }
  const result: DuplicatePair[] = [];
  for (const [id, reasonSet] of pairs) {
    const [a, b] = id.split(':').map(Number);
    const reasons = (['mac', 'ip', 'name'] as MatchReason[]).filter((reason) => reasonSet.has(reason));
    result.push({
      first: known[a].asset,
      second: known[b].asset,
      reasons,
      strength: judge(reasons, macsConflict(known[a].macs, known[b].macs), known[a].full === known[b].full && Boolean(known[a].full)),
    });
  }
  return result.sort((left, right) => rank(right) - rank(left) || left.first.name.localeCompare(right.first.name));
}

/**
 * The same interface recorded twice: the same address, and hardware addresses
 * that agree or are missing on one side (an ARP entry knows the MAC, a typed
 * one does not). The core applies the same rule when it merges assets.
 */
export function sameNic(left: { ip: string; mac?: string | null }, right: { ip: string; mac?: string | null }): boolean {
  const [leftMac, rightMac] = [normalizeMac(left.mac), normalizeMac(right.mac)];
  const ip = left.ip.trim();
  if (!ip && !leftMac && !rightMac) return false;
  return ip.toLowerCase() === right.ip.trim().toLowerCase() && (leftMac === rightMac || !leftMac || !rightMac);
}

/** "same MAC address and name" for a toast or a confirmation. */
export function describeReasons(reasons: MatchReason[]): string {
  const words = reasons.map((reason) => (reason === 'mac' ? 'MAC address' : reason === 'ip' ? 'IP address' : 'name'));
  return words.length > 1 ? `same ${words.slice(0, -1).join(', ')} and ${words[words.length - 1]}` : `same ${words[0] ?? 'details'}`;
}
