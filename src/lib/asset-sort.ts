import type { Asset, CompromiseStatus, InvestigationStatus } from '@/types';

export type AssetSortKey = 'name' | 'network' | 'ip' | 'type' | 'compromise' | 'progress' | 'nics';
export interface AssetSort { key: AssetSortKey; direction: 'asc' | 'desc' }

/** Compromise ordering follows severity, not the alphabet: clean first, infected last. */
const COMPROMISE_RANK: Record<CompromiseStatus, number> = { clean: 0, unknown: 1, suspected: 2, infected: 3 };
const PROGRESS_RANK: Record<InvestigationStatus, number> = { not_started: 0, in_progress: 1, completed: 2 };

const TEXT_COLLATOR = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

function ipv4Key(value: string): number[] | null {
  const parts = value.trim().split('.');
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    octets.push(octet);
  }
  return octets;
}

/**
 * Numeric ordering for dotted-quad IPv4 addresses (`10.0.0.9` before
 * `10.0.0.10`); anything that is not a plain IPv4 sorts after them by string.
 */
export function compareIpAddresses(left: string | undefined, right: string | undefined): number {
  const leftKey = left ? ipv4Key(left) : null;
  const rightKey = right ? ipv4Key(right) : null;
  if (leftKey && rightKey) {
    for (let index = 0; index < 4; index += 1) {
      const difference = leftKey[index] - rightKey[index];
      if (difference !== 0) return difference;
    }
    return 0;
  }
  if (leftKey) return -1;
  if (rightKey) return 1;
  return TEXT_COLLATOR.compare(left ?? '', right ?? '');
}

export function sortAssets(assets: Asset[], nicCounts: ReadonlyMap<string, number>, sort: AssetSort | null): Asset[] {
  if (!sort) return assets;
  const factor = sort.direction === 'asc' ? 1 : -1;
  const byName = (left: Asset, right: Asset) => TEXT_COLLATOR.compare(left.name, right.name) || left.id.localeCompare(right.id);
  return [...assets].sort((left, right) => {
    let result = 0;
    switch (sort.key) {
      case 'name':
        return factor * byName(left, right);
      case 'network':
        result = TEXT_COLLATOR.compare(left.network_name ?? '', right.network_name ?? '') || byName(left, right);
        break;
      case 'ip':
        result = compareIpAddresses(left.ip_address, right.ip_address) || byName(left, right);
        break;
      case 'type':
        result = TEXT_COLLATOR.compare(left.asset_type, right.asset_type)
          || TEXT_COLLATOR.compare(left.os ?? '', right.os ?? '')
          || byName(left, right);
        break;
      case 'compromise':
        result = COMPROMISE_RANK[left.compromise_status] - COMPROMISE_RANK[right.compromise_status] || byName(left, right);
        break;
      case 'progress':
        result = PROGRESS_RANK[left.investigation_status] - PROGRESS_RANK[right.investigation_status] || byName(left, right);
        break;
      case 'nics':
        result = (nicCounts.get(left.id) ?? 0) - (nicCounts.get(right.id) ?? 0) || byName(left, right);
        break;
    }
    return result * factor;
  });
}
