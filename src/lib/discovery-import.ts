/**
 * From parsed discovery output to reviewed changes. Each host becomes a row
 * the investigator can add as a new asset, use to update the asset it matches,
 * or skip; only then are partial-import changes built, previewed by the core,
 * and applied as one attributed commit.
 *
 * What a discovery records is what the output says and nothing more: a new
 * asset is typed "other" (or Windows by what ipconfig prints), marked
 * `discovered`, given the time it was observed, and linked to the one subnet
 * that contains its address. An asset already in the case only gains what it
 * lacked (a MAC address, an interface, the observation time) and is never
 * rewritten. An asset the client listed keeps that origin.
 */
import { v4 as uuidv4 } from 'uuid';
import { findAssetMatches, sameNic, type AssetMatch } from '@/lib/asset-match';
import type { DiscoveredHost, DiscoveredNic, ParsedDiscovery } from '@/lib/discovery-parse';
import { partialDocument, type PartialChange } from '@/lib/reviewed-import';
import { matchNetworkForIp } from '@/lib/subnet-match';
import { classifyGuestOs } from '@/lib/vm-inventory';
import type { Asset, JsonValue, Network, NetworkInterface } from '@/types';

export interface DiscoveryInventory {
  caseId: string;
  assets: Asset[];
  networks: Network[];
  networkInterfaces: NetworkInterface[];
}

export type DiscoveryAction = 'create' | 'update' | 'skip';

export interface DiscoveryRow {
  id: string;
  host: DiscoveredHost;
  /** What a new asset is called. Editable before the import is built. */
  name: string;
  match: AssetMatch | null;
  action: DiscoveryAction;
}

export interface BuiltDiscoveryImport {
  document: string;
  changeCount: number;
  warnings: string[];
}

function assetTypeFor(host: DiscoveredHost): string {
  const os = host.os ?? '';
  if (classifyGuestOs(os) === 'mobile') return 'mobile';
  if (/windows server/i.test(os)) return 'server';
  if (/windows/i.test(os)) return 'workstation';
  return 'other';
}

/**
 * One row per host, with the action it starts on. A match on hardware address
 * or on name and address updates the asset it names. An address alone updates
 * it from live output (ARP, ipconfig, nmap) but not from DHCP history, where
 * addresses were reused; a different MAC at the same address, or a short name
 * alone, is left for the investigator.
 */
export function planDiscovery(parsed: ParsedDiscovery, inventory: DiscoveryInventory): DiscoveryRow[] {
  return parsed.hosts.map((host, index) => {
    const match = findAssetMatches(
      { name: host.name, ips: host.nics.map((nic) => nic.ip), macs: host.nics.map((nic) => nic.mac) },
      inventory.assets,
      inventory.networkInterfaces,
    )[0] ?? null;
    let action: DiscoveryAction = 'create';
    if (host.reference) action = 'skip';
    else if (match) {
      const live = parsed.format !== 'dhcp';
      action = match.strength === 'strong' || (live && !match.macConflict && match.reasons.includes('ip')) ? 'update' : 'skip';
    }
    return { id: `host-${index}`, host, name: host.name || host.nics[0]?.ip || `host-${index + 1}`, match, action };
  });
}

/** The open ports and scan details worth keeping with the asset, or null when there are none. */
function scanResultsFor(host: DiscoveredHost, observedAt: string): string | null {
  if (!host.ports?.length && !host.vendor) return null;
  return JSON.stringify({
    source: 'nmap',
    scanned_at: observedAt,
    open_ports: (host.ports ?? []).map((port) => ({ port: port.port, protocol: port.protocol, service: port.service })),
    ...(host.vendor ? { mac_vendor: host.vendor } : {}),
    ...(host.os ? { os_guess: host.os } : {}),
  });
}

/** A new scan replaces an earlier nmap result; anything else already stored is kept. */
function mayReplaceScan(existing?: string): boolean {
  if (!existing?.trim()) return true;
  try {
    return (JSON.parse(existing) as { source?: string }).source === 'nmap';
  } catch {
    return false;
  }
}

function later(candidate: string, current?: string | null): boolean {
  return !current || Date.parse(candidate) > Date.parse(current);
}

export function buildDiscoveryImport(
  rows: DiscoveryRow[],
  inventory: DiscoveryInventory,
  options: { observedAt: string; sourceLabel: string },
): BuiltDiscoveryImport {
  const changes: PartialChange[] = [];
  const warnings = new Set<string>();
  const networkFor = (ip: string, host: string): Network | undefined => {
    const match = matchNetworkForIp(inventory.networks, ip);
    if (match.kind === 'ambiguous') {
      warnings.add(`${host}: ${ip} fits ${match.candidates.length} networks with the same subnet (${match.candidates.map((network) => network.name).join(', ')}); left unassigned for review.`);
    }
    return match.kind === 'unique' ? match.network : undefined;
  };
  const nicValues = (assetId: string, nic: DiscoveredNic, name: string, primary: boolean, host: string): Record<string, JsonValue | undefined> => ({
    asset_id: assetId,
    name,
    ip_address: nic.ip,
    mac_address: nic.mac || null,
    network_id: networkFor(nic.ip, host)?.id ?? null,
    is_primary: primary,
  });

  rows.filter((row) => row.action !== 'skip').forEach((row, index) => {
    const { host } = row;
    const label = row.name || host.nics[0]?.ip || 'host';
    const observedAt = host.observedAt ?? options.observedAt;
    const target = row.action === 'update' ? row.match?.asset : undefined;

    if (!target) {
      const assetId = uuidv4();
      const primary = host.nics[0];
      changes.push({
        change_id: `discovery-asset-${index}`,
        entity_type: 'asset',
        operation: 'upsert',
        target_id: assetId,
        values: {
          name: row.name.trim() || label,
          asset_type: assetTypeFor(host),
          ip_address: primary?.ip ?? '',
          mac_address: primary?.mac || null,
          network_id: primary ? networkFor(primary.ip, label)?.id ?? null : null,
          os: host.os ?? null,
          origin: 'discovered',
          last_observed: observedAt,
          scan_results: scanResultsFor(host, observedAt),
        },
      });
      host.nics.forEach((nic, nicIndex) => changes.push({
        change_id: `discovery-nic-${index}-${nicIndex}`,
        entity_type: 'network_interface',
        operation: 'upsert',
        target_id: uuidv4(),
        values: nicValues(assetId, nic, nic.name || (nicIndex === 0 ? 'Primary' : `NIC ${nicIndex + 1}`), nicIndex === 0, label),
      }));
      return;
    }

    const values: Record<string, JsonValue | undefined> = {};
    if (later(observedAt, target.last_observed)) values.last_observed = observedAt;
    if (!target.os && host.os) values.os = host.os;
    const scan = scanResultsFor(host, observedAt);
    if (scan && mayReplaceScan(target.scan_results)) values.scan_results = scan;
    else if (scan) warnings.add(`${target.name}: kept its existing scan results; the new nmap details were not stored.`);
    if (Object.keys(values).length) {
      changes.push({ change_id: `discovery-asset-${index}`, entity_type: 'asset', operation: 'update', target_id: target.id, values });
    }
    const known = inventory.networkInterfaces.filter((item) => item.asset_id === target.id);
    host.nics.forEach((nic, nicIndex) => {
      const same = known.find((item) => sameNic({ ip: item.ip_address, mac: item.mac_address }, nic));
      if (same) {
        // The interface is already recorded; it may only lack the hardware address.
        if (!same.mac_address && nic.mac) {
          changes.push({ change_id: `discovery-nic-${index}-${nicIndex}`, entity_type: 'network_interface', operation: 'update', target_id: same.id, values: { mac_address: nic.mac } });
        }
        return;
      }
      changes.push({
        change_id: `discovery-nic-${index}-${nicIndex}`,
        entity_type: 'network_interface',
        operation: 'upsert',
        target_id: uuidv4(),
        values: nicValues(target.id, nic, nic.name && nic.name !== 'Primary' ? nic.name : 'From discovery', known.length === 0 && nicIndex === 0, target.name),
      });
    });
  });

  if (!changes.length) throw new Error('Nothing to record: every chosen host is already in the case with these details.');
  return {
    document: partialDocument(inventory.caseId, options.sourceLabel, changes),
    changeCount: changes.length,
    warnings: [...warnings],
  };
}
