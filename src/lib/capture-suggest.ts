/**
 * Suggestions for processing a capture: which assets and indicators the
 * captured text seems to mention. Everything is a proposal — the
 * investigator ticks what is justified, and the capture text itself is kept
 * as written either way.
 *
 * "APP01, 10.0.0.15, probably on ESX03. Finance says they own it." suggests
 * the asset APP01 at 10.0.0.15 and (unticked) the host ESX03.
 */
import { v4 as uuidv4 } from 'uuid';
import { detectIocType, iocKey, normalizeIocValue, refang, wasDefanged, type IocType } from '@/lib/ioc-detect';
import type { PartialChange } from '@/lib/reviewed-import';
import { isIpAddress, isPrivateAddress, matchNetworkForIp } from '@/lib/subnet-match';
import type { Asset, Network, NetworkInterface } from '@/types';

export interface AssetSuggestion {
  key: string;
  name: string;
  ipAddress: string;
  reason: string;
  selected: boolean;
  /** An asset with this name is already in the case. */
  existing: boolean;
}

export interface IocSuggestion {
  key: string;
  type: IocType;
  value: string;
  selected: boolean;
  /** This indicator is already in the case. */
  existing: boolean;
}

export interface CaptureSuggestions {
  assets: AssetSuggestion[];
  iocs: IocSuggestion[];
}

export interface SuggestionContext {
  existingAssetNames?: Iterable<string>;
  existingIocKeys?: Iterable<string>;
}

/** Internal DNS suffixes: a name ending in one is a client system, not an indicator. */
const INTERNAL_SUFFIX = /\.(?:local|lan|corp|internal|intra|intranet|ad|home|localdomain|private)$/i;
/** Hostname-like: starts with a letter and contains a digit (APP01, WS-FIN-12, esx03). */
const HOSTNAME = /^[a-z][a-z0-9-]{1,62}$/i;
/** Identifiers that look like hostnames but are not (CVE ids, ATT&CK ids, protocol versions). */
const NOT_A_HOST = /^(?:cve-\d{4}-\d+|t\d{4}(?:\.\d{3})?|ta\d{4}|s\d{4}|g\d{4}|ipv[46]|tlsv?\d+|sslv?\d+|smbv?\d|http\d?|sha\d+|md\d|win\d+|windows\d+|q[1-4]|fy\d+|h[12]|x86|x64|arm64|utf-?\d+|base64|rc\d+|v\d+)$/i;

/**
 * Words that may stand between a host's name and its own address: "DB02 at
 * 10.0.0.40", "APP01 also answers on 10.0.0.16", "SRV7 ip 10.1.1.7". Words
 * that relate two hosts (to, from, talks, connects) are deliberately absent:
 * in "APP01 talks to 10.0.0.40" the address belongs to someone else.
 */
const NAME_TO_ADDRESS = new Set([
  'at', 'on', 'is', 'was', 'has', 'with', 'uses', 'also', 'answers', 'responds', 'listens',
  'ip', 'ipv4', 'ipv6', 'address', 'addr', 'aka', '=', '-', '–', '—', '/',
]);
/** Words between an address and the name it is given: "10.0.0.40 is DB02". */
const ADDRESS_TO_NAME = new Set(['is', 'was', 'aka', '=', '-', '–', '—', '/']);
/** At most this many connecting words between a name and an address. */
const MAX_CONNECTORS = 3;

interface Token {
  raw: string;
  clean: string;
}

function cleanToken(token: string): string {
  return token.trim().replace(/^[("'`<[{]+/, '').replace(/[)"'`>\]},;:!?]+$/, '').replace(/\.+$/, '');
}

function endsSentence(token: Token): boolean {
  return /[.!?]$/.test(token.raw);
}

/** The host named before the address at `index`, within the same sentence. */
function hostBefore(tokens: Token[], index: number): number | undefined {
  for (let at = index - 1; at >= Math.max(0, index - 1 - MAX_CONNECTORS); at -= 1) {
    const token = tokens[at];
    if (endsSentence(token)) return undefined;
    if (isHostname(token.clean)) return at;
    if (!NAME_TO_ADDRESS.has(token.clean.toLowerCase())) return undefined;
  }
  return undefined;
}

/** The host named after the address at `index`: "(DB02)" right after it, or "is DB02". */
function hostAfter(tokens: Token[], index: number): number | undefined {
  const next = tokens[index + 1];
  if (next?.raw.startsWith('(') && isHostname(next.clean)) return index + 1;
  for (let at = index + 1; at <= Math.min(tokens.length - 1, index + 1 + MAX_CONNECTORS); at += 1) {
    if (endsSentence(tokens[at - 1])) return undefined;
    const token = tokens[at];
    // At least one connecting word: a bare "10.0.0.40 DB02" may be the next row of a list.
    if (isHostname(token.clean)) return at > index + 1 ? at : undefined;
    if (!ADDRESS_TO_NAME.has(token.clean.toLowerCase())) return undefined;
  }
  return undefined;
}

function isHostname(token: string): boolean {
  if (INTERNAL_SUFFIX.test(token)) return true;
  return HOSTNAME.test(token) && /\d/.test(token) && !NOT_A_HOST.test(token) && !isIpAddress(token);
}

export function suggestFromCapture(text: string, context: SuggestionContext = {}): CaptureSuggestions {
  const assetNames = new Set([...(context.existingAssetNames ?? [])].map((name) => name.toLowerCase()));
  const iocKeys = new Set(context.existingIocKeys ?? []);
  const tokens: Token[] = [...text.matchAll(/[^\s,;|]+/g)].map((match) => ({ raw: match[0], clean: cleanToken(match[0]) }));
  const assets = new Map<string, AssetSuggestion>();
  const iocs = new Map<string, IocSuggestion>();
  const pairedHosts = new Set<number>();

  const addAsset = (name: string, ipAddress: string, reason: string, selected: boolean) => {
    const key = name.toLowerCase();
    const current = assets.get(key);
    if (current) {
      if (!current.ipAddress && ipAddress) assets.set(key, { ...current, ipAddress, reason, selected: selected && !current.existing });
      return;
    }
    const existing = assetNames.has(key);
    assets.set(key, { key, name, ipAddress, reason, selected: selected && !existing, existing });
  };
  const addIoc = (type: IocType, raw: string, selected: boolean) => {
    const value = normalizeIocValue(type, raw);
    const key = iocKey(type, value);
    if (iocs.has(key)) return;
    const existing = iocKeys.has(key);
    iocs.set(key, { key, type, value, selected: selected && !existing, existing });
  };

  tokens.forEach((token, index) => {
    const value = refang(token.clean);
    if (!value) return;
    const defanged = wasDefanged(token.clean);
    if (isIpAddress(value) && !defanged) {
      const host = hostBefore(tokens, index) ?? hostAfter(tokens, index);
      if (host !== undefined) {
        pairedHosts.add(host);
        addAsset(tokens[host].clean, value, `named next to ${value}`, true);
      } else if (isPrivateAddress(value)) {
        addAsset(value, value, 'internal address without a name', false);
      } else {
        addIoc('IP', value, false);
      }
      return;
    }
    const type = detectIocType(token.clean);
    if (type && !(type === 'Domain' && INTERNAL_SUFFIX.test(value))) {
      // Defanged values, hashes, URLs, paths, and registry keys are almost
      // always indicators; a bare domain, e-mail, or file name may be context.
      const likely = defanged || ['Hash', 'URL', 'FilePath', 'Registry'].includes(type);
      addIoc(type, token.clean, likely);
    }
  });
  tokens.forEach((token, index) => {
    if (pairedHosts.has(index) || !isHostname(token.clean)) return;
    addAsset(token.clean, '', 'mentioned by name', false);
  });
  return { assets: [...assets.values()], iocs: [...iocs.values()] };
}

/** An asset a capture refers to, and the reviewed changes that record it. */
export interface PlannedAsset {
  assetId: string;
  name: string;
  ipAddress: string;
  /** Already in the case: only an address it lacked is added. */
  existing: boolean;
  /** The asset's own change first (new assets), then its interface change. */
  changeIds: string[];
}

export interface CaptureAssetPlan {
  changes: PartialChange[];
  planned: PlannedAsset[];
  warnings: string[];
}

/**
 * Reviewed-import changes for the assets ticked in a capture. A capture only
 * says that a host exists, and maybe its address, so nothing more is
 * recorded: a new asset gets type "other" and, with an address, a primary
 * interface in the one subnet that contains it, the way a manually added
 * asset does. An asset already in the case only gains an address it does
 * not have yet; nothing it holds is overwritten.
 */
export function captureAssetChanges(
  selected: Pick<AssetSuggestion, 'name' | 'ipAddress'>[],
  inventory: { assets: Asset[]; networks: Network[]; networkInterfaces: NetworkInterface[] },
): CaptureAssetPlan {
  const changes: PartialChange[] = [];
  const planned: PlannedAsset[] = [];
  const warnings: string[] = [];
  const seen = new Set<string>();
  for (const item of selected) {
    const name = item.name.trim();
    const ipAddress = item.ipAddress.trim();
    if (!name || seen.has(name.toLowerCase())) continue;
    seen.add(name.toLowerCase());
    const index = planned.length;
    const match = ipAddress ? matchNetworkForIp(inventory.networks, ipAddress) : { kind: 'none' as const };
    if (match.kind === 'ambiguous') {
      warnings.push(`${name}: ${ipAddress} fits ${match.candidates.length} networks with the same subnet (${match.candidates.map((network) => network.name).join(', ')}); left unassigned for review.`);
    }
    const networkId = match.kind === 'unique' ? match.network.id : null;
    const existing = inventory.assets.find((asset) => asset.name.trim().toLowerCase() === name.toLowerCase());

    if (!existing) {
      const assetId = uuidv4();
      const changeIds = [`capture-asset-${index}`];
      changes.push({
        change_id: changeIds[0],
        entity_type: 'asset',
        operation: 'upsert',
        target_id: assetId,
        values: { name, asset_type: 'other', ip_address: ipAddress, network_id: networkId },
      });
      if (ipAddress) {
        changeIds.push(`capture-interface-${index}`);
        changes.push({
          change_id: changeIds[1],
          entity_type: 'network_interface',
          operation: 'upsert',
          target_id: uuidv4(),
          values: { asset_id: assetId, name: 'Primary', ip_address: ipAddress, network_id: networkId, is_primary: true },
        });
      }
      planned.push({ assetId, name, ipAddress, existing: false, changeIds });
      continue;
    }

    const interfaces = inventory.networkInterfaces.filter((item) => item.asset_id === existing.id);
    const known = existing.ip_address === ipAddress || interfaces.some((item) => item.ip_address === ipAddress);
    if (!ipAddress || known) {
      warnings.push(`${existing.name} is already in the case${ipAddress ? ` with ${ipAddress}` : ''}; it is linked to the capture and left unchanged.`);
      planned.push({ assetId: existing.id, name: existing.name, ipAddress, existing: true, changeIds: [] });
      continue;
    }
    const changeId = `capture-interface-${index}`;
    changes.push({
      change_id: changeId,
      entity_type: 'network_interface',
      operation: 'upsert',
      target_id: uuidv4(),
      values: { asset_id: existing.id, name: 'From capture', ip_address: ipAddress, network_id: networkId, is_primary: interfaces.length === 0 },
    });
    planned.push({ assetId: existing.id, name: existing.name, ipAddress, existing: true, changeIds: [changeId] });
  }
  return { changes, planned, warnings };
}
