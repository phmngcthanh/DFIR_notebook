import { v4 as uuidv4 } from 'uuid';
import type {
  Asset,
  Firewall,
  FirewallInterface,
  FirewallNatRule,
  JsonValue,
  Network,
  NetworkInterface,
} from '@/types';
import {
  hostAddress,
  type ParsedDeviceConfig,
  type ParsedInterface,
  type ParsedNatRule,
  readStoredDeviceConfig,
  subnetFromAddress,
} from '@/lib/network-config';

export interface ConfigImportInventory {
  caseId: string;
  networks: Network[];
  assets: Asset[];
  networkInterfaces: NetworkInterface[];
  firewalls: Firewall[];
  firewallInterfaces: FirewallInterface[];
  firewallNatRules: FirewallNatRule[];
}

interface PartialChange {
  change_id: string;
  entity_type: string;
  operation: 'upsert';
  target_id: string;
  values: Record<string, JsonValue | undefined>;
}

export interface BuiltConfigImport {
  document: string;
  warnings: string[];
  changeCount: number;
}

interface DerivedNetwork {
  id: string;
  name: string;
  subnet: string;
  networkType: string;
  description: string;
  vlanId?: string;
  existing: boolean;
  interfaceNames: Set<string>;
}

function importedDescription(config: ParsedDeviceConfig, detail: string): string {
  return `Imported from ${config.vendor} ${config.hostname}: ${detail}`;
}

function networkType(item: ParsedInterface): string {
  if (item.role === 'wan') return 'WAN';
  if (item.role === 'dmz') return 'DMZ';
  if (item.role === 'management') return 'MANAGEMENT';
  return 'LAN';
}

function stableNetworkName(config: ParsedDeviceConfig, item: ParsedInterface, subnet: string): string {
  if (item.vlanId) {
    const vlan = config.vlans.find((candidate) => candidate.id === item.vlanId);
    return vlan?.name ?? `VLAN ${item.vlanId}`;
  }
  if (item.zone) return `${config.hostname} ${item.zone}`;
  return `${config.hostname} ${item.name}${subnet ? '' : ' L2'}`;
}

function networkMatch(
  inventory: ConfigImportInventory,
  name: string,
  subnet: string,
  vlanId?: string,
): Network | undefined {
  const exact = inventory.networks.find((item) =>
    item.name.toLowerCase() === name.toLowerCase()
    && item.subnet === subnet
    && (item.vlan_id ?? '') === (vlanId ?? ''));
  if (exact) return exact;
  if (vlanId) {
    const vlanMatches = inventory.networks.filter((item) => item.vlan_id === vlanId && item.name.toLowerCase() === name.toLowerCase());
    if (vlanMatches.length === 1) return vlanMatches[0];
  }
  if (subnet) {
    const subnetMatches = inventory.networks.filter((item) => item.subnet === subnet);
    if (subnetMatches.length === 1) return subnetMatches[0];
  }
  return inventory.networks.find((item) => item.name.toLowerCase() === name.toLowerCase());
}

function topologyInterfaces(config: ParsedDeviceConfig): ParsedInterface[] {
  const result = [...config.interfaces];
  for (const vlan of config.vlans) {
    if (result.some((item) => item.vlanId === vlan.id)) continue;
    result.push({
      name: `VLAN ${vlan.id}${vlan.interfaces.length ? ` (${vlan.interfaces.join(', ')})` : ''}`,
      addresses: vlan.subnet ? [vlan.subnet] : [],
      vlanId: vlan.id,
      zone: vlan.name,
      role: 'lan',
      description: `Logical VLAN attachment derived from ${vlan.interfaces.join(', ') || 'device configuration'}`,
      enabled: true,
    });
  }
  return result;
}

function derivedNetworks(config: ParsedDeviceConfig, inventory: ConfigImportInventory, importedInterfaces: ParsedInterface[]): DerivedNetwork[] {
  const result: DerivedNetwork[] = [];
  const findOrCreate = (item: ParsedInterface, subnet: string, vlanId?: string) => {
    const name = stableNetworkName(config, item, subnet);
    let network = result.find((candidate) =>
      (subnet && candidate.subnet === subnet)
      || (!subnet && candidate.name === name && candidate.vlanId === vlanId));
    if (!network) {
      const existing = networkMatch(inventory, name, subnet, vlanId);
      network = {
        id: existing?.id ?? uuidv4(),
        name: existing?.name ?? name,
        subnet: existing?.subnet ?? subnet,
        networkType: existing?.network_type ?? networkType(item),
        description: existing?.description ?? importedDescription(config, subnet ? `${item.name} ${subnet}` : `${item.name}; subnet unresolved`),
        vlanId: existing?.vlan_id ?? vlanId,
        existing: Boolean(existing),
        interfaceNames: new Set(),
      };
      result.push(network);
    }
    network.interfaceNames.add(item.name);
  };

  for (const item of importedInterfaces) {
    const addressSubnets = item.addresses.map(subnetFromAddress).filter(Boolean);
    if (addressSubnets.length) {
      for (const subnet of addressSubnets) findOrCreate(item, subnet, item.vlanId);
    } else if (item.vlanId || item.zone) {
      findOrCreate(item, '', item.vlanId);
    }
  }
  return result;
}

function interfaceNetwork(networks: DerivedNetwork[], item: ParsedInterface, address?: string): DerivedNetwork | undefined {
  const subnet = address ? subnetFromAddress(address) : '';
  return networks.find((network) =>
    (subnet && network.subnet === subnet)
    || (item.vlanId && network.vlanId === item.vlanId)
    || network.interfaceNames.has(item.name));
}

function change(
  changes: PartialChange[],
  entityType: string,
  targetId: string,
  values: Record<string, JsonValue | undefined>,
): void {
  changes.push({
    change_id: `config-${entityType}-${targetId}`,
    entity_type: entityType,
    operation: 'upsert',
    target_id: targetId,
    values,
  });
}

function validAddress(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const address = hostAddress(value);
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(address) || address.includes(':')) return address;
  return undefined;
}

function validCidrOrIp(value: string | undefined): string | undefined {
  if (!value || value.includes(',') || value.startsWith('zone:') || /[A-Za-z]/.test(value.replace(/[a-f]/gi, ''))) return undefined;
  const address = hostAddress(value);
  return validAddress(address) ? value : undefined;
}

function normalizedNatType(rule: ParsedNatRule): FirewallNatRule['nat_type'] {
  return rule.natType;
}

function protocol(value: string): FirewallNatRule['protocol'] {
  const normalized = value.toLowerCase();
  if (['any', 'tcp', 'udp', 'icmp', 'sctp'].includes(normalized)) return normalized as FirewallNatRule['protocol'];
  return 'other';
}

function normalizedConfigValue(
  config: ParsedDeviceConfig,
  existingJson: string | null | undefined,
  legacyField: 'legacyProperties' | 'legacyRules',
): JsonValue {
  if (!existingJson?.trim()) return config as unknown as JsonValue;
  const existingNormalized = readStoredDeviceConfig(existingJson);
  if (existingNormalized) {
    const existingObject = JSON.parse(existingJson) as Record<string, JsonValue>;
    return existingObject[legacyField] === undefined
      ? config as unknown as JsonValue
      : { ...(config as unknown as Record<string, JsonValue>), [legacyField]: existingObject[legacyField] };
  }
  let legacy: JsonValue = existingJson;
  try {
    legacy = JSON.parse(existingJson) as JsonValue;
  } catch {
    // Preserve non-standard legacy text verbatim inside the normalized record.
  }
  return { ...(config as unknown as Record<string, JsonValue>), [legacyField]: legacy };
}

function natValues(
  rule: ParsedNatRule,
  config: ParsedDeviceConfig,
  warnings: string[],
): Record<string, JsonValue | undefined> | null {
  const translatedSource = validCidrOrIp(rule.translatedSource);
  const translatedDestination = validCidrOrIp(rule.translatedDestination);
  if (rule.natType === 'snat' && !translatedSource) {
    warnings.push(`NAT rule “${rule.name}” remains in the normalized configuration but could not become a structured NAT row because its translated source is symbolic.`);
    return null;
  }
  if (rule.natType !== 'snat' && !translatedDestination) {
    warnings.push(`NAT rule “${rule.name}” remains in the normalized configuration but could not become a structured NAT row because its translated destination is symbolic or missing.`);
    return null;
  }
  return {
    name: rule.name,
    nat_type: normalizedNatType(rule),
    enabled: rule.enabled,
    protocol: protocol(rule.protocol),
    source_cidr: validCidrOrIp(rule.source) ?? null,
    original_destination: validCidrOrIp(rule.originalDestination) ?? null,
    original_port: rule.originalPort ?? null,
    translated_source: translatedSource ?? null,
    translated_destination: translatedDestination ?? null,
    translated_port: rule.translatedPort ?? null,
    inbound_interface_id: null,
    outbound_interface_id: null,
    description: rule.description ?? importedDescription(config, 'normalized NAT rule'),
  };
}

export function buildConfigImport(
  config: ParsedDeviceConfig,
  inventory: ConfigImportInventory,
): BuiltConfigImport {
  const changes: PartialChange[] = [];
  const warnings = [...config.warnings];
  const importedInterfaces = topologyInterfaces(config);
  const networks = derivedNetworks(config, inventory, importedInterfaces);

  for (const item of networks) {
    if (!item.existing) {
      change(changes, 'network', item.id, {
        name: item.name,
        subnet: item.subnet,
        network_type: item.networkType,
        description: item.description,
        vlan_id: item.vlanId ?? null,
      });
    }
  }

  const primaryParsed = importedInterfaces.find((item) => item.enabled && item.role === 'management' && item.addresses.length > 0)
    ?? importedInterfaces.find((item) => item.enabled && item.role === 'lan' && item.addresses.length > 0)
    ?? importedInterfaces.find((item) => item.enabled && item.role !== 'wan' && item.addresses.length > 0)
    ?? importedInterfaces.find((item) => item.enabled && item.addresses.length > 0)
    ?? importedInterfaces.find((item) => item.enabled)
    ?? importedInterfaces[0];
  const primaryNetwork = primaryParsed ? interfaceNetwork(networks, primaryParsed, primaryParsed.addresses[0]) : undefined;

  if (config.deviceType === 'firewall') {
    const existing = inventory.firewalls.find((item) => item.name.toLowerCase() === config.hostname.toLowerCase());
    const firewallId = existing?.id ?? uuidv4();
    change(changes, 'firewall', firewallId, {
      network_id: primaryNetwork?.id ?? null,
      name: config.hostname,
      vendor: config.vendor,
      model: config.model ?? null,
      rules: normalizedConfigValue(config, existing?.rules, 'legacyRules'),
      config_text: config.rawConfig,
    });

    let markedPrimary = false;
    for (const item of importedInterfaces) {
      const network = interfaceNetwork(networks, item, item.addresses[0]);
      const existingInterface = inventory.firewallInterfaces.find((candidate) =>
        candidate.firewall_id === firewallId && candidate.name === item.name);
      const interfaceId = existingInterface?.id ?? uuidv4();
      const isPrimary = !markedPrimary && item === primaryParsed;
      if (isPrimary) markedPrimary = true;
      change(changes, 'firewall_interface', interfaceId, {
        firewall_id: firewallId,
        name: item.name,
        ip_addresses: item.addresses,
        mac_address: item.macAddress ?? null,
        network_id: network?.id ?? null,
        vlan_id: item.vlanId ?? null,
        role: item.role,
        is_primary: isPrimary,
        description: item.description ?? (item.zone ? `Zone ${item.zone}` : ''),
      });
    }

    for (const rule of config.natRules) {
      const values = natValues(rule, config, warnings);
      if (!values) continue;
      const existingRule = inventory.firewallNatRules.find((candidate) =>
        candidate.firewall_id === firewallId && candidate.name === rule.name);
      const ruleId = existingRule?.id ?? uuidv4();
      change(changes, 'firewall_nat_rule', ruleId, { firewall_id: firewallId, ...values });
    }
  } else {
    const existing = inventory.assets.find((item) =>
      item.name.toLowerCase() === config.hostname.toLowerCase()
      && ['router', 'switch'].includes(item.asset_type));
    const assetId = existing?.id ?? uuidv4();
    change(changes, 'asset', assetId, {
      network_id: primaryNetwork?.id ?? null,
      name: config.hostname,
      ip_address: primaryParsed?.addresses[0] ? hostAddress(primaryParsed.addresses[0]) : '',
      mac_address: primaryParsed?.macAddress ?? null,
      asset_type: config.deviceType,
      os: config.vendor,
      user_name: null,
      compromise_status: existing?.compromise_status ?? 'unknown',
      investigation_status: existing?.investigation_status ?? 'not_started',
      properties: normalizedConfigValue(config, existing?.properties, 'legacyProperties'),
      scan_results: existing?.scan_results ?? null,
    });

    let markedPrimary = false;
    for (const item of importedInterfaces) {
      const addresses = item.addresses.length ? item.addresses : [''];
      for (const [index, address] of addresses.entries()) {
        const name = index === 0 ? item.name : `${item.name} [${index + 1}]`;
        const network = interfaceNetwork(networks, item, address);
        const existingInterface = inventory.networkInterfaces.find((candidate) =>
          candidate.asset_id === assetId && candidate.name === name);
        const interfaceId = existingInterface?.id ?? uuidv4();
        const isPrimary = !markedPrimary && item === primaryParsed && index === 0;
        if (isPrimary) markedPrimary = true;
        change(changes, 'network_interface', interfaceId, {
          asset_id: assetId,
          name,
          ip_address: address ? hostAddress(address) : '',
          mac_address: item.macAddress ?? null,
          network_id: network?.id ?? null,
          is_primary: isPrimary,
        });
      }
    }
  }

  if (!networks.length) warnings.push('No networks could be derived. The device will be imported without a topology attachment.');
  if (!changes.length) throw new Error('The configuration did not produce any importable records');
  return {
    document: JSON.stringify({
      format: 'dfir-investigator-partial',
      format_version: 1,
      case_id: inventory.caseId,
      source: `${config.vendor} configuration import: ${config.hostname}`,
      changes,
    }, null, 2),
    warnings,
    changeCount: changes.length,
  };
}
