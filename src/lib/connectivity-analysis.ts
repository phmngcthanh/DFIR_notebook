import type {
  Asset,
  Firewall,
  FirewallInterface,
  FirewallNatRule,
  Network,
  NetworkConnection,
  NetworkInterface,
} from '@/types';
import {
  hostAddress,
  type ParsedAclRule,
  type ParsedDeviceConfig,
  type ParsedInterface,
  readStoredDeviceConfig,
} from '@/lib/network-config';

export const INTERNET_NODE_ID = '__internet__';

export type ConnectivityMode = 'physical' | 'logical';
export type ConnectivityDirection = 'outbound' | 'inbound';
export type PathCertainty = 'confirmed' | 'possible';

export interface ConnectivityPolicy {
  id: string;
  name: string;
  sourceNetworkId: string;
  targetKind: 'internet' | 'network';
  targetNetworkId?: string;
  direction: ConnectivityDirection | 'bidirectional';
  mode: ConnectivityMode;
  expectation: 'blocked' | 'allowed';
  enabled: boolean;
  description: string;
}

export interface ConnectivityPathStep {
  fromNetworkId: string;
  toNetworkId: string;
  via: string;
  evidence: string[];
  certainty: PathCertainty;
}

export interface ConnectivityPath {
  id: string;
  certainty: PathCertainty;
  networkIds: string[];
  steps: ConnectivityPathStep[];
}

export interface ConnectivityAnalysis {
  mode: ConnectivityMode;
  direction: ConnectivityDirection;
  sourceNetworkId: string;
  targetNetworkId: string;
  paths: ConnectivityPath[];
  truncated: boolean;
  warnings: string[];
}

export interface PolicyEvaluation {
  policy: ConnectivityPolicy;
  status: 'pass' | 'fail' | 'warning';
  summary: string;
  analyses: ConnectivityAnalysis[];
}

export interface ConnectivityInventory {
  networks: Network[];
  connections: NetworkConnection[];
  assets: Asset[];
  networkInterfaces: NetworkInterface[];
  firewalls: Firewall[];
  firewallInterfaces: FirewallInterface[];
  firewallNatRules: FirewallNatRule[];
}

interface Attachment {
  networkId: string;
  interfaceNames: string[];
  zones: string[];
  roles: string[];
  vlanIds: string[];
}

interface Device {
  id: string;
  name: string;
  kind: 'asset' | 'firewall';
  config: ParsedDeviceConfig;
  attachments: Attachment[];
  structuredNat: FirewallNatRule[];
}

interface GraphEdge extends ConnectivityPathStep {
  fromNetworkId: string;
  toNetworkId: string;
}

type MatchResult = 'match' | 'no-match' | 'unknown';
type RuleDecision = 'allow' | 'deny' | 'unknown' | 'none';
type NatDecision = 'yes' | 'no' | 'unknown';

interface Ipv4Range {
  start: number;
  end: number;
}

function ipv4Number(value: string): number | null {
  const octets = value.split('.').map(Number);
  if (octets.length !== 4 || octets.some((item) => !Number.isInteger(item) || item < 0 || item > 255)) return null;
  return (((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>> 0;
}

function ipv4Range(value: string): Ipv4Range | null {
  const [address, prefixText] = value.trim().split('/');
  const numeric = ipv4Number(address);
  const prefix = prefixText == null ? 32 : Number(prefixText);
  if (numeric == null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const start = (numeric & mask) >>> 0;
  const size = 2 ** (32 - prefix);
  return { start, end: start + size - 1 };
}

function cidrOverlaps(left: string, right: string): boolean | null {
  const leftRange = ipv4Range(left);
  const rightRange = ipv4Range(right);
  if (leftRange && rightRange) return leftRange.start <= rightRange.end && rightRange.start <= leftRange.end;
  if (left.includes(':') && right.includes(':')) {
    const leftAddress = hostAddress(left).toLowerCase();
    const rightAddress = hostAddress(right).toLowerCase();
    return leftAddress === rightAddress;
  }
  return null;
}

function isPrivateNetwork(network: Network): boolean {
  const range = ipv4Range(network.subnet);
  if (range) {
    const privateRanges = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '169.254.0.0/16']
      .map(ipv4Range)
      .filter((value): value is Ipv4Range => value != null);
    return privateRanges.some((item) => range.start >= item.start && range.end <= item.end);
  }
  return network.subnet.toLowerCase().startsWith('fc') || network.subnet.toLowerCase().startsWith('fd');
}

function networkIsWan(network: Network, attachment?: Attachment): boolean {
  if (network.network_type.toUpperCase() === 'WAN') return true;
  if (network.subnet === '0.0.0.0/0' || network.subnet === '::/0') return true;
  return Boolean(attachment?.roles.some((role) => role === 'wan')
    || attachment?.zones.some((zone) => /(wan|outside|untrust|external|internet)/i.test(zone)));
}

function findParsedInterface(config: ParsedDeviceConfig, storedName: string): ParsedInterface | undefined {
  const direct = config.interfaces.find((item) =>
    item.name === storedName
    || storedName.startsWith(`${item.name} [`)
    || item.name.endsWith(`.${storedName}`));
  if (direct) return direct;
  const syntheticVlan = storedName.match(/^VLAN\s+([^\s(]+)/i);
  const vlan = syntheticVlan ? config.vlans.find((item) => item.id === syntheticVlan[1]) : undefined;
  return vlan ? {
    name: storedName,
    addresses: vlan.subnet ? [vlan.subnet] : [],
    vlanId: vlan.id,
    zone: vlan.name,
    role: 'lan',
    enabled: true,
  } : undefined;
}

function groupAttachments(
  config: ParsedDeviceConfig,
  interfaces: Array<{ name: string; network_id?: string; vlan_id?: string }>,
): Attachment[] {
  const result = new Map<string, Attachment>();
  for (const item of interfaces) {
    if (!item.network_id) continue;
    const parsed = findParsedInterface(config, item.name);
    const attachment = result.get(item.network_id) ?? {
      networkId: item.network_id,
      interfaceNames: [],
      zones: [],
      roles: [],
      vlanIds: [],
    };
    attachment.interfaceNames.push(item.name);
    if (parsed?.zone) attachment.zones.push(parsed.zone);
    if (parsed?.role) attachment.roles.push(parsed.role);
    if (parsed?.vlanId) attachment.vlanIds.push(parsed.vlanId);
    if (item.vlan_id) attachment.vlanIds.push(item.vlan_id);
    result.set(item.network_id, attachment);
  }
  for (const item of result.values()) {
    item.interfaceNames = [...new Set(item.interfaceNames)];
    item.zones = [...new Set(item.zones)];
    item.roles = [...new Set(item.roles)];
    item.vlanIds = [...new Set(item.vlanIds)];
  }
  return [...result.values()];
}

function devices(inventory: ConnectivityInventory): Device[] {
  const result: Device[] = [];
  for (const asset of inventory.assets) {
    const config = readStoredDeviceConfig(asset.properties);
    if (!config || !['router', 'switch'].includes(asset.asset_type)) continue;
    result.push({
      id: asset.id,
      name: asset.name,
      kind: 'asset',
      config,
      attachments: groupAttachments(
        config,
        inventory.networkInterfaces.filter((item) => item.asset_id === asset.id),
      ),
      structuredNat: [],
    });
  }
  for (const firewall of inventory.firewalls) {
    const config = readStoredDeviceConfig(firewall.rules);
    if (!config) continue;
    result.push({
      id: firewall.id,
      name: firewall.name,
      kind: 'firewall',
      config,
      attachments: groupAttachments(
        config,
        inventory.firewallInterfaces.filter((item) => item.firewall_id === firewall.id),
      ),
      structuredNat: inventory.firewallNatRules.filter((item) => item.firewall_id === firewall.id && item.enabled),
    });
  }
  return result;
}

function commaValues(value: string | undefined): string[] {
  return (value ?? '').split(',').map((item) => item.trim()).filter(Boolean);
}

function matchesList(specification: string | undefined, values: string[]): MatchResult {
  const expected = commaValues(specification);
  if (!expected.length || expected.some((item) => ['any', 'all', 'any-ipv4', 'any-ipv6'].includes(item.toLowerCase()))) return 'match';
  if (!values.length) return 'unknown';
  return expected.some((item) => values.some((value) => item.toLowerCase() === value.toLowerCase())) ? 'match' : 'no-match';
}

function matchesEndpoint(specification: string | undefined, network: Network, attachment: Attachment): MatchResult {
  const values = commaValues(specification);
  if (!values.length || values.some((item) => ['any', 'all', 'any-ipv4', 'any-ipv6'].includes(item.toLowerCase()))) return 'match';
  let unknown = false;
  for (const value of values) {
    if (value.toLowerCase().startsWith('zone:')) {
      const zone = value.slice(5);
      if (attachment.zones.some((item) => item.toLowerCase() === zone.toLowerCase())) return 'match';
      continue;
    }
    const overlap = cidrOverlaps(value, network.subnet);
    if (overlap === true) return 'match';
    if (overlap == null) unknown = true;
  }
  return unknown ? 'unknown' : 'no-match';
}

function combineMatch(values: MatchResult[]): MatchResult {
  if (values.some((value) => value === 'no-match')) return 'no-match';
  if (values.some((value) => value === 'unknown')) return 'unknown';
  return 'match';
}

function ruleMatches(
  rule: ParsedAclRule,
  sourceNetwork: Network,
  targetNetwork: Network,
  source: Attachment,
  target: Attachment,
): MatchResult {
  const interfaceNames = rule.direction === 'inbound'
    ? source.interfaceNames
    : rule.direction === 'outbound'
      ? target.interfaceNames
      : [...source.interfaceNames, ...target.interfaceNames];
  return combineMatch([
    matchesEndpoint(rule.source, sourceNetwork, source),
    matchesEndpoint(rule.destination, targetNetwork, target),
    matchesList(rule.fromZone, source.zones),
    matchesList(rule.toZone, target.zones),
    rule.interface ? matchesList(rule.interface, interfaceNames) : 'match',
  ]);
}

function aclDecision(
  config: ParsedDeviceConfig,
  sourceNetwork: Network,
  targetNetwork: Network,
  source: Attachment,
  target: Attachment,
): { decision: RuleDecision; evidence?: string } {
  let unknownBeforeMatch = false;
  for (const rule of config.aclRules.filter((item) => item.enabled).sort((left, right) => left.sequence - right.sequence)) {
    const match = ruleMatches(rule, sourceNetwork, targetNetwork, source, target);
    if (match === 'no-match') continue;
    if (match === 'unknown') {
      unknownBeforeMatch = true;
      continue;
    }
    if (unknownBeforeMatch) return { decision: 'unknown', evidence: `Named-object ACL evaluation before ${rule.name} is incomplete` };
    return {
      decision: rule.action,
      evidence: `${rule.action === 'allow' ? 'Allowed' : 'Denied'} by ${rule.name} (#${rule.sequence})`,
    };
  }
  return config.aclRules.length
    ? { decision: unknownBeforeMatch ? 'unknown' : 'none', evidence: unknownBeforeMatch ? 'ACL contains unresolved named objects' : 'No matching allow rule' }
    : { decision: 'unknown', evidence: 'No ACL/security policy was parsed' };
}

function natEndpointMatches(value: string | undefined, network: Network, attachment?: Attachment): NatDecision {
  if (!value || ['any', 'interface-address', 'dynamic'].includes(value.toLowerCase()) || value.toLowerCase().startsWith('interface:')) return value ? 'yes' : 'unknown';
  if (value.toLowerCase().startsWith('zone:')) {
    const zone = value.slice(5);
    return attachment?.zones.some((item) => item.toLowerCase() === zone.toLowerCase()) ? 'yes' : attachment ? 'no' : 'unknown';
  }
  const result = cidrOverlaps(value, network.subnet);
  return result === true ? 'yes' : result === false ? 'no' : 'unknown';
}

function dnatDecision(device: Device, targetNetwork: Network): NatDecision {
  let unknown = false;
  for (const rule of device.config.natRules.filter((item) => item.enabled && item.natType !== 'snat')) {
    const decision = natEndpointMatches(rule.translatedDestination, targetNetwork);
    if (decision === 'yes') return 'yes';
    if (decision === 'unknown') unknown = true;
  }
  for (const rule of device.structuredNat.filter((item) => item.nat_type !== 'snat')) {
    const decision = natEndpointMatches(rule.translated_destination, targetNetwork);
    if (decision === 'yes') return 'yes';
    if (decision === 'unknown') unknown = true;
  }
  return unknown ? 'unknown' : 'no';
}

function snatDecision(device: Device, sourceNetwork: Network, sourceAttachment: Attachment): NatDecision {
  let unknown = false;
  for (const rule of device.config.natRules.filter((item) => item.enabled && item.natType === 'snat')) {
    const decision = natEndpointMatches(rule.source, sourceNetwork, sourceAttachment);
    if (decision === 'yes') return 'yes';
    if (decision === 'unknown') unknown = true;
  }
  for (const rule of device.structuredNat.filter((item) => item.nat_type === 'snat')) {
    const decision = natEndpointMatches(rule.source_cidr, sourceNetwork, sourceAttachment);
    if (decision === 'yes') return 'yes';
    if (decision === 'unknown') unknown = true;
  }
  return unknown ? 'unknown' : 'no';
}

function defaultRoutes(config: ParsedDeviceConfig) {
  return config.routes.filter((item) => item.active && ['0.0.0.0/0', '::/0', 'default'].includes(item.destination.toLowerCase()));
}

function attachmentForRoute(device: Device, routeInterface: string | undefined, nextHop: string | undefined, inventory: ConnectivityInventory): Attachment[] {
  if (routeInterface) {
    const exact = device.attachments.filter((item) =>
      item.interfaceNames.some((name) => name === routeInterface || name.startsWith(`${routeInterface} [`)));
    if (exact.length) return exact;
    const parsed = device.config.interfaces.find((item) => item.name === routeInterface);
    if (parsed) {
      const byZone = device.attachments.filter((item) =>
        item.zones.includes(parsed.zone ?? '') || item.vlanIds.includes(parsed.vlanId ?? ''));
      if (byZone.length) return byZone;
    }
  }
  if (nextHop) {
    const byGateway = device.attachments.filter((item) => {
      const network = inventory.networks.find((candidate) => candidate.id === item.networkId);
      return network ? cidrOverlaps(nextHop, network.subnet) === true : false;
    });
    if (byGateway.length) return byGateway;
  }
  const wan = device.attachments.filter((item) => {
    const network = inventory.networks.find((candidate) => candidate.id === item.networkId);
    return network ? networkIsWan(network, item) : false;
  });
  return wan.length ? wan : device.attachments;
}

function addEdge(edges: GraphEdge[], edge: GraphEdge): void {
  const key = `${edge.fromNetworkId}|${edge.toNetworkId}|${edge.via}|${edge.evidence.join('|')}`;
  if (!edges.some((item) => `${item.fromNetworkId}|${item.toNetworkId}|${item.via}|${item.evidence.join('|')}` === key)) edges.push(edge);
}

function addBoth(edges: GraphEdge[], left: string, right: string, via: string, evidence: string[], certainty: PathCertainty): void {
  addEdge(edges, { fromNetworkId: left, toNetworkId: right, via, evidence, certainty });
  addEdge(edges, { fromNetworkId: right, toNetworkId: left, via, evidence, certainty });
}

function physicalEdges(inventory: ConnectivityInventory): GraphEdge[] {
  const edges: GraphEdge[] = [];
  for (const connection of inventory.connections) {
    addBoth(
      edges,
      connection.source_network_id,
      connection.target_network_id,
      connection.device_name ?? 'Recorded network link',
      [`${connection.connection_type}: ${connection.description || 'manually asserted connection'}`],
      'confirmed',
    );
  }
  for (const device of devices(inventory)) {
    for (let left = 0; left < device.attachments.length; left += 1) {
      for (let right = left + 1; right < device.attachments.length; right += 1) {
        addBoth(
          edges,
          device.attachments[left].networkId,
          device.attachments[right].networkId,
          device.name,
          [`Interfaces ${device.attachments[left].interfaceNames.join(', ')} and ${device.attachments[right].interfaceNames.join(', ')}`],
          'confirmed',
        );
      }
    }
    const boundaryAttachments = new Map<string, PathCertainty>();
    for (const attachment of device.attachments) {
      const network = inventory.networks.find((item) => item.id === attachment.networkId);
      if (network && networkIsWan(network, attachment)) boundaryAttachments.set(attachment.networkId, 'confirmed');
    }
    for (const route of defaultRoutes(device.config)) {
      for (const attachment of attachmentForRoute(device, route.interface, route.nextHop, inventory)) {
        boundaryAttachments.set(attachment.networkId, route.interface || route.nextHop ? 'confirmed' : 'possible');
      }
    }
    for (const [networkId, certainty] of boundaryAttachments) {
      addBoth(edges, networkId, INTERNET_NODE_ID, device.name, ['WAN/default-route Internet boundary'], certainty);
    }
  }
  for (const network of inventory.networks.filter((item) => networkIsWan(item))) {
    if (!edges.some((edge) => edge.fromNetworkId === network.id && edge.toNetworkId === INTERNET_NODE_ID)) {
      addBoth(edges, network.id, INTERNET_NODE_ID, 'Declared WAN boundary', [`${network.name} is classified as WAN`], 'confirmed');
    }
  }
  return edges;
}

function logicalPair(
  edges: GraphEdge[],
  inventory: ConnectivityInventory,
  device: Device,
  source: Attachment,
  target: Attachment,
): void {
  const sourceNetwork = inventory.networks.find((item) => item.id === source.networkId);
  const targetNetwork = inventory.networks.find((item) => item.id === target.networkId);
  if (!sourceNetwork || !targetNetwork) return;

  if (device.config.deviceType === 'switch') {
    const sharedVlan = source.vlanIds.some((item) => target.vlanIds.includes(item));
    if (!sharedVlan && device.config.routes.length === 0) return;
  }

  const decision = aclDecision(device.config, sourceNetwork, targetNetwork, source, target);
  if (decision.decision === 'deny') return;
  if (device.kind === 'firewall' && decision.decision === 'none') return;

  const sourceWan = networkIsWan(sourceNetwork, source);
  const targetWan = networkIsWan(targetNetwork, target);
  const evidence = ['Both networks are directly attached', decision.evidence ?? 'Policy result unavailable'];
  let certainty: PathCertainty = decision.decision === 'allow' ? 'confirmed' : 'possible';

  if (sourceWan && !targetWan && isPrivateNetwork(targetNetwork)) {
    const nat = dnatDecision(device, targetNetwork);
    if (nat === 'no') return;
    evidence.push(nat === 'yes' ? 'Matching inbound destination NAT / VIP exists' : 'Inbound NAT contains unresolved objects');
    if (nat !== 'yes') certainty = 'possible';
  }
  if (!sourceWan && targetWan && isPrivateNetwork(sourceNetwork)) {
    const nat = snatDecision(device, sourceNetwork, source);
    evidence.push(nat === 'yes' ? 'Matching source NAT exists' : nat === 'no' ? 'No source NAT was recognized; upstream NAT may still exist' : 'Source NAT uses unresolved objects');
    if (nat !== 'yes') certainty = 'possible';
  }

  addEdge(edges, {
    fromNetworkId: source.networkId,
    toNetworkId: target.networkId,
    via: device.name,
    evidence,
    certainty,
  });
}

function logicalEdges(inventory: ConnectivityInventory): GraphEdge[] {
  const edges: GraphEdge[] = [];
  for (const connection of inventory.connections) {
    addBoth(
      edges,
      connection.source_network_id,
      connection.target_network_id,
      connection.device_name ?? 'Recorded logical link',
      [`Recorded ${connection.connection_type} connection; route/ACL details were not imported`],
      'possible',
    );
  }

  for (const device of devices(inventory)) {
    for (const source of device.attachments) {
      for (const target of device.attachments) {
        if (source.networkId !== target.networkId) logicalPair(edges, inventory, device, source, target);
      }
    }

    const routes = defaultRoutes(device.config);
    for (const route of routes) {
      const attachments = attachmentForRoute(device, route.interface, route.nextHop, inventory);
      for (const attachment of attachments) {
        addEdge(edges, {
          fromNetworkId: attachment.networkId,
          toNetworkId: INTERNET_NODE_ID,
          via: device.name,
          evidence: [`Active default route ${route.destination}${route.nextHop ? ` via ${route.nextHop}` : ''}`],
          certainty: route.interface || route.nextHop ? 'confirmed' : 'possible',
        });
        addEdge(edges, {
          fromNetworkId: INTERNET_NODE_ID,
          toNetworkId: attachment.networkId,
          via: device.name,
          evidence: ['External traffic can reach the configured WAN-side network; downstream policy/NAT is evaluated separately'],
          certainty: 'possible',
        });
      }
    }
    for (const attachment of device.attachments) {
      const network = inventory.networks.find((item) => item.id === attachment.networkId);
      if (network && networkIsWan(network, attachment)) {
        addEdge(edges, {
          fromNetworkId: attachment.networkId,
          toNetworkId: INTERNET_NODE_ID,
          via: device.name,
          evidence: ['Interface/zone is marked WAN; upstream route was not fully resolved'],
          certainty: 'possible',
        });
        addEdge(edges, {
          fromNetworkId: INTERNET_NODE_ID,
          toNetworkId: attachment.networkId,
          via: device.name,
          evidence: ['WAN-side network is a possible inbound boundary'],
          certainty: 'possible',
        });
      }
    }
  }
  for (const network of inventory.networks.filter((item) => networkIsWan(item))) {
    if (!edges.some((edge) => edge.fromNetworkId === network.id && edge.toNetworkId === INTERNET_NODE_ID)) {
      addBoth(edges, network.id, INTERNET_NODE_ID, 'Declared WAN boundary', [`${network.name} is classified as WAN`], 'possible');
    }
  }
  return edges;
}

function enumeratePaths(edges: GraphEdge[], start: string, target: string, maximum = 50): { paths: ConnectivityPath[]; truncated: boolean } {
  const adjacency = new Map<string, GraphEdge[]>();
  for (const edge of edges) {
    const values = adjacency.get(edge.fromNetworkId) ?? [];
    values.push(edge);
    adjacency.set(edge.fromNetworkId, values);
  }
  const paths: ConnectivityPath[] = [];
  let truncated = false;
  const maximumDepth = Math.min(16, new Set(edges.flatMap((edge) => [edge.fromNetworkId, edge.toNetworkId])).size + 1);
  const visit = (node: string, seen: Set<string>, steps: GraphEdge[]) => {
    if (paths.length >= maximum) {
      truncated = true;
      return;
    }
    if (node === target) {
      const id = steps.map((step) => `${step.fromNetworkId}:${step.toNetworkId}:${step.via}`).join('|');
      const candidate: ConnectivityPath = {
        id,
        certainty: steps.every((step) => step.certainty === 'confirmed') ? 'confirmed' : 'possible',
        networkIds: [start, ...steps.map((step) => step.toNetworkId)],
        steps,
      };
      const existingIndex = paths.findIndex((item) => item.id === id);
      if (existingIndex < 0) paths.push(candidate);
      else if (paths[existingIndex].certainty === 'possible' && candidate.certainty === 'confirmed') paths[existingIndex] = candidate;
      return;
    }
    if (steps.length >= maximumDepth) return;
    for (const edge of adjacency.get(node) ?? []) {
      if (seen.has(edge.toNetworkId)) continue;
      seen.add(edge.toNetworkId);
      visit(edge.toNetworkId, seen, [...steps, edge]);
      seen.delete(edge.toNetworkId);
    }
  };
  visit(start, new Set([start]), []);
  return { paths, truncated };
}

export function analyzeConnectivity(
  inventory: ConnectivityInventory,
  sourceNetworkId: string,
  targetNetworkId: string,
  direction: ConnectivityDirection,
  mode: ConnectivityMode,
): ConnectivityAnalysis {
  const start = direction === 'outbound' ? sourceNetworkId : targetNetworkId;
  const target = direction === 'outbound' ? targetNetworkId : sourceNetworkId;
  const edges = mode === 'physical' ? physicalEdges(inventory) : logicalEdges(inventory);
  const { paths, truncated } = enumeratePaths(edges, start, target);
  const warnings: string[] = [];
  if (mode === 'logical' && devices(inventory).length === 0) warnings.push('No normalized device configurations are available; only manually asserted network connections were evaluated.');
  if (truncated) warnings.push('More than 50 simple paths exist. The result is truncated; narrow the scope or inspect the configuration manually.');
  if (paths.some((path) => path.certainty === 'possible')) warnings.push('Possible paths contain unresolved named objects, incomplete ACL/NAT evidence, or manually asserted links.');
  return {
    mode,
    direction,
    sourceNetworkId,
    targetNetworkId,
    paths,
    truncated,
    warnings,
  };
}

export function evaluatePolicy(inventory: ConnectivityInventory, policy: ConnectivityPolicy): PolicyEvaluation {
  const target = policy.targetKind === 'internet' ? INTERNET_NODE_ID : policy.targetNetworkId ?? '';
  const directions: ConnectivityDirection[] = policy.direction === 'bidirectional'
    ? ['outbound', 'inbound']
    : [policy.direction];
  const analyses = directions.map((direction) =>
    analyzeConnectivity(inventory, policy.sourceNetworkId, target, direction, policy.mode));
  const paths = analyses.flatMap((item) => item.paths);
  const hasConfirmed = paths.some((path) => path.certainty === 'confirmed');
  const hasPossible = paths.length > 0;
  if (policy.expectation === 'blocked') {
    if (hasConfirmed) return { policy, status: 'fail', summary: 'A confirmed path violates the required isolation.', analyses };
    if (hasPossible) return { policy, status: 'warning', summary: 'A possible path needs review before isolation can be accepted.', analyses };
    return { policy, status: 'pass', summary: 'No path was found in the imported physical/logical model.', analyses };
  }
  if (hasConfirmed) return { policy, status: 'pass', summary: 'At least one confirmed allowed path was found.', analyses };
  if (hasPossible) return { policy, status: 'warning', summary: 'Only possible paths were found; policy/NAT evidence is incomplete.', analyses };
  return { policy, status: 'fail', summary: 'No path was found for required connectivity.', analyses };
}

export function parseConnectivityPolicies(metadata: string | null | undefined): ConnectivityPolicy[] {
  if (!metadata?.trim()) return [];
  try {
    const root = JSON.parse(metadata) as { connectivity_policies?: unknown };
    if (!Array.isArray(root.connectivity_policies)) return [];
    return root.connectivity_policies.filter((item): item is ConnectivityPolicy => {
      if (!item || typeof item !== 'object') return false;
      const value = item as Partial<ConnectivityPolicy>;
      return typeof value.id === 'string'
        && typeof value.name === 'string'
        && typeof value.sourceNetworkId === 'string'
        && ['internet', 'network'].includes(value.targetKind ?? '')
        && ['outbound', 'inbound', 'bidirectional'].includes(value.direction ?? '')
        && ['physical', 'logical'].includes(value.mode ?? '')
        && ['blocked', 'allowed'].includes(value.expectation ?? '');
    });
  } catch {
    return [];
  }
}

export function metadataWithConnectivityPolicies(
  metadata: string | null | undefined,
  policies: ConnectivityPolicy[],
): string {
  let root: Record<string, unknown> = {};
  if (metadata?.trim()) {
    try {
      const value = JSON.parse(metadata) as unknown;
      if (value && typeof value === 'object' && !Array.isArray(value)) root = value as Record<string, unknown>;
      else root.legacy_metadata = metadata;
    } catch {
      root.legacy_metadata = metadata;
    }
  }
  root.connectivity_policies = policies;
  return JSON.stringify(root);
}
