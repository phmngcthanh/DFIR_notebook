export type ConfigProfile =
  | 'palo_alto_firewall'
  | 'opnsense_firewall'
  | 'juniper_firewall'
  | 'openwrt_network'
  | 'cisco_network'
  | 'palo_alto_network';

export interface ConfigProfileOption {
  value: ConfigProfile;
  label: string;
  vendor: string;
  expectedFormat: string;
}

export const CONFIG_PROFILES: ConfigProfileOption[] = [
  { value: 'palo_alto_firewall', label: 'Palo Alto firewall', vendor: 'Palo Alto', expectedFormat: 'PAN-OS set commands or XML' },
  { value: 'opnsense_firewall', label: 'OPNsense firewall', vendor: 'OPNsense', expectedFormat: 'config.xml backup' },
  { value: 'juniper_firewall', label: 'Juniper firewall', vendor: 'Juniper', expectedFormat: 'Junos “display set” configuration' },
  { value: 'openwrt_network', label: 'OpenWrt router / switch', vendor: 'OpenWrt', expectedFormat: 'UCI configuration export' },
  { value: 'cisco_network', label: 'Cisco router / switch', vendor: 'Cisco', expectedFormat: 'IOS / IOS-XE running configuration' },
  { value: 'palo_alto_network', label: 'Palo Alto router / switch', vendor: 'Palo Alto', expectedFormat: 'PAN-OS set commands or XML' },
];

export type DeviceType = 'firewall' | 'router' | 'switch';
export type InterfaceRole = 'wan' | 'lan' | 'dmz' | 'management' | 'ha' | 'vpn' | 'other';
export type AclAction = 'allow' | 'deny';
export type NatType = 'vip' | 'dnat' | 'snat' | 'port_mapping';

export interface ParsedInterface {
  name: string;
  addresses: string[];
  macAddress?: string;
  vlanId?: string;
  zone?: string;
  role: InterfaceRole;
  description?: string;
  enabled: boolean;
}

export interface ParsedVlan {
  id: string;
  name: string;
  subnet?: string;
  interfaces: string[];
}

export interface ParsedRoute {
  name: string;
  destination: string;
  nextHop?: string;
  interface?: string;
  metric?: number;
  protocol: string;
  active: boolean;
  description?: string;
}

export interface ParsedAclRule {
  name: string;
  sequence: number;
  action: AclAction;
  protocol: string;
  source: string;
  destination: string;
  sourcePort?: string;
  destinationPort?: string;
  fromZone?: string;
  toZone?: string;
  interface?: string;
  direction?: 'inbound' | 'outbound';
  enabled: boolean;
  description?: string;
}

export interface ParsedNatRule {
  name: string;
  natType: NatType;
  protocol: string;
  source?: string;
  originalDestination?: string;
  originalPort?: string;
  translatedSource?: string;
  translatedDestination?: string;
  translatedPort?: string;
  inboundInterface?: string;
  outboundInterface?: string;
  enabled: boolean;
  description?: string;
}

export interface ParsedDeviceConfig {
  schema: 'dfir-network-config-v1';
  profile: ConfigProfile;
  vendor: string;
  deviceType: DeviceType;
  hostname: string;
  model?: string;
  sourceFile?: string;
  rawConfig: string;
  interfaces: ParsedInterface[];
  vlans: ParsedVlan[];
  routes: ParsedRoute[];
  aclRules: ParsedAclRule[];
  natRules: ParsedNatRule[];
  warnings: string[];
}

interface MutableConfig extends ParsedDeviceConfig {
  interfaces: ParsedInterface[];
  vlans: ParsedVlan[];
  routes: ParsedRoute[];
  aclRules: ParsedAclRule[];
  natRules: ParsedNatRule[];
  warnings: string[];
}

interface UciSection {
  type: string;
  name: string;
  options: Record<string, string>;
  lists: Record<string, string[]>;
}

function emptyConfig(
  profile: ConfigProfile,
  rawConfig: string,
  hostname: string,
  sourceFile?: string,
): MutableConfig {
  const option = CONFIG_PROFILES.find((item) => item.value === profile);
  if (!option) throw new Error(`Unsupported configuration profile: ${profile}`);
  return {
    schema: 'dfir-network-config-v1',
    profile,
    vendor: option.vendor,
    deviceType: profile.endsWith('_firewall') ? 'firewall' : 'router',
    hostname,
    sourceFile,
    rawConfig,
    interfaces: [],
    vlans: [],
    routes: [],
    aclRules: [],
    natRules: [],
    warnings: [],
  };
}

function stripQuotes(value: string): string {
  const trimmed = value.trim();
  if (
    trimmed.length >= 2
    && ((trimmed.startsWith("'") && trimmed.endsWith("'"))
      || (trimmed.startsWith('"') && trimmed.endsWith('"')))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function words(line: string): string[] {
  const result: string[] = [];
  let current = '';
  let quote = '';
  let escaped = false;
  const push = () => {
    if (current) result.push(current);
    current = '';
  };
  for (const character of line.trim()) {
    if (escaped) {
      current += character;
      escaped = false;
    } else if (character === '\\') {
      escaped = true;
    } else if (quote) {
      if (character === quote) quote = '';
      else current += character;
    } else if (character === '"' || character === "'") {
      quote = character;
    } else if (/\s/.test(character)) {
      push();
    } else if (character === '[' || character === ']') {
      push();
    } else {
      current += character;
    }
  }
  push();
  return result;
}

function unique(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function optional(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function normalizeProtocol(value: string | undefined): string {
  const protocol = (value ?? 'any').toLowerCase();
  if (['ip', 'all', 'any', 'any-ipv4', 'any-ipv6'].includes(protocol)) return 'any';
  if (['tcp', 'udp', 'icmp', 'icmp6', 'sctp'].includes(protocol)) return protocol === 'icmp6' ? 'icmp' : protocol;
  return protocol;
}

function normalizeAction(value: string | undefined): AclAction {
  return ['allow', 'accept', 'pass', 'permit'].includes((value ?? '').toLowerCase()) ? 'allow' : 'deny';
}

function roleFromName(name: string): InterfaceRole {
  const value = name.toLowerCase();
  if (/(^|[-_.])(wan|outside|untrust|external|internet)([-_.]|$)/.test(value)) return 'wan';
  if (/(^|[-_.])(dmz|dms)([-_.]|$)/.test(value)) return 'dmz';
  if (/(^|[-_.])(mgmt|management)([-_.]|$)/.test(value)) return 'management';
  if (/(^|[-_.])(vpn|tunnel)([-_.]|$)/.test(value)) return 'vpn';
  if (/(^|[-_.])(ha|sync)([-_.]|$)/.test(value)) return 'ha';
  if (/(^|[-_.])(lan|inside|trust|internal)([-_.]|$)/.test(value)) return 'lan';
  return 'other';
}

function ensureInterface(config: MutableConfig, name: string): ParsedInterface {
  const cleanName = stripQuotes(name);
  let item = config.interfaces.find((candidate) => candidate.name === cleanName);
  if (!item) {
    item = { name: cleanName, addresses: [], role: roleFromName(cleanName), enabled: true };
    config.interfaces.push(item);
  }
  return item;
}

function ensureVlan(config: MutableConfig, id: string, name?: string): ParsedVlan {
  const cleanId = stripQuotes(id);
  let vlan = config.vlans.find((candidate) => candidate.id === cleanId);
  if (!vlan) {
    vlan = { id: cleanId, name: optional(name) ?? `VLAN ${cleanId}`, interfaces: [] };
    config.vlans.push(vlan);
  } else if (name && /^VLAN \d+$/i.test(vlan.name)) {
    vlan.name = name;
  }
  return vlan;
}

function maskToPrefix(mask: string): number | null {
  const octets = mask.split('.').map(Number);
  if (octets.length !== 4 || octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) return null;
  const bits = octets.map((value) => value.toString(2).padStart(8, '0')).join('');
  if (!/^1*0*$/.test(bits)) return null;
  return bits.indexOf('0') === -1 ? 32 : bits.indexOf('0');
}

function wildcardToPrefix(mask: string): number | null {
  const octets = mask.split('.').map(Number);
  if (octets.length !== 4 || octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) return null;
  return maskToPrefix(octets.map((value) => 255 - value).join('.'));
}

function ipWithMask(address: string, mask: string): string {
  if (address.includes('/')) return address;
  const prefix = maskToPrefix(mask);
  return prefix == null ? address : `${address}/${prefix}`;
}

function aclAddress(tokens: string[], start: number): { value: string; next: number } {
  const value = tokens[start]?.toLowerCase();
  if (!value) return { value: 'any', next: start };
  if (value === 'any' || value === 'any4' || value === 'any6') return { value: 'any', next: start + 1 };
  if (value === 'host' && tokens[start + 1]) return { value: tokens[start + 1], next: start + 2 };
  const wildcard = tokens[start + 1];
  const prefix = wildcard ? wildcardToPrefix(wildcard) : null;
  if (prefix != null) return { value: `${tokens[start]}/${prefix}`, next: start + 2 };
  return { value: tokens[start], next: start + 1 };
}

function parseCiscoAclTokens(name: string, sequence: number, input: string[]): ParsedAclRule | null {
  const tokens = [...input];
  const first = tokens[0]?.toLowerCase();
  if (!first) return null;
  const actionIndex = ['permit', 'deny'].includes(first) ? 0 : ['permit', 'deny'].includes(tokens[1]?.toLowerCase()) ? 1 : -1;
  if (actionIndex < 0) return null;
  const parsedSequence = actionIndex === 1 ? Number(tokens[0]) : sequence;
  const action = normalizeAction(tokens[actionIndex]);
  const firstOperand = tokens[actionIndex + 1]?.toLowerCase() ?? '';
  const standardRule = firstOperand === 'any'
    || firstOperand === 'host'
    || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(firstOperand)
    || firstOperand.includes(':');
  if (standardRule) {
    const source = aclAddress(tokens, actionIndex + 1);
    return {
      name,
      sequence: Number.isFinite(parsedSequence) ? parsedSequence : sequence,
      action,
      protocol: 'any',
      source: source.value,
      destination: 'any',
      enabled: true,
    };
  }
  const protocol = normalizeProtocol(firstOperand);
  let cursor = actionIndex + 2;
  const source = aclAddress(tokens, cursor);
  cursor = source.next;
  let sourcePort: string | undefined;
  if (['eq', 'range', 'lt', 'gt'].includes(tokens[cursor]?.toLowerCase())) {
    const operator = tokens[cursor++].toLowerCase();
    sourcePort = operator === 'range' ? `${tokens[cursor]}-${tokens[cursor + 1]}` : tokens[cursor];
    cursor += operator === 'range' ? 2 : 1;
  }
  const destination = aclAddress(tokens, cursor);
  cursor = destination.next;
  let destinationPort: string | undefined;
  if (['eq', 'range', 'lt', 'gt'].includes(tokens[cursor]?.toLowerCase())) {
    const operator = tokens[cursor++].toLowerCase();
    destinationPort = operator === 'range' ? `${tokens[cursor]}-${tokens[cursor + 1]}` : tokens[cursor];
  }
  return {
    name,
    sequence: Number.isFinite(parsedSequence) ? parsedSequence : sequence,
    action,
    protocol,
    source: source.value,
    destination: destination.value,
    sourcePort,
    destinationPort,
    enabled: true,
  };
}

function parseCisco(config: MutableConfig): void {
  let currentInterface: ParsedInterface | null = null;
  let currentVlan: ParsedVlan | null = null;
  let currentAcl: string | null = null;
  let aclSequence = 10;
  let sawIpRouting = false;
  let sawRoutedPhysicalInterface = false;
  const interfaceAclBindings = new Map<string, Array<{ name: string; direction: 'inbound' | 'outbound' }>>();

  for (const rawLine of config.rawConfig.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('!')) {
      if (line.startsWith('!')) {
        currentInterface = null;
        currentVlan = null;
        currentAcl = null;
      }
      continue;
    }
    const tokens = words(line);
    const lower = tokens.map((token) => token.toLowerCase());
    if (lower[0] === 'hostname' && tokens[1]) {
      config.hostname = tokens.slice(1).join(' ');
      continue;
    }
    if (lower[0] === 'ip' && lower[1] === 'routing') {
      sawIpRouting = true;
      continue;
    }
    if (lower[0] === 'interface' && tokens[1]) {
      currentInterface = ensureInterface(config, tokens.slice(1).join(' '));
      currentVlan = null;
      currentAcl = null;
      const svi = currentInterface.name.match(/^vlan(\d+)$/i);
      if (svi) {
        currentInterface.vlanId = svi[1];
        ensureVlan(config, svi[1]).interfaces.push(currentInterface.name);
      }
      continue;
    }
    if (lower[0] === 'vlan' && tokens[1]) {
      currentVlan = ensureVlan(config, tokens[1]);
      currentInterface = null;
      currentAcl = null;
      continue;
    }
    if (lower[0] === 'ip' && lower[1] === 'access-list' && tokens[3]) {
      currentAcl = tokens.slice(3).join(' ');
      currentInterface = null;
      currentVlan = null;
      aclSequence = 10;
      continue;
    }
    if (lower[0] === 'access-list' && tokens[1]) {
      const rule = parseCiscoAclTokens(tokens[1], aclSequence, tokens.slice(2));
      if (rule) config.aclRules.push(rule);
      aclSequence += 10;
      continue;
    }
    if (lower[0] === 'ip' && lower[1] === 'route' && tokens[2] && tokens[3]) {
      const prefix = maskToPrefix(tokens[3]);
      const looksLikeAddress = (value: string | undefined) => Boolean(value && (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value) || value.includes(':')));
      const hasExplicitInterface = Boolean(tokens[4] && !looksLikeAddress(tokens[4]));
      const nextHop = hasExplicitInterface && looksLikeAddress(tokens[5]) ? tokens[5] : !hasExplicitInterface ? tokens[4] : undefined;
      const metricToken = hasExplicitInterface ? tokens[6] : tokens[5];
      const routeInterface = hasExplicitInterface ? tokens[4] : undefined;
      config.routes.push({
        name: `static-${config.routes.length + 1}`,
        destination: prefix == null ? tokens[2] : `${tokens[2]}/${prefix}`,
        nextHop,
        interface: routeInterface,
        metric: Number.isFinite(Number(metricToken)) ? Number(metricToken) : undefined,
        protocol: 'static',
        active: routeInterface?.toLowerCase() !== 'null0',
      });
      continue;
    }
    if (currentVlan && lower[0] === 'name') {
      currentVlan.name = tokens.slice(1).join(' ');
      continue;
    }
    if (currentAcl) {
      const rule = parseCiscoAclTokens(currentAcl, aclSequence, tokens);
      if (rule) {
        config.aclRules.push(rule);
        aclSequence += 10;
      }
      continue;
    }
    if (!currentInterface) continue;
    if (lower[0] === 'description') currentInterface.description = tokens.slice(1).join(' ');
    if (lower[0] === 'shutdown') currentInterface.enabled = false;
    if (lower[0] === 'no' && lower[1] === 'shutdown') currentInterface.enabled = true;
    if (lower[0] === 'ip' && lower[1] === 'address' && tokens[2] && tokens[3] && lower[2] !== 'dhcp') {
      currentInterface.addresses.push(ipWithMask(tokens[2], tokens[3]));
      if (!/^vlan\d+$/i.test(currentInterface.name)) sawRoutedPhysicalInterface = true;
    }
    if (lower[0] === 'ipv6' && lower[1] === 'address' && tokens[2]) currentInterface.addresses.push(tokens[2]);
    if (lower[0] === 'switchport' && lower[1] === 'access' && lower[2] === 'vlan' && tokens[3]) {
      currentInterface.vlanId = tokens[3];
      ensureVlan(config, tokens[3]).interfaces.push(currentInterface.name);
    }
    if (lower[0] === 'switchport' && lower[1] === 'trunk' && lower.includes('vlan')) {
      const value = tokens[lower.indexOf('vlan') + 1] ?? '';
      for (const vlanId of value.split(',').filter((item) => /^\d+$/.test(item))) {
        ensureVlan(config, vlanId).interfaces.push(currentInterface.name);
      }
    }
    if (lower[0] === 'ip' && lower[1] === 'access-group' && tokens[2] && tokens[3]) {
      const direction = lower[3] === 'out' ? 'outbound' : 'inbound';
      const bindings = interfaceAclBindings.get(currentInterface.name) ?? [];
      bindings.push({ name: tokens[2], direction });
      interfaceAclBindings.set(currentInterface.name, bindings);
    }
  }

  for (const [interfaceName, bindings] of interfaceAclBindings) {
    for (const binding of bindings) {
      for (const rule of config.aclRules.filter((item) => item.name === binding.name)) {
        rule.interface = interfaceName;
        rule.direction = binding.direction;
      }
    }
  }
  config.deviceType = config.routes.length > 0 || sawIpRouting || sawRoutedPhysicalInterface
    ? 'router'
    : 'switch';
}

function parseUciSections(text: string): UciSection[] {
  const result: UciSection[] = [];
  let current: UciSection | null = null;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const tokens = words(line);
    if (tokens[0] === 'config' && tokens[1]) {
      current = { type: tokens[1], name: tokens[2] ?? `${tokens[1]}-${result.length + 1}`, options: {}, lists: {} };
      result.push(current);
    } else if (current && tokens[0] === 'option' && tokens[1]) {
      current.options[tokens[1]] = tokens.slice(2).join(' ');
    } else if (current && tokens[0] === 'list' && tokens[1]) {
      const list = current.lists[tokens[1]] ?? [];
      list.push(tokens.slice(2).join(' '));
      current.lists[tokens[1]] = list;
    }
  }
  return result;
}

function parseOpenWrt(config: MutableConfig): void {
  const sections = parseUciSections(config.rawConfig);
  const system = sections.find((section) => section.type === 'system');
  if (system?.options.hostname) config.hostname = system.options.hostname;
  const devices = new Map(sections.filter((section) => section.type === 'device').map((section) => [section.options.name ?? section.name, section]));

  for (const section of sections.filter((item) => item.type === 'interface')) {
    const deviceName = section.options.device ?? section.options.ifname ?? section.name;
    const item = ensureInterface(config, deviceName);
    item.zone = section.name;
    item.role = roleFromName(section.name);
    const addressValues = [...(section.lists.ipaddr ?? [])];
    if (section.options.ipaddr) {
      const mask = section.options.netmask;
      addressValues.push(mask ? ipWithMask(section.options.ipaddr, mask) : section.options.ipaddr);
    }
    if (section.options.ip6addr) addressValues.push(section.options.ip6addr);
    item.addresses.push(...addressValues.filter((value) => !['dhcp', 'auto'].includes(value.toLowerCase())));
    item.macAddress = optional(section.options.macaddr ?? devices.get(deviceName)?.options.macaddr);
    item.enabled = section.options.auto !== '0' && section.options.disabled !== '1';
    item.description = section.name !== deviceName ? `OpenWrt logical interface ${section.name}` : undefined;
  }

  for (const section of sections.filter((item) => item.type === 'bridge-vlan')) {
    const vlanId = section.options.vlan;
    if (!vlanId) continue;
    const vlan = ensureVlan(config, vlanId, section.options.description);
    vlan.interfaces.push(...(section.lists.ports ?? []).map((port) => port.replace(/:[ut*]+$/i, '')));
    const device = section.options.device;
    if (device) vlan.interfaces.push(device);
  }

  for (const section of sections.filter((item) => item.type === 'route' || item.type === 'route6')) {
    const destination = section.options.target ?? section.options.destination;
    if (!destination) continue;
    config.routes.push({
      name: section.name,
      destination: destination.includes('/') ? destination : ipWithMask(destination, section.options.netmask ?? '255.255.255.255'),
      nextHop: optional(section.options.gateway),
      interface: optional(section.options.interface),
      metric: Number.isFinite(Number(section.options.metric)) ? Number(section.options.metric) : undefined,
      protocol: 'static',
      active: section.options.disabled !== '1',
    });
  }

  let sequence = 10;
  for (const section of sections.filter((item) => item.type === 'rule' || item.type === 'forwarding')) {
    const source = section.options.src_ip ?? (section.options.src ? `zone:${section.options.src}` : 'any');
    const destination = section.options.dest_ip ?? (section.options.dest ? `zone:${section.options.dest}` : 'any');
    config.aclRules.push({
      name: section.options.name ?? section.name,
      sequence,
      action: normalizeAction(section.options.target ?? (section.type === 'forwarding' ? 'ACCEPT' : 'DROP')),
      protocol: normalizeProtocol(section.options.proto),
      source,
      destination,
      sourcePort: optional(section.options.src_port),
      destinationPort: optional(section.options.dest_port),
      fromZone: optional(section.options.src),
      toZone: optional(section.options.dest),
      enabled: section.options.enabled !== '0',
      description: optional(section.options.description),
    });
    sequence += 10;
  }

  for (const section of sections.filter((item) => item.type === 'redirect' || item.type === 'nat')) {
    const translatedDestination = section.options.dest_ip;
    const translatedSource = section.options.src_dip;
    config.natRules.push({
      name: section.options.name ?? section.name,
      natType: translatedDestination ? (section.options.src_dport || section.options.dest_port ? 'port_mapping' : 'dnat') : 'snat',
      protocol: normalizeProtocol(section.options.proto),
      source: optional(section.options.src_ip),
      originalDestination: optional(section.options.dest_ip === translatedDestination ? undefined : section.options.dest_ip),
      originalPort: optional(section.options.src_dport),
      translatedSource: optional(translatedSource ?? (section.options.target === 'MASQUERADE' ? 'interface-address' : undefined)),
      translatedDestination: optional(translatedDestination),
      translatedPort: optional(section.options.dest_port),
      inboundInterface: optional(section.options.src),
      outboundInterface: optional(section.options.dest),
      enabled: section.options.enabled !== '0',
    });
  }
  config.deviceType = config.routes.length > 0 || sections.some((item) => item.type === 'forwarding') ? 'router' : 'switch';
}

function parseXml(text: string): Document {
  const document = new DOMParser().parseFromString(text, 'application/xml');
  if (document.getElementsByTagName('parsererror').length > 0) throw new Error('The selected XML configuration is malformed');
  return document;
}

function child(parent: Element | Document, tagName: string): Element | null {
  return Array.from(parent.children).find((item) => item.tagName === tagName) ?? null;
}

function childText(parent: Element | Document | null, tagName: string): string | undefined {
  if (!parent) return undefined;
  return optional(child(parent, tagName)?.textContent ?? undefined);
}

function descendant(parent: Element | Document | null, tagName: string): Element | null {
  if (!parent) return null;
  return parent.getElementsByTagName(tagName)[0] ?? null;
}

function descendantText(parent: Element | Document | null, tagName: string): string | undefined {
  return optional(descendant(parent, tagName)?.textContent ?? undefined);
}

function entryName(entry: Element): string {
  return entry.getAttribute('name') ?? childText(entry, 'name') ?? '';
}

function members(parent: Element | null, tagName: string): string[] {
  const container = parent ? descendant(parent, tagName) : null;
  return container ? Array.from(container.getElementsByTagName('member')).map((item) => item.textContent?.trim() ?? '').filter(Boolean) : [];
}

function xmlEndpoint(parent: Element | null): { value: string; port?: string } {
  if (!parent) return { value: 'any' };
  if (child(parent, 'any')) return { value: 'any', port: childText(parent, 'port') };
  const network = childText(parent, 'network');
  const address = childText(parent, 'address');
  return {
    value: network ? (network.includes('/') ? network : `zone:${network}`) : address ?? 'any',
    port: childText(parent, 'port'),
  };
}

function parseOpnsense(config: MutableConfig): void {
  const document = parseXml(config.rawConfig);
  config.hostname = descendantText(descendant(document, 'system'), 'hostname') ?? config.hostname;
  const gateways = new Map<string, string>();
  const gatewayContainer = descendant(document, 'gateways');
  if (gatewayContainer) {
    for (const item of Array.from(gatewayContainer.getElementsByTagName('gateway_item'))) {
      const name = childText(item, 'name');
      const gateway = childText(item, 'gateway');
      if (name && gateway) gateways.set(name, gateway);
    }
  }

  const interfaces = descendant(document, 'interfaces');
  if (interfaces) {
    for (const node of Array.from(interfaces.children)) {
      if (['groups', 'wireless'].includes(node.tagName)) continue;
      const interfaceName = childText(node, 'if') ?? node.tagName;
      const item = ensureInterface(config, interfaceName);
      item.zone = node.tagName;
      item.role = roleFromName(node.tagName);
      item.description = childText(node, 'descr');
      item.macAddress = childText(node, 'spoofmac');
      item.enabled = child(node, 'enable') != null || childText(node, 'enable') !== '0';
      const address = childText(node, 'ipaddr');
      const prefix = childText(node, 'subnet');
      if (address && !['dhcp', 'pppoe', 'none'].includes(address.toLowerCase())) item.addresses.push(prefix ? `${address}/${prefix}` : address);
      const ipv6 = childText(node, 'ipaddrv6');
      const prefix6 = childText(node, 'subnetv6');
      if (ipv6 && !['dhcp6', 'track6', 'none'].includes(ipv6.toLowerCase())) item.addresses.push(prefix6 ? `${ipv6}/${prefix6}` : ipv6);
    }
  }

  const vlans = descendant(document, 'vlans');
  if (vlans) {
    for (const node of Array.from(vlans.getElementsByTagName('vlan'))) {
      const id = childText(node, 'tag');
      if (!id) continue;
      const vlan = ensureVlan(config, id, childText(node, 'descr'));
      const interfaceName = childText(node, 'if');
      if (interfaceName) vlan.interfaces.push(interfaceName);
    }
  }

  const staticRoutes = descendant(document, 'staticroutes');
  if (staticRoutes) {
    for (const [index, node] of Array.from(staticRoutes.getElementsByTagName('route')).entries()) {
      const destination = childText(node, 'network');
      if (!destination) continue;
      const gatewayName = childText(node, 'gateway');
      config.routes.push({
        name: childText(node, 'descr') ?? `static-${index + 1}`,
        destination,
        nextHop: gatewayName ? gateways.get(gatewayName) ?? gatewayName : undefined,
        protocol: 'static',
        active: child(node, 'disabled') == null,
      });
    }
  }

  const filter = descendant(document, 'filter');
  let sequence = 10;
  if (filter) {
    for (const node of Array.from(filter.children).filter((item) => item.tagName === 'rule')) {
      const source = xmlEndpoint(child(node, 'source'));
      const destination = xmlEndpoint(child(node, 'destination'));
      const interfaceName = childText(node, 'interface');
      config.aclRules.push({
        name: childText(node, 'descr') ?? `rule-${sequence}`,
        sequence,
        action: normalizeAction(childText(node, 'type') ?? 'block'),
        protocol: normalizeProtocol(childText(node, 'protocol') ?? childText(node, 'ipprotocol')),
        source: source.value,
        destination: destination.value,
        sourcePort: source.port,
        destinationPort: destination.port,
        fromZone: interfaceName,
        interface: interfaceName,
        direction: childText(node, 'direction') === 'out' ? 'outbound' : 'inbound',
        enabled: child(node, 'disabled') == null,
      });
      sequence += 10;
    }
  }

  const nat = descendant(document, 'nat');
  if (nat) {
    for (const [index, node] of Array.from(nat.getElementsByTagName('rule')).entries()) {
      const target = childText(node, 'target');
      const source = xmlEndpoint(child(node, 'source'));
      const destination = xmlEndpoint(child(node, 'destination'));
      const outbound = node.parentElement?.tagName === 'outbound';
      if (!target && !outbound) continue;
      config.natRules.push({
        name: childText(node, 'descr') ?? `nat-${index + 1}`,
        natType: outbound ? 'snat' : destination.port || childText(node, 'local-port') ? 'port_mapping' : 'dnat',
        protocol: normalizeProtocol(childText(node, 'protocol')),
        source: source.value === 'any' ? undefined : source.value,
        originalDestination: destination.value === 'any' ? undefined : destination.value,
        originalPort: destination.port,
        translatedSource: outbound ? target ?? 'interface-address' : undefined,
        translatedDestination: outbound ? undefined : target,
        translatedPort: childText(node, 'local-port'),
        inboundInterface: childText(node, 'interface'),
        enabled: child(node, 'disabled') == null,
      });
    }
  }
  config.deviceType = 'firewall';
}

function tokenValues(tokens: string[], fieldIndex: number): string[] {
  return unique(tokens.slice(fieldIndex + 1).filter((value) => !['[', ']'].includes(value)));
}

interface PanPolicyAccumulator {
  name: string;
  sequence: number;
  from: string[];
  to: string[];
  source: string[];
  destination: string[];
  application: string[];
  service: string[];
  action?: string;
  disabled?: boolean;
}

interface PanNatAccumulator {
  name: string;
  source: string[];
  destination: string[];
  from: string[];
  to: string[];
  translatedSource?: string;
  translatedDestination?: string;
  originalPort?: string;
  translatedPort?: string;
  inboundInterface?: string;
  outboundInterface?: string;
  disabled?: boolean;
}

function parsePanosSet(config: MutableConfig): void {
  const routes = new Map<string, ParsedRoute>();
  const policies = new Map<string, PanPolicyAccumulator>();
  const natRules = new Map<string, PanNatAccumulator>();
  const zones = new Map<string, string>();

  for (const rawLine of config.rawConfig.split(/\r?\n/)) {
    const tokens = words(rawLine);
    if (tokens[0]?.toLowerCase() !== 'set') continue;
    const lower = tokens.map((token) => token.toLowerCase());
    const hostnameIndex = lower.lastIndexOf('hostname');
    if (hostnameIndex >= 0 && tokens[hostnameIndex + 1]) config.hostname = tokens[hostnameIndex + 1];

    const ethernetIndex = lower.findIndex((token, index) => token === 'ethernet' && lower[index - 1] === 'interface');
    if (ethernetIndex >= 0 && tokens[ethernetIndex + 1]) {
      let interfaceName = tokens[ethernetIndex + 1];
      const unitsIndex = lower.indexOf('units', ethernetIndex);
      if (unitsIndex >= 0 && tokens[unitsIndex + 1]) interfaceName = tokens[unitsIndex + 1];
      const item = ensureInterface(config, interfaceName);
      const ipIndex = lower.lastIndexOf('ip');
      if (ipIndex > ethernetIndex && tokens[ipIndex + 1]) item.addresses.push(tokens[ipIndex + 1]);
      const tagIndex = lower.lastIndexOf('tag');
      if (tagIndex > ethernetIndex && tokens[tagIndex + 1]) {
        item.vlanId = tokens[tagIndex + 1];
        ensureVlan(config, item.vlanId).interfaces.push(item.name);
      }
      const commentIndex = lower.lastIndexOf('comment');
      if (commentIndex > ethernetIndex) item.description = tokens.slice(commentIndex + 1).join(' ');
    }

    const zoneIndex = lower.indexOf('zone');
    const layer3Index = lower.indexOf('layer3');
    if (zoneIndex >= 0 && layer3Index > zoneIndex && tokens[zoneIndex + 1]) {
      for (const interfaceName of tokens.slice(layer3Index + 1)) zones.set(interfaceName, tokens[zoneIndex + 1]);
    }

    const staticIndex = lower.indexOf('static-route');
    if (staticIndex >= 0 && tokens[staticIndex + 1]) {
      const name = tokens[staticIndex + 1];
      const route = routes.get(name) ?? { name, destination: '', protocol: 'static', active: true };
      const destinationIndex = lower.indexOf('destination', staticIndex);
      if (destinationIndex >= 0) route.destination = tokens[destinationIndex + 1] ?? route.destination;
      const nextHopIndex = lower.indexOf('ip-address', staticIndex);
      if (nextHopIndex >= 0) route.nextHop = tokens[nextHopIndex + 1];
      const interfaceIndex = lower.indexOf('interface', staticIndex);
      if (interfaceIndex >= 0) route.interface = tokens[interfaceIndex + 1];
      if (lower.includes('disable') && lower.at(-1) === 'yes') route.active = false;
      routes.set(name, route);
    }

    const rulebaseIndex = lower.indexOf('rulebase');
    const securityIndex = lower.indexOf('security', rulebaseIndex);
    const rulesIndex = lower.indexOf('rules', securityIndex);
    if (rulebaseIndex >= 0 && securityIndex >= 0 && rulesIndex >= 0 && tokens[rulesIndex + 1]) {
      const name = tokens[rulesIndex + 1];
      const policy = policies.get(name) ?? {
        name,
        sequence: policies.size * 10 + 10,
        from: [],
        to: [],
        source: [],
        destination: [],
        application: [],
        service: [],
      };
      const fieldIndex = rulesIndex + 2;
      const field = lower[fieldIndex];
      const values = tokenValues(tokens, fieldIndex);
      if (field === 'from') policy.from = values;
      if (field === 'to') policy.to = values;
      if (field === 'source') policy.source = values;
      if (field === 'destination') policy.destination = values;
      if (field === 'application') policy.application = values;
      if (field === 'service') policy.service = values;
      if (field === 'action') policy.action = values[0];
      if (field === 'disabled') policy.disabled = values[0] === 'yes';
      policies.set(name, policy);
    }

    const natIndex = lower.indexOf('nat', rulebaseIndex);
    const natRulesIndex = lower.indexOf('rules', natIndex);
    if (rulebaseIndex >= 0 && natIndex >= 0 && natRulesIndex >= 0 && tokens[natRulesIndex + 1]) {
      const name = tokens[natRulesIndex + 1];
      const rule = natRules.get(name) ?? { name, source: [], destination: [], from: [], to: [] };
      const fieldIndex = natRulesIndex + 2;
      const field = lower[fieldIndex];
      const values = tokenValues(tokens, fieldIndex);
      if (field === 'from') rule.from = values;
      if (field === 'to') rule.to = values;
      if (field === 'source') rule.source = values;
      if (field === 'destination') rule.destination = values;
      if (field === 'to-interface') rule.outboundInterface = values[0];
      if (field === 'disabled') rule.disabled = values[0] === 'yes';
      const translatedAddressIndex = lower.indexOf('translated-address', fieldIndex);
      if (translatedAddressIndex >= 0) rule.translatedDestination = tokens[translatedAddressIndex + 1];
      const translatedPortIndex = lower.indexOf('translated-port', fieldIndex);
      if (translatedPortIndex >= 0) rule.translatedPort = tokens[translatedPortIndex + 1];
      if (lower.includes('source-translation')) {
        const interfaceIndex = lower.lastIndexOf('interface');
        rule.translatedSource = interfaceIndex >= 0 ? `interface:${tokens[interfaceIndex + 1]}` : values.at(-1) ?? 'dynamic';
        if (interfaceIndex >= 0) rule.outboundInterface = tokens[interfaceIndex + 1];
      }
      natRules.set(name, rule);
    }
  }

  for (const [interfaceName, zone] of zones) {
    const item = ensureInterface(config, interfaceName);
    item.zone = zone;
    item.role = roleFromName(zone);
  }
  config.routes.push(...[...routes.values()].filter((route) => route.destination));
  config.aclRules.push(...[...policies.values()].map((policy) => ({
    name: policy.name,
    sequence: policy.sequence,
    action: normalizeAction(policy.action),
    protocol: policy.application.length ? policy.application.join(',') : 'any',
    source: policy.source.length ? policy.source.join(',') : 'any',
    destination: policy.destination.length ? policy.destination.join(',') : 'any',
    destinationPort: policy.service.length ? policy.service.join(',') : undefined,
    fromZone: policy.from.length ? policy.from.join(',') : undefined,
    toZone: policy.to.length ? policy.to.join(',') : undefined,
    enabled: !policy.disabled,
  })));
  config.natRules.push(...[...natRules.values()].map((rule): ParsedNatRule => ({
    name: rule.name,
    natType: rule.translatedDestination ? (rule.translatedPort ? 'port_mapping' : 'dnat') : 'snat',
    protocol: 'any',
    source: rule.source.length ? rule.source.join(',') : undefined,
    originalDestination: rule.destination.length ? rule.destination.join(',') : undefined,
    translatedSource: rule.translatedSource,
    translatedDestination: rule.translatedDestination,
    translatedPort: rule.translatedPort,
    inboundInterface: rule.inboundInterface,
    outboundInterface: rule.outboundInterface,
    enabled: !rule.disabled,
    description: [rule.from.length ? `from ${rule.from.join(',')}` : '', rule.to.length ? `to ${rule.to.join(',')}` : ''].filter(Boolean).join('; '),
  })));
}

function panEntryValues(entry: Element, field: string): string[] {
  const node = child(entry, field);
  if (!node) return [];
  const values = Array.from(node.getElementsByTagName('member')).map((item) => item.textContent?.trim() ?? '').filter(Boolean);
  return values.length ? values : optional(node.textContent ?? undefined)?.split(/\s+/) ?? [];
}

function parsePanosXml(config: MutableConfig): void {
  const document = parseXml(config.rawConfig);
  config.hostname = descendantText(document, 'hostname') ?? config.hostname;
  const ethernet = descendant(document, 'ethernet');
  if (ethernet) {
    for (const entry of Array.from(ethernet.children).filter((item) => item.tagName === 'entry')) {
      const name = entryName(entry);
      const layer3 = descendant(entry, 'layer3');
      if (layer3) {
        const item = ensureInterface(config, name);
        item.addresses.push(...Array.from(layer3.getElementsByTagName('ip')).flatMap((ip) =>
          Array.from(ip.getElementsByTagName('entry')).map(entryName).filter(Boolean)));
      }
      const units = descendant(entry, 'units');
      if (units) {
        for (const unit of Array.from(units.children).filter((item) => item.tagName === 'entry')) {
          const item = ensureInterface(config, entryName(unit));
          item.vlanId = descendantText(unit, 'tag');
          item.addresses.push(...Array.from(unit.getElementsByTagName('ip')).flatMap((ip) =>
            Array.from(ip.getElementsByTagName('entry')).map(entryName).filter(Boolean)));
          if (item.vlanId) ensureVlan(config, item.vlanId).interfaces.push(item.name);
        }
      }
    }
  }

  const zoneContainer = descendant(document, 'zone');
  if (zoneContainer) {
    for (const entry of Array.from(zoneContainer.children).filter((item) => item.tagName === 'entry')) {
      const zone = entryName(entry);
      for (const interfaceName of members(entry, 'layer3')) {
        const item = ensureInterface(config, interfaceName);
        item.zone = zone;
        item.role = roleFromName(zone);
      }
    }
  }

  const staticRouteContainers = Array.from(document.getElementsByTagName('static-route'));
  for (const container of staticRouteContainers) {
    for (const entry of Array.from(container.children).filter((item) => item.tagName === 'entry')) {
      const destination = childText(entry, 'destination');
      if (!destination) continue;
      config.routes.push({
        name: entryName(entry),
        destination,
        nextHop: descendantText(child(entry, 'nexthop'), 'ip-address'),
        interface: childText(entry, 'interface'),
        metric: Number.isFinite(Number(childText(entry, 'metric'))) ? Number(childText(entry, 'metric')) : undefined,
        protocol: 'static',
        active: childText(entry, 'disabled') !== 'yes',
      });
    }
  }

  const security = descendant(document, 'security');
  const securityRules = security ? descendant(security, 'rules') : null;
  if (securityRules) {
    let sequence = 10;
    for (const entry of Array.from(securityRules.children).filter((item) => item.tagName === 'entry')) {
      config.aclRules.push({
        name: entryName(entry),
        sequence,
        action: normalizeAction(childText(entry, 'action')),
        protocol: panEntryValues(entry, 'application').join(',') || 'any',
        source: panEntryValues(entry, 'source').join(',') || 'any',
        destination: panEntryValues(entry, 'destination').join(',') || 'any',
        destinationPort: panEntryValues(entry, 'service').join(',') || undefined,
        fromZone: panEntryValues(entry, 'from').join(',') || undefined,
        toZone: panEntryValues(entry, 'to').join(',') || undefined,
        enabled: childText(entry, 'disabled') !== 'yes',
      });
      sequence += 10;
    }
  }

  const natContainers = Array.from(document.getElementsByTagName('nat'));
  const seenNatEntries = new Set<Element>();
  for (const natContainer of natContainers) {
    const rules = descendant(natContainer, 'rules');
    if (!rules) continue;
    for (const entry of Array.from(rules.children).filter((item) => item.tagName === 'entry')) {
      if (seenNatEntries.has(entry)) continue;
      seenNatEntries.add(entry);
      const sourceTranslation = child(entry, 'source-translation');
      const destinationTranslation = child(entry, 'destination-translation');
      const translatedDestination = destinationTranslation ? descendantText(destinationTranslation, 'translated-address') : undefined;
      const translatedPort = destinationTranslation ? descendantText(destinationTranslation, 'translated-port') : undefined;
      const sourceInterface = sourceTranslation ? descendantText(sourceTranslation, 'interface') : undefined;
      const translatedSource = sourceTranslation
        ? descendantText(sourceTranslation, 'translated-address') ?? (sourceInterface ? `interface:${sourceInterface}` : 'dynamic')
        : undefined;
      if (!sourceTranslation && !destinationTranslation) continue;
      config.natRules.push({
        name: entryName(entry),
        natType: translatedDestination ? (translatedPort ? 'port_mapping' : 'dnat') : 'snat',
        protocol: 'any',
        source: panEntryValues(entry, 'source').join(',') || undefined,
        originalDestination: panEntryValues(entry, 'destination').join(',') || undefined,
        translatedSource,
        translatedDestination,
        translatedPort,
        outboundInterface: childText(entry, 'to-interface') ?? sourceInterface,
        enabled: childText(entry, 'disabled') !== 'yes',
        description: [
          panEntryValues(entry, 'from').length ? `from ${panEntryValues(entry, 'from').join(',')}` : '',
          panEntryValues(entry, 'to').length ? `to ${panEntryValues(entry, 'to').join(',')}` : '',
        ].filter(Boolean).join('; '),
      });
    }
  }
}

interface JuniperPolicyAccumulator {
  name: string;
  sequence: number;
  fromZone: string;
  toZone: string;
  source: string[];
  destination: string[];
  applications: string[];
  action?: string;
  disabled?: boolean;
}

function parseJuniper(config: MutableConfig): void {
  const policies = new Map<string, JuniperPolicyAccumulator>();
  const routes = new Map<string, ParsedRoute>();
  for (const rawLine of config.rawConfig.split(/\r?\n/)) {
    const tokens = words(rawLine);
    const lower = tokens.map((token) => token.toLowerCase());
    if (lower[0] !== 'set') continue;
    if (lower[1] === 'system' && lower[2] === 'host-name' && tokens[3]) config.hostname = tokens[3];
    if (lower[1] === 'interfaces' && tokens[2]) {
      const unitIndex = lower.indexOf('unit', 3);
      const unit = unitIndex >= 0 ? tokens[unitIndex + 1] : '0';
      const name = unit === '0' ? tokens[2] : `${tokens[2]}.${unit}`;
      const item = ensureInterface(config, name);
      const addressIndex = lower.lastIndexOf('address');
      if (addressIndex >= 0 && tokens[addressIndex + 1]) item.addresses.push(tokens[addressIndex + 1]);
      const vlanIndex = lower.lastIndexOf('vlan-id');
      if (vlanIndex >= 0 && tokens[vlanIndex + 1]) {
        item.vlanId = tokens[vlanIndex + 1];
        ensureVlan(config, item.vlanId).interfaces.push(item.name);
      }
      if (lower.includes('disable')) item.enabled = false;
    }
    const zoneIndex = lower.indexOf('security-zone');
    const interfaceIndex = lower.indexOf('interfaces', zoneIndex);
    if (zoneIndex >= 0 && interfaceIndex > zoneIndex && tokens[zoneIndex + 1] && tokens[interfaceIndex + 1]) {
      const item = ensureInterface(config, tokens[interfaceIndex + 1]);
      item.zone = tokens[zoneIndex + 1];
      item.role = roleFromName(item.zone);
    }
    if (lower[1] === 'routing-options' && lower[2] === 'static' && lower[3] === 'route' && tokens[4]) {
      const destination = tokens[4];
      const route = routes.get(destination) ?? {
        name: `static-${destination}`,
        destination,
        protocol: 'static',
        active: true,
      };
      const nextHopIndex = lower.indexOf('next-hop', 5);
      if (nextHopIndex >= 0) route.nextHop = tokens[nextHopIndex + 1];
      const qualifiedIndex = lower.indexOf('qualified-next-hop', 5);
      if (qualifiedIndex >= 0) route.nextHop = tokens[qualifiedIndex + 1];
      const preferenceIndex = lower.indexOf('preference', 5);
      if (preferenceIndex >= 0 && Number.isFinite(Number(tokens[preferenceIndex + 1]))) route.metric = Number(tokens[preferenceIndex + 1]);
      if (lower.includes('discard') || lower.includes('reject')) route.active = false;
      routes.set(destination, route);
    }
    const policiesIndex = lower.indexOf('policies');
    const fromIndex = lower.indexOf('from-zone', policiesIndex);
    const toIndex = lower.indexOf('to-zone', policiesIndex);
    const policyIndex = lower.indexOf('policy', policiesIndex);
    if (policiesIndex >= 0 && fromIndex >= 0 && toIndex >= 0 && policyIndex >= 0 && tokens[policyIndex + 1]) {
      const name = `${tokens[fromIndex + 1]}:${tokens[toIndex + 1]}:${tokens[policyIndex + 1]}`;
      const policy = policies.get(name) ?? {
        name: tokens[policyIndex + 1],
        sequence: policies.size * 10 + 10,
        fromZone: tokens[fromIndex + 1],
        toZone: tokens[toIndex + 1],
        source: [],
        destination: [],
        applications: [],
      };
      const matchIndex = lower.indexOf('match', policyIndex);
      if (matchIndex >= 0) {
        const field = lower[matchIndex + 1];
        const value = tokens[matchIndex + 2];
        if (field === 'source-address' && value) policy.source.push(value);
        if (field === 'destination-address' && value) policy.destination.push(value);
        if (field === 'application' && value) policy.applications.push(value);
      }
      const thenIndex = lower.indexOf('then', policyIndex);
      if (thenIndex >= 0) policy.action = tokens[thenIndex + 1];
      if (lower.includes('inactive:')) policy.disabled = true;
      policies.set(name, policy);
    }
  }
  config.routes.push(...routes.values());
  config.aclRules.push(...[...policies.values()].map((policy) => ({
    name: policy.name,
    sequence: policy.sequence,
    action: normalizeAction(policy.action),
    protocol: policy.applications.join(',') || 'any',
    source: unique(policy.source).join(',') || 'any',
    destination: unique(policy.destination).join(',') || 'any',
    fromZone: policy.fromZone,
    toZone: policy.toZone,
    enabled: !policy.disabled,
  })));
  config.deviceType = 'firewall';
  if (config.rawConfig.trimStart().startsWith('<')) {
    config.warnings.push('Junos XML is not yet normalized; export the configuration with “show configuration | display set”.');
  }
}

function finalize(config: MutableConfig, hostnameOverride?: string): ParsedDeviceConfig {
  if (hostnameOverride?.trim()) config.hostname = hostnameOverride.trim();
  config.hostname = config.hostname.trim() || 'Imported network device';
  for (const item of config.interfaces) {
    item.addresses = unique(item.addresses);
    item.role = item.role === 'other' && item.zone ? roleFromName(item.zone) : item.role;
  }
  for (const vlan of config.vlans) vlan.interfaces = unique(vlan.interfaces);
  config.interfaces = config.interfaces.filter((item) => item.name);
  config.vlans = config.vlans.filter((item) => item.id);
  config.routes = config.routes.filter((item) => item.destination);
  config.aclRules.sort((left, right) => left.sequence - right.sequence);
  if (!config.interfaces.length) config.warnings.push('No interfaces were recognized.');
  if (!config.routes.length) config.warnings.push('No route entries were recognized; Internet reachability may remain indeterminate.');
  if (!config.aclRules.length) config.warnings.push('No ACL or security-policy entries were recognized; filtering decisions will be reported as possible, not confirmed.');
  return config;
}

function fallbackHostname(sourceFile: string | undefined, profile: ConfigProfile): string {
  const fromFile = sourceFile?.replace(/\.[^.]+$/, '').trim();
  if (fromFile) return fromFile;
  return CONFIG_PROFILES.find((item) => item.value === profile)?.label ?? 'Imported network device';
}

export function parseDeviceConfig(
  profile: ConfigProfile,
  rawConfig: string,
  hostnameOverride?: string,
  sourceFile?: string,
): ParsedDeviceConfig {
  if (!rawConfig.trim()) throw new Error('Paste or select a device configuration first');
  if (rawConfig.length > 16 * 1024 * 1024) throw new Error('Configuration files larger than 16 MiB are not accepted by the interactive importer');
  const config = emptyConfig(profile, rawConfig, fallbackHostname(sourceFile, profile), sourceFile);
  if (profile === 'cisco_network') parseCisco(config);
  if (profile === 'openwrt_network') parseOpenWrt(config);
  if (profile === 'opnsense_firewall') parseOpnsense(config);
  if (profile === 'juniper_firewall') parseJuniper(config);
  if (profile === 'palo_alto_firewall' || profile === 'palo_alto_network') {
    if (rawConfig.trimStart().startsWith('<')) parsePanosXml(config);
    else parsePanosSet(config);
    config.deviceType = profile === 'palo_alto_firewall'
      ? 'firewall'
      : config.routes.length > 0 ? 'router' : 'switch';
  }
  return finalize(config, hostnameOverride);
}

export function readStoredDeviceConfig(value: string | null | undefined): ParsedDeviceConfig | null {
  if (!value?.trim()) return null;
  try {
    const parsed = JSON.parse(value) as Partial<ParsedDeviceConfig>;
    if (parsed.schema !== 'dfir-network-config-v1') return null;
    if (!Array.isArray(parsed.interfaces) || !Array.isArray(parsed.routes) || !Array.isArray(parsed.aclRules)) return null;
    return parsed as ParsedDeviceConfig;
  } catch {
    return null;
  }
}

export function hostAddress(value: string): string {
  return value.split('/')[0]?.trim() ?? '';
}

export function subnetFromAddress(value: string): string {
  const [address, rawPrefix] = value.split('/');
  if (!address || rawPrefix == null) return '';
  const prefix = Number(rawPrefix);
  if (address.includes(':')) {
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) return '';
    return `${address}/${prefix}`;
  }
  const octets = address.split('.').map(Number);
  if (octets.length !== 4 || octets.some((item) => !Number.isInteger(item) || item < 0 || item > 255) || prefix < 0 || prefix > 32) return '';
  const numeric = (((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (numeric & mask) >>> 0;
  return `${[(network >>> 24) & 255, (network >>> 16) & 255, (network >>> 8) & 255, network & 255].join('.')}/${prefix}`;
}
