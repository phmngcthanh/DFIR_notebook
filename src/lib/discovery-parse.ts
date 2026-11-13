/**
 * Reading what a responder pastes from a client network: an ARP table, the
 * output of ipconfig or ip addr, an nmap scan, or a DHCP lease file. Each
 * parser turns text into hosts with their addresses; deciding what to do with
 * them (new asset, update, skip) happens in `discovery-import.ts`.
 *
 * Only IPv4 is read. Link-local, multicast, loopback and container-bridge
 * entries are skipped because they identify nothing about the client. Labels
 * are matched in English (`ipconfig` prints localized labels on localized
 * Windows).
 */
import { normalizeMac } from '@/lib/asset-match';

export type DiscoveryFormat = 'arp' | 'ipconfig' | 'ipaddr' | 'nmap' | 'dhcp';

export const DISCOVERY_FORMATS: { value: DiscoveryFormat; label: string; hint: string }[] = [
  { value: 'arp', label: 'ARP / neighbor table', hint: 'arp -a, arp -n, ip neigh, show ip arp' },
  { value: 'ipconfig', label: 'ipconfig /all', hint: 'Windows: ipconfig /all' },
  { value: 'ipaddr', label: 'ip addr / ifconfig', hint: 'Linux, macOS, BSD' },
  { value: 'nmap', label: 'nmap scan', hint: 'nmap -oN or -oG output, ping sweeps' },
  { value: 'dhcp', label: 'DHCP leases', hint: 'dhcpd.leases, dnsmasq.leases, netsh dhcp, Get-DhcpServerv4Lease CSV' },
];

export function discoveryLabel(format: DiscoveryFormat): string {
  return DISCOVERY_FORMATS.find((item) => item.value === format)?.label ?? format;
}

export interface DiscoveredNic {
  name: string;
  ip: string;
  /** `AA:BB:CC:DD:EE:FF`, or empty when the source has none. */
  mac: string;
}

export interface DiscoveredPort {
  port: number;
  protocol: string;
  service: string;
}

export interface DiscoveredHost {
  /** The host name when the source gave one. */
  name: string;
  nics: DiscoveredNic[];
  os?: string;
  vendor?: string;
  ports?: DiscoveredPort[];
  /** RFC 3339, when the source says when the host was seen. */
  observedAt?: string;
  /** Set for a host only mentioned by another's configuration (gateway, DNS, DHCP server). */
  reference?: string;
  note?: string;
}

export interface ParsedDiscovery {
  format: DiscoveryFormat;
  label: string;
  hosts: DiscoveredHost[];
  warnings: string[];
}

export interface DiscoveryOptions {
  format?: DiscoveryFormat;
  /** The machine `ip addr` or `ifconfig` was run on; those outputs do not name it. */
  hostName?: string;
}

// ---- small helpers ------------------------------------------------------------

const IPV4 = String.raw`(\d{1,3}(?:\.\d{1,3}){3})`;

function lineList(text: string): string[] {
  return text.split(/\r?\n/);
}

/** `AA:BB:CC:DD:EE:FF` from any common notation, including macOS's short octets and Cisco's dotted form. */
export function toMac(value?: string | null): string {
  const text = (value ?? '').trim();
  const padded = /^[0-9a-f]{1,2}(?:[:-][0-9a-f]{1,2}){5}$/i.test(text)
    ? text.split(/[:-]/).map((part) => part.padStart(2, '0')).join('')
    : text;
  const digits = normalizeMac(padded);
  return digits ? (digits.match(/../g) ?? []).join(':').toUpperCase() : '';
}

/** Broadcast and multicast hardware addresses name no machine. */
function hostMac(value?: string | null): string {
  const mac = toMac(value);
  return mac && (parseInt(mac.slice(0, 2), 16) & 1) === 0 ? mac : '';
}

/** A dotted quad that can belong to a host: not unspecified, loopback, link-local, multicast, or broadcast. */
function usableIp(value?: string | null): string {
  const text = (value ?? '').trim();
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(text)) return '';
  const parts = text.split('.').map(Number);
  if (parts.some((part) => part > 255)) return '';
  if (parts[0] === 0 || parts[0] === 127 || parts[0] >= 224) return '';
  if (parts[0] === 169 && parts[1] === 254) return '';
  return parts.join('.');
}

function hostLabel(value?: string | null): string {
  const text = (value ?? '').trim().replace(/\.+$/, '');
  return text === '?' || text === '*' || usableIp(text) ? '' : text;
}

const VIRTUAL_INTERFACE = /^(?:lo\d*|docker\d*|veth\w*|br-\w+|virbr\d*|lxc\w*|lxd\w*|cali\w*|flannel\S*|cni\d*|vboxnet\d*|vmnet\d*|tun\d*|tap\d*)$/i;

function firstMatch(line: string, patterns: RegExp[]): RegExpExecArray | null {
  for (const pattern of patterns) {
    const found = pattern.exec(line);
    if (found) return found;
  }
  return null;
}

function singleNicHost(ip: string, mac: string, name = ''): DiscoveredHost | null {
  const address = usableIp(ip);
  if (!address) return null;
  return { name: hostLabel(name), nics: [{ name: 'Primary', ip: address, mac: hostMac(mac) }] };
}

// ---- ARP ------------------------------------------------------------------------

function parseArp(lines: string[]): DiscoveredHost[] {
  const hosts: DiscoveredHost[] = [];
  for (const line of lines) {
    const found = firstMatch(line, [
      // Windows: arp -a
      new RegExp(String.raw`^\s*${IPV4}\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\s+(?:dynamic|static)\b`, 'i'),
      // Linux, BSD, macOS: arp -a ("? (10.0.0.1) at aa:bb:... [ether] on eth0")
      new RegExp(String.raw`^(\S+)\s+\(${IPV4}\)\s+at\s+([0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5})\b`, 'i'),
      // Linux: arp -n
      new RegExp(String.raw`^${IPV4}\s+ether\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b`, 'i'),
      // Linux: ip neigh
      new RegExp(String.raw`^${IPV4}\s+dev\s+\S+\s+lladdr\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b`, 'i'),
      // Cisco: show ip arp
      new RegExp(String.raw`^Internet\s+${IPV4}\s+\S+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+ARPA\b`, 'i'),
    ]);
    if (!found) continue;
    // The BSD form is the only one with a leading name; its groups are (name, ip, mac).
    const host = found.length === 4 ? singleNicHost(found[2], found[3], found[1]) : singleNicHost(found[1], found[2]);
    if (host && host.nics[0].mac) hosts.push(host);
  }
  return hosts;
}

// ---- ipconfig /all --------------------------------------------------------------

interface Adapter {
  name: string;
  mac: string;
  ips: string[];
  gateways: string[];
  dhcp: string[];
  dns: string[];
  disconnected: boolean;
}

function parseIpconfig(lines: string[], options: DiscoveryOptions): DiscoveredHost[] {
  let hostName = '';
  const adapters: Adapter[] = [];
  let current: Adapter | null = null;
  let list: string[] | null = null;
  for (const line of lines) {
    if (!line.trim()) continue;
    if (!/^\s/.test(line)) {
      const header = /^(.*?):\s*$/.exec(line);
      if (header && !/windows ip configuration/i.test(header[1])) {
        current = { name: header[1].replace(/^.*?adapter\s+/i, '').trim(), mac: '', ips: [], gateways: [], dhcp: [], dns: [], disconnected: false };
        adapters.push(current);
      }
      list = null;
      continue;
    }
    const pair = /^\s+(.+?)[\s.]*\s:(?:\s(.*))?$/.exec(line);
    if (!pair) {
      // A value continued on the next line (a second DNS server or gateway).
      const value = line.trim();
      if (list && /^\d{1,3}(?:\.\d{1,3}){3}/.test(value)) list.push(value.replace(/\(.*$/, ''));
      continue;
    }
    const key = pair[1].trim().toLowerCase();
    const value = (pair[2] ?? '').trim();
    list = null;
    if (!current) {
      if (key === 'host name') hostName = value;
      continue;
    }
    if (key === 'physical address') current.mac = value;
    else if (key === 'media state') current.disconnected = /disconnected/i.test(value);
    else if (key === 'ipv4 address' || key === 'ip address') current.ips.push(value.replace(/\(.*$/, ''));
    else if (key === 'default gateway') { list = current.gateways; if (value) list.push(value.replace(/\(.*$/, '')); }
    else if (key === 'dhcp server') { list = current.dhcp; if (value) list.push(value); }
    else if (key === 'dns servers') { list = current.dns; if (value) list.push(value); }
  }
  const nics: DiscoveredNic[] = [];
  const references = new Map<string, Set<string>>();
  for (const adapter of adapters) {
    if (adapter.disconnected) continue;
    for (const ip of adapter.ips) {
      const address = usableIp(ip);
      if (address) nics.push({ name: adapter.name || 'Primary', ip: address, mac: hostMac(adapter.mac) });
    }
    const note = (ip: string, role: string) => {
      const address = usableIp(ip);
      if (!address) return;
      const roles = references.get(address) ?? new Set<string>();
      roles.add(role);
      references.set(address, roles);
    };
    adapter.gateways.forEach((ip) => note(ip, 'default gateway'));
    adapter.dhcp.forEach((ip) => note(ip, 'DHCP server'));
    adapter.dns.forEach((ip) => note(ip, 'DNS server'));
  }
  if (!nics.length) return [];
  const name = hostLabel(hostName) || hostLabel(options.hostName);
  const hosts: DiscoveredHost[] = [{ name, nics, os: 'Windows' }];
  for (const [ip, roles] of references) {
    if (nics.some((nic) => nic.ip === ip)) continue;
    hosts.push({ name: '', nics: [{ name: 'Primary', ip, mac: '' }], reference: `${[...roles].join(' and ')} of ${name || nics[0].ip}` });
  }
  return hosts;
}

// ---- ip addr / ifconfig ----------------------------------------------------------

function parseIpAddr(lines: string[], options: DiscoveryOptions, warnings: string[]): DiscoveredHost[] {
  const interfaces: { name: string; mac: string; ips: string[] }[] = [];
  let current: { name: string; mac: string; ips: string[] } | null = null;
  let skipped = 0;
  for (const line of lines) {
    const header = firstMatch(line, [
      /^\d+:\s+([^\s:@]+)(?:@\S+)?:\s+</, // ip addr
      /^([A-Za-z0-9._-]+):?\s+(?:flags=|Link encap)/, // ifconfig
    ]);
    if (header) {
      if (VIRTUAL_INTERFACE.test(header[1])) {
        skipped += 1;
        current = null;
      } else {
        current = { name: header[1], mac: '', ips: [] };
        interfaces.push(current);
      }
      continue;
    }
    if (!current || !/^\s/.test(line)) continue;
    const mac = firstMatch(line, [/^\s+link\/ether\s+([0-9a-f:]{17})/i, /^\s+ether\s+([0-9a-f:]{11,17})/i, /HWaddr\s+([0-9a-f:]{17})/i, /^\s+lladdr\s+([0-9a-f:]{11,17})/i]);
    if (mac) {
      current.mac = mac[1];
      continue;
    }
    const ip = firstMatch(line, [new RegExp(String.raw`^\s+inet\s+(?:addr:)?${IPV4}`)]);
    if (ip && usableIp(ip[1])) current.ips.push(ip[1]);
  }
  if (skipped) warnings.push(`Skipped ${skipped} loopback or virtual interface${skipped === 1 ? '' : 's'} (lo, docker, veth, bridges).`);
  const nics: DiscoveredNic[] = [];
  for (const item of interfaces) {
    item.ips.forEach((ip, index) => nics.push({ name: index === 0 ? item.name : `${item.name}:${index}`, ip, mac: hostMac(item.mac) }));
  }
  return nics.length ? [{ name: hostLabel(options.hostName), nics }] : [];
}

// ---- nmap ---------------------------------------------------------------------------

function nmapTime(text: string): string | undefined {
  const date = new Date(text.trim());
  return Number.isNaN(date.valueOf()) ? undefined : date.toISOString();
}

function parseNmapNormal(lines: string[]): DiscoveredHost[] {
  const hosts: DiscoveredHost[] = [];
  let current: DiscoveredHost | null = null;
  let scanned: string | undefined;
  for (const line of lines) {
    const started = /^#\s*Nmap\s+\S+\s+scan initiated\s+(.+?)\s+as:/i.exec(line);
    if (started) {
      scanned = nmapTime(started[1]);
      continue;
    }
    const report = new RegExp(String.raw`^Nmap scan report for\s+(?:(\S+)\s+\(${IPV4}\)|${IPV4})\s*$`, 'i').exec(line);
    if (report) {
      const ip = usableIp(report[2] ?? report[3]);
      current = ip ? { name: hostLabel(report[1]), nics: [{ name: 'Primary', ip, mac: '' }], ports: [], observedAt: scanned } : null;
      if (current) hosts.push(current);
      continue;
    }
    if (!current) continue;
    const port = /^(\d+)\/(tcp|udp|sctp)\s+open(?!\|)\s*(\S*)/i.exec(line);
    if (port) {
      current.ports?.push({ port: Number(port[1]), protocol: port[2].toLowerCase(), service: port[3] });
      continue;
    }
    const mac = /^MAC Address:\s+([0-9a-f:]{17})(?:\s+\((.*)\))?/i.exec(line);
    if (mac) {
      current.nics[0].mac = hostMac(mac[1]);
      if (mac[2] && !/^unknown$/i.test(mac[2])) current.vendor = mac[2];
      continue;
    }
    const os = /^OS details:\s*(.+)$/i.exec(line) ?? (current.os ? null : /^Running:\s*(.+)$/i.exec(line));
    if (os) current.os = os[1].trim();
  }
  return hosts;
}

function parseNmapGreppable(lines: string[]): DiscoveredHost[] {
  const hosts: DiscoveredHost[] = [];
  let scanned: string | undefined;
  for (const line of lines) {
    const started = /^#\s*Nmap\s+\S+\s+scan initiated\s+(.+?)\s+as:/i.exec(line);
    if (started) {
      scanned = nmapTime(started[1]);
      continue;
    }
    const entry = new RegExp(String.raw`^Host:\s+${IPV4}\s+\(([^)]*)\)\s*(.*)$`).exec(line);
    if (!entry) continue;
    const ip = usableIp(entry[1]);
    if (!ip) continue;
    const host: DiscoveredHost = { name: hostLabel(entry[2]), nics: [{ name: 'Primary', ip, mac: '' }], ports: [], observedAt: scanned };
    for (const section of entry[3].split('\t')) {
      const ports = /^Ports:\s*(.*)$/.exec(section);
      if (ports) {
        for (const item of ports[1].split(/,\s*/)) {
          const [port, state, protocol, , service] = item.split('/');
          if (state === 'open' && /^\d+$/.test(port)) host.ports?.push({ port: Number(port), protocol: protocol || 'tcp', service: service ?? '' });
        }
      }
      const os = /^OS:\s*(.+)$/.exec(section);
      if (os) host.os = os[1].trim();
    }
    hosts.push(host);
  }
  return hosts;
}

// ---- DHCP leases ----------------------------------------------------------------------

function parseIscLeases(text: string): DiscoveredHost[] {
  // A lease file is append-only: the last block for an address is the current one.
  const latest = new Map<string, DiscoveredHost>();
  for (const block of text.matchAll(new RegExp(String.raw`lease\s+${IPV4}\s*\{([\s\S]*?)\}`, 'g'))) {
    const mac = /hardware ethernet\s+([0-9a-f:]{17})/i.exec(block[2]);
    const host = singleNicHost(block[1], mac?.[1] ?? '', /client-hostname\s+"([^"]*)"/i.exec(block[2])?.[1]);
    if (!host || !host.nics[0].mac) continue;
    const starts = /starts\s+\d+\s+(\d{4})\/(\d{2})\/(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/.exec(block[2]);
    if (starts) host.observedAt = new Date(Date.UTC(+starts[1], +starts[2] - 1, +starts[3], +starts[4], +starts[5], +starts[6])).toISOString();
    const state = /binding state\s+(\w+)/.exec(block[2])?.[1];
    if (state && state !== 'active') host.note = `lease ${state}`;
    latest.set(block[1], host);
  }
  return [...latest.values()];
}

function csvCells(line: string, delimiter: string): string[] {
  const cells: string[] = [];
  let cell = '';
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (quoted) {
      if (char === '"' && line[index + 1] === '"') { cell += '"'; index += 1; }
      else if (char === '"') quoted = false;
      else cell += char;
    } else if (char === '"') quoted = true;
    else if (char === delimiter) { cells.push(cell); cell = ''; }
    else cell += char;
  }
  cells.push(cell);
  return cells.map((item) => item.trim());
}

function parseDhcpTable(lines: string[]): DiscoveredHost[] {
  const hosts: DiscoveredHost[] = [];
  const header = lines.findIndex((line) => /^["']?IPAddress["']?\s*[,;\t]/i.test(line.trim()));
  if (header >= 0) {
    const delimiter = lines[header].includes('\t') ? '\t' : lines[header].includes(';') && !lines[header].includes(',') ? ';' : ',';
    const names = csvCells(lines[header], delimiter).map((item) => item.toLowerCase());
    const column = (...wanted: string[]) => names.findIndex((item) => wanted.includes(item));
    const [ipAt, macAt, nameAt] = [column('ipaddress'), column('clientid', 'macaddress', 'mac'), column('hostname', 'name')];
    for (const line of lines.slice(header + 1)) {
      if (!line.trim()) continue;
      const cells = csvCells(line, delimiter);
      const host = singleNicHost(cells[ipAt] ?? '', cells[macAt] ?? '', cells[nameAt] ?? '');
      if (host?.nics[0].mac) hosts.push(host);
    }
    return hosts;
  }
  for (const line of lines) {
    // dnsmasq.leases: expiry, mac, ip, name, client id
    const dnsmasq = new RegExp(String.raw`^\d{9,}\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s+${IPV4}\s+(\S+)`, 'i').exec(line);
    if (dnsmasq) {
      const host = singleNicHost(dnsmasq[2], dnsmasq[1], dnsmasq[3]);
      if (host?.nics[0].mac) hosts.push(host);
      continue;
    }
    // netsh dhcp server scope <id> show clients 1
    const netsh = new RegExp(String.raw`^\s*${IPV4}\s+-\s+\S+\s+-\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\s*-\s*(.*)$`, 'i').exec(line);
    if (netsh) {
      const name = /-\s*[A-Z]\s*-\s*(\S.*)$/.exec(netsh[3])?.[1];
      const host = singleNicHost(netsh[1], netsh[2], name);
      if (host?.nics[0].mac) hosts.push(host);
    }
  }
  return hosts;
}

function parseDhcp(text: string): DiscoveredHost[] {
  return /^\s*lease\s+\d{1,3}(?:\.\d{1,3}){3}\s*\{/m.test(text) ? parseIscLeases(text) : parseDhcpTable(lineList(text));
}

// ---- merging and detection -----------------------------------------------------------

function macsOf(host: DiscoveredHost): Set<string> {
  return new Set(host.nics.map((nic) => nic.mac).filter(Boolean));
}

function ipsOf(host: DiscoveredHost): Set<string> {
  return new Set(host.nics.map((nic) => nic.ip).filter(Boolean));
}

function overlaps(left: Set<string>, right: Set<string>): boolean {
  for (const value of left) if (right.has(value)) return true;
  return false;
}

/** The same machine listed twice: a shared MAC, or a shared address when one side has no MAC to disagree. */
function sameHost(left: DiscoveredHost, right: DiscoveredHost): boolean {
  const [leftMacs, rightMacs] = [macsOf(left), macsOf(right)];
  if (overlaps(leftMacs, rightMacs)) return true;
  return overlaps(ipsOf(left), ipsOf(right)) && (leftMacs.size === 0 || rightMacs.size === 0);
}

function absorb(target: DiscoveredHost, other: DiscoveredHost): void {
  for (const nic of other.nics) {
    const same = target.nics.find((item) => item.ip === nic.ip && (item.mac === nic.mac || !item.mac || !nic.mac));
    if (!same) target.nics.push({ ...nic });
    else if (!same.mac && nic.mac) same.mac = nic.mac;
  }
  target.name ||= other.name;
  target.os ||= other.os;
  target.vendor ||= other.vendor;
  target.note ||= other.note;
  if (other.ports?.length) {
    const ports = target.ports ?? [];
    for (const port of other.ports) if (!ports.some((item) => item.port === port.port && item.protocol === port.protocol)) ports.push(port);
    target.ports = ports;
  }
  if (other.observedAt && (!target.observedAt || Date.parse(other.observedAt) > Date.parse(target.observedAt))) target.observedAt = other.observedAt;
}

function mergeHosts(hosts: DiscoveredHost[], warnings: string[]): DiscoveredHost[] {
  const merged: DiscoveredHost[] = [];
  for (const host of hosts) {
    const target = merged.find((item) => sameHost(item, host));
    if (target) absorb(target, host);
    else merged.push({ ...host, nics: host.nics.map((nic) => ({ ...nic })), ports: host.ports?.map((port) => ({ ...port })) });
  }
  const macsByIp = new Map<string, Set<string>>();
  for (const host of merged) {
    for (const nic of host.nics) {
      if (!nic.mac) continue;
      const set = macsByIp.get(nic.ip) ?? new Set<string>();
      set.add(nic.mac);
      macsByIp.set(nic.ip, set);
    }
  }
  for (const [ip, macs] of macsByIp) {
    if (macs.size > 1) warnings.push(`${ip} appears with ${macs.size} different MAC addresses (${[...macs].join(', ')}). That can mean an address conflict or spoofing.`);
  }
  return merged;
}

/** Which kind of output this is, judged from its shape; null when nothing fits. */
export function detectDiscoveryFormat(text: string): DiscoveryFormat | null {
  if (/<nmaprun\b/i.test(text) || /^\s*(?:#\s*Nmap\b|Nmap scan report for\b)/im.test(text) || /^Host:\s+\d{1,3}(?:\.\d{1,3}){3}\s+\(/m.test(text)) return 'nmap';
  if (/Windows IP Configuration/i.test(text) || (/Physical Address/i.test(text) && /IPv4 Address|IP Address/i.test(text))) return 'ipconfig';
  if (
    /^\s*lease\s+\d{1,3}(?:\.\d{1,3}){3}\s*\{/m.test(text)
    || /^\d{9,}\s+(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\s+\d{1,3}(?:\.\d{1,3}){3}\s+\S+/im.test(text)
    || /^\s*\d{1,3}(?:\.\d{1,3}){3}\s+-\s+\S+\s+-\s+(?:[0-9a-f]{2}-){5}[0-9a-f]{2}\b/im.test(text)
    || /^["']?IPAddress["']?\s*[,;\t]/im.test(text)
  ) return 'dhcp';
  if (/^\d+:\s+\S+:\s+</m.test(text) || /^\s+link\/ether\b/m.test(text) || /\bflags=\d+<|Link encap:/i.test(text)) return 'ipaddr';
  if (
    /Internet Address\s+Physical Address/i.test(text)
    || /^\s*\d{1,3}(?:\.\d{1,3}){3}\s+(?:[0-9a-f]{2}-){5}[0-9a-f]{2}\s+(?:dynamic|static)\b/im.test(text)
    || /\)\s+at\s+[0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5}\b/i.test(text)
    || /\bdev\s+\S+\s+lladdr\b/i.test(text)
    || /^\d{1,3}(?:\.\d{1,3}){3}\s+ether\s+/m.test(text)
    || /^Internet\s+\d{1,3}(?:\.\d{1,3}){3}\s+\S+\s+[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\s+ARPA/im.test(text)
  ) return 'arp';
  return null;
}

export function parseDiscovery(text: string, options: DiscoveryOptions = {}): ParsedDiscovery {
  if (!text.trim()) throw new Error('Paste the output first');
  const format = options.format ?? detectDiscoveryFormat(text);
  if (!format) {
    throw new Error('Could not tell what this output is. Choose the format, or paste arp -a, ipconfig /all, ip addr, nmap, or DHCP lease output.');
  }
  if (/<nmaprun\b/i.test(text)) throw new Error('nmap XML is not read. Run nmap with -oN (normal) or -oG (greppable) output instead.');
  const warnings: string[] = [];
  const lines = lineList(text);
  const found = ((): DiscoveredHost[] => {
    switch (format) {
      case 'arp': return parseArp(lines);
      case 'ipconfig': return parseIpconfig(lines, options);
      case 'ipaddr': return parseIpAddr(lines, options, warnings);
      case 'nmap': return /^Host:\s+\d/m.test(text) && !/^Nmap scan report for/m.test(text) ? parseNmapGreppable(lines) : parseNmapNormal(lines);
      case 'dhcp': return parseDhcp(text);
    }
  })();
  const hosts = mergeHosts(found, warnings);
  if (!hosts.length) throw new Error(`No hosts with an address were found in this ${discoveryLabel(format)} output.`);
  return { format, label: discoveryLabel(format), hosts, warnings };
}
