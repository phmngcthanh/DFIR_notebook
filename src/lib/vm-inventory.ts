import { v4 as uuidv4 } from 'uuid';
import type { Asset, JsonValue, Network, NetworkInterface } from '@/types';
import type { XmindTopic } from './topology-export';

export type VmInventoryPlatform = 'esxi' | 'proxmox' | 'hyperv' | 'generic';
export type VmInventorySourceFormat = 'csv' | 'json' | 'native';
export type VmKind = 'virtual-machine' | 'container';

export const VM_INVENTORY_SCHEMA = 'dfir-vm-inventory-v1' as const;

export interface ImportedVmInventory {
  schema: typeof VM_INVENTORY_SCHEMA;
  platform: VmInventoryPlatform;
  kind: VmKind;
  identityKey: string;
  nativeId?: string;
  name: string;
  inventoryScope?: string;
  hypervisor?: string;
  state?: string;
  guestOs?: string;
  assetType?: string;
  userName?: string;
  cpuCount?: number;
  memoryBytes?: number;
  diskBytes?: number;
  version?: string;
  generation?: string;
  configPath?: string;
  ipAddresses: string[];
  macAddresses: string[];
  sourceFormat: VmInventorySourceFormat;
  sourceFile?: string;
  raw: Record<string, JsonValue>;
  legacyProperties?: JsonValue;
}

export interface ParsedVmInventory {
  platform: VmInventoryPlatform;
  sourceFormat: VmInventorySourceFormat;
  sourceFile?: string;
  inventoryScope?: string;
  records: ImportedVmInventory[];
  warnings: string[];
}

export interface VmInventoryParseOptions {
  sourceFile?: string;
  inventoryScope?: string;
}

export interface VmImportInventory {
  caseId: string;
  assets: Asset[];
  networks: Network[];
  networkInterfaces: NetworkInterface[];
}

interface PartialChange {
  change_id: string;
  entity_type: string;
  operation: 'upsert';
  target_id: string;
  values: Record<string, JsonValue | undefined>;
}

export interface BuiltVmInventoryImport {
  document: string;
  warnings: string[];
  changeCount: number;
}

type InputRecord = Record<string, unknown>;

const PLATFORM_LABELS: Record<VmInventoryPlatform, string> = {
  esxi: 'VMware ESXi / vSphere',
  proxmox: 'Proxmox VE',
  hyperv: 'Microsoft Hyper-V',
  generic: 'Generic device list',
};

/**
 * Asset types a batch row may declare explicitly. Mirrors the Assets type
 * dropdown; anything else is reported as ignored rather than stored.
 */
export const BATCH_ASSET_TYPES = ['mobile', 'vm', 'workstation', 'server', 'laptop', 'router', 'switch', 'firewall', 'other'] as const;
export type BatchAssetType = (typeof BATCH_ASSET_TYPES)[number];

const DECLARED_TYPE_ALIASES: Record<string, BatchAssetType> = {
  pc: 'workstation',
  computer: 'workstation',
  desktop: 'workstation',
  host: 'workstation',
  'mobile-device': 'mobile',
  mobile_device: 'mobile',
  phone: 'mobile',
  tablet: 'mobile',
  smartphone: 'mobile',
  'virtual-machine': 'vm',
  'virtual machine': 'vm',
};

export function normalizeBatchAssetType(value: unknown): BatchAssetType | undefined {
  const text = cleanText(value)?.toLowerCase();
  if (!text) return undefined;
  return (BATCH_ASSET_TYPES as readonly string[]).includes(text)
    ? text as BatchAssetType
    : DECLARED_TYPE_ALIASES[text];
}

const MOBILE_OS_PATTERN = /android|iphone|ipad|ipados|watchos|kaios|tizen|harmony\s*os|wear\s*os|fuchsia/i;

/** Classifies a guest OS string into a mobile-device asset type, or undefined for PC/other OS. */
export function classifyGuestOs(guestOs: string | undefined): 'mobile' | undefined {
  const text = guestOs?.trim();
  if (!text) return undefined;
  if (MOBILE_OS_PATTERN.test(text)) return 'mobile';
  // Bare "iOS" without another vendor qualifier; "Cisco IOS" stays a network OS.
  if (/(?:^|[^a-z])ios(?:[\s\d._-]|$)/i.test(text) && !/cisco/i.test(text)) return 'mobile';
  return undefined;
}

function cleanText(value: unknown): string | undefined {
  if (value === null || value === undefined) return undefined;
  if (Array.isArray(value)) {
    const joined = value.map(cleanText).filter(Boolean).join(';');
    return joined || undefined;
  }
  if (typeof value === 'object') return undefined;
  const text = String(value).trim();
  return text && text !== 'System.String[]' ? text : undefined;
}

function keyName(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function keyed(record: InputRecord): Map<string, unknown> {
  return new Map(Object.entries(record).map(([key, value]) => [keyName(key), value]));
}

function read(record: Map<string, unknown>, ...aliases: string[]): unknown {
  for (const alias of aliases) {
    const value = record.get(keyName(alias));
    if (value !== undefined && value !== null && cleanText(value) !== '') return value;
  }
  return undefined;
}

function numberValue(value: unknown): number | undefined {
  const text = cleanText(value)?.replaceAll(',', '');
  if (!text) return undefined;
  const parsed = Number(text);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : undefined;
}

function scaledNumber(value: unknown, scale: number): number | undefined {
  const parsed = numberValue(value);
  return parsed === undefined ? undefined : Math.round(parsed * scale);
}

function listValue(value: unknown): string[] {
  const values = Array.isArray(value)
    ? value.flatMap((item) => listValue(item))
    : (cleanText(value) ?? '')
        .replace(/^\{|\}$/g, '')
        .split(/[;,\r\n]+/)
        .map((item) => item.trim());
  return [...new Set(values.filter(Boolean))];
}

function validIp(value: string): boolean {
  const host = value.replace(/^\[|\]$/g, '').split('/')[0];
  if (host.includes(':')) return /^[0-9a-f:.%]+$/i.test(host);
  const octets = host.split('.');
  return octets.length === 4 && octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255);
}

function ipValues(value: unknown): string[] {
  return listValue(value)
    .map((item) => item.replace(/^\[|\]$/g, '').split('/')[0])
    .filter(validIp);
}

function normalizeMac(value: string): string | undefined {
  const compact = value.replace(/[^0-9a-f]/gi, '').toUpperCase();
  if (compact.length !== 12) return undefined;
  return compact.match(/.{2}/g)?.join(':');
}

function macValues(value: unknown): string[] {
  return [...new Set(listValue(value).map(normalizeMac).filter((item): item is string => Boolean(item)))];
}

function jsonValueRecord(record: InputRecord): Record<string, JsonValue> {
  const serialized = JSON.stringify(record, (_key, value) => {
    if (typeof value === 'bigint') return value.toString();
    return value;
  });
  const parsed = JSON.parse(serialized) as JsonValue;
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
    ? parsed as Record<string, JsonValue>
    : {};
}

function identityKey(
  platform: VmInventoryPlatform,
  nativeId: string | undefined,
  inventoryScope: string | undefined,
  hypervisor: string | undefined,
  configPath: string | undefined,
  name: string,
): string {
  const scope = inventoryScope?.trim().toLowerCase();
  if (nativeId) {
    if (scope) return `${platform}:scope:${scope}:id:${nativeId.toLowerCase()}`;
    if (platform === 'esxi' && /^\d+$/.test(nativeId)) {
      if (hypervisor) return `${platform}:host:${hypervisor.toLowerCase()}:id:${nativeId}`;
      if (configPath) return `${platform}:path:${configPath.toLowerCase()}:id:${nativeId}`;
    }
    return `${platform}:id:${nativeId.toLowerCase()}`;
  }
  if (scope) return `${platform}:scope:${scope}:name:${name.toLowerCase()}`;
  if (hypervisor) return `${platform}:host:${hypervisor.toLowerCase()}:name:${name.toLowerCase()}`;
  if (configPath) return `${platform}:path:${configPath.toLowerCase()}`;
  return `${platform}:name:${name.toLowerCase()}`;
}

function normalizeRecord(
  platform: VmInventoryPlatform,
  sourceFormat: VmInventorySourceFormat,
  input: InputRecord,
  options: VmInventoryParseOptions,
  warnings: string[],
): ImportedVmInventory | null {
  const generic = platform === 'generic';
  const fields = keyed(input);
  const name = cleanText(read(fields, 'name', 'vmname', 'displayname', ...(generic ? ['hostname', 'devicename'] : [])));
  if (!name) return null;

  let nativeId = cleanText(read(fields, 'nativeid', 'vmid', 'id'));
  let hypervisor = cleanText(read(fields, 'hypervisor', 'vmhost', 'host', 'node', 'computername'));
  let kind: VmKind = 'virtual-machine';
  let state = cleanText(read(fields, 'state', 'status', 'powerstate'));
  let guestOs = cleanText(read(fields, 'guestos', 'guestid', 'osfullname', 'operatingsystem', 'guest', ...(generic ? ['os'] : [])));
  const declaredTypeSource = read(fields, 'assettype', 'devicetype', ...(generic ? ['type'] : []));
  const assetType = normalizeBatchAssetType(declaredTypeSource);
  if (generic && cleanText(declaredTypeSource) && !assetType) {
    warnings.push(`Ignored unknown asset type "${cleanText(declaredTypeSource)}" for ${name}; use one of: ${BATCH_ASSET_TYPES.join(', ')}.`);
  }
  const userName = cleanText(read(fields, 'user', 'username', 'owner'));
  const cpuCount = numberValue(read(fields, 'cpucount', 'numcpu', 'processorcount', 'maxcpu', 'cpus'));
  let memoryBytes = numberValue(read(fields, 'memorybytes', 'memoryassigned', 'memorystartup', 'maxmem'));
  let diskBytes = numberValue(read(fields, 'diskbytes', 'maxdisk'));
  let version = cleanText(read(fields, 'version', 'hardwareversion', 'vmversion'));
  const generation = cleanText(read(fields, 'generation'));
  let configPath = cleanText(read(fields, 'configpath', 'configurationlocation', 'path', 'file', 'vmxpath'));
  let ipAddresses = ipValues(read(fields, 'ipaddresses', 'ipaddress', 'ips', 'ip'));
  let macAddresses = macValues(read(fields, 'macaddresses', 'macaddress', 'macs', 'mac'));

  if (platform === 'esxi') {
    nativeId = nativeId ?? cleanText(read(fields, 'vmwareid'));
    state = state ?? cleanText(read(fields, 'power'));
    guestOs = guestOs ?? cleanText(read(fields, 'guest os'));
    memoryBytes = scaledNumber(read(fields, 'memorygb'), 1024 ** 3)
      ?? scaledNumber(read(fields, 'memorymb'), 1024 ** 2)
      ?? memoryBytes;
    diskBytes = scaledNumber(read(fields, 'provisionedspacegb', 'diskgb'), 1024 ** 3) ?? diskBytes;
    configPath = configPath ?? cleanText(read(fields, 'vmx'));
  } else if (platform === 'proxmox') {
    const type = cleanText(read(fields, 'type', 'vmtype'))?.toLowerCase();
    if (type === 'lxc' || type === 'container' || type === 'ct') kind = 'container';
    memoryBytes = memoryBytes
      ?? scaledNumber(read(fields, 'memmb', 'memorymb', 'mem(mb)'), 1024 ** 2);
    diskBytes = diskBytes
      ?? scaledNumber(read(fields, 'bootdiskgb', 'diskgb', 'bootdisk(gb)'), 1024 ** 3);
    version = version ?? cleanText(read(fields, 'qemuversion'));
  } else if (platform === 'hyperv') {
    nativeId = nativeId ?? cleanText(read(fields, 'guid'));
    memoryBytes = memoryBytes
      ?? scaledNumber(read(fields, 'memoryassignedm', 'memoryassignedmb', 'memorymb'), 1024 ** 2);
    configPath = configPath ?? cleanText(read(fields, 'configurationpath'));
  }

  if (!hypervisor) hypervisor = options.inventoryScope?.trim() || undefined;
  ipAddresses = [...new Set(ipAddresses)];
  macAddresses = [...new Set(macAddresses)];
  const inventoryScope = options.inventoryScope?.trim() || undefined;

  return {
    schema: VM_INVENTORY_SCHEMA,
    platform,
    kind,
    identityKey: identityKey(platform, nativeId, inventoryScope, hypervisor, configPath, name),
    ...(nativeId ? { nativeId } : {}),
    name,
    ...(inventoryScope ? { inventoryScope } : {}),
    ...(hypervisor ? { hypervisor } : {}),
    ...(state ? { state } : {}),
    ...(guestOs ? { guestOs } : {}),
    ...(assetType ? { assetType } : {}),
    ...(userName ? { userName } : {}),
    ...(cpuCount !== undefined ? { cpuCount } : {}),
    ...(memoryBytes !== undefined ? { memoryBytes } : {}),
    ...(diskBytes !== undefined ? { diskBytes } : {}),
    ...(version ? { version } : {}),
    ...(generation ? { generation } : {}),
    ...(configPath ? { configPath } : {}),
    ipAddresses,
    macAddresses,
    sourceFormat,
    ...(options.sourceFile ? { sourceFile: options.sourceFile } : {}),
    raw: jsonValueRecord(input),
  };
}

function delimiterFor(header: string): string {
  const candidates = [',', '\t', ';'];
  return candidates
    .map((delimiter) => ({ delimiter, count: header.split(delimiter).length - 1 }))
    .sort((left, right) => right.count - left.count)[0].delimiter;
}

export function parseCsv(text: string): InputRecord[] {
  const source = text.replace(/^\uFEFF/, '');
  const delimiter = delimiterFor(source.split(/\r?\n/, 1)[0] ?? '');
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    if (character === '"') {
      if (quoted && source[index + 1] === '"') {
        field += '"';
        index += 1;
      } else {
        quoted = !quoted;
      }
    } else if (character === delimiter && !quoted) {
      row.push(field);
      field = '';
    } else if ((character === '\n' || character === '\r') && !quoted) {
      if (character === '\r' && source[index + 1] === '\n') index += 1;
      row.push(field);
      if (row.some((item) => item.trim())) rows.push(row);
      row = [];
      field = '';
    } else {
      field += character;
    }
  }
  row.push(field);
  if (row.some((item) => item.trim())) rows.push(row);
  if (quoted) throw new Error('CSV contains an unterminated quoted field');
  const headers = rows.shift()?.map((item) => item.trim()) ?? [];
  if (headers.length < 2 || !headers.some((item) => keyName(item) === 'name')) {
    throw new Error('CSV must contain a Name column and at least one additional column');
  }
  return rows.map((values) => Object.fromEntries(headers.map((header, index) => [header, values[index]?.trim() ?? ''])));
}

function fixedColumns(line: string, starts: number[]): string[] {
  return starts.map((start, index) => line.slice(start, starts[index + 1]).trim());
}

function parseEsxiNative(text: string): InputRecord[] {
  const lines = text.split(/\r?\n/).filter((line) => line.trim());
  const headerIndex = lines.findIndex((line) => /\bVmid\b/i.test(line) && /\bGuest OS\b/i.test(line) && /\bVersion\b/i.test(line));
  if (headerIndex < 0) throw new Error('ESXi native input must be output from vim-cmd vmsvc/getallvms');
  const header = lines[headerIndex];
  const starts = [
    header.search(/\bVmid\b/i),
    header.search(/\bName\b/i),
    header.search(/\bFile\b/i),
    header.search(/\bGuest OS\b/i),
    header.search(/\bVersion\b/i),
    header.search(/\bAnnotation\b/i),
  ];
  if (starts.some((value) => value < 0)) throw new Error('ESXi inventory header is incomplete');
  return lines.slice(headerIndex + 1).flatMap((line) => {
    const [vmid, name, file, guestOs, version, annotation] = fixedColumns(line, starts);
    if (!/^\d+$/.test(vmid) || !name) return [];
    return [{ VMid: vmid, Name: name, File: file, GuestOS: guestOs, Version: version, Annotation: annotation }];
  });
}

function parseProxmoxNative(text: string): InputRecord[] {
  const lines = text.split(/\r?\n/).filter((line) => line.trim());
  const headerIndex = lines.findIndex((line) => /\bVMID\b/i.test(line) && /\bNAME\b/i.test(line) && /\bSTATUS\b/i.test(line));
  if (headerIndex < 0) throw new Error('Proxmox native input must be JSON from pvesh or table output from qm list');
  const header = lines[headerIndex];
  const labels = ['VMID', 'NAME', 'STATUS', 'MEM(MB)', 'BOOTDISK(GB)', 'PID'];
  const starts = labels.map((label) => header.toUpperCase().indexOf(label));
  if (starts.slice(0, 3).some((value) => value < 0)) throw new Error('Proxmox VM table header is incomplete');
  const available = starts.filter((value) => value >= 0);
  return lines.slice(headerIndex + 1).flatMap((line) => {
    const values = fixedColumns(line, available);
    if (!/^\d+$/.test(values[0] ?? '') || !values[1]) return [];
    const record: InputRecord = { VMID: values[0], Name: values[1], Status: values[2], Type: 'qemu' };
    if (starts[3] >= 0) record['MEM(MB)'] = values[available.indexOf(starts[3])];
    if (starts[4] >= 0) record['BOOTDISK(GB)'] = values[available.indexOf(starts[4])];
    return [record];
  });
}

function parseHyperVNative(text: string): InputRecord[] {
  const lines = text.split(/\r?\n/);
  const headerIndex = lines.findIndex((line) => /\bName\b/i.test(line) && /\bState\b/i.test(line) && /CPUUsage/i.test(line));
  if (headerIndex < 0) throw new Error('Hyper-V native input must be Get-VM table output, CSV, or ConvertTo-Json output');
  const header = lines[headerIndex];
  const labelPatterns = [/Name/i, /State/i, /CPUUsage/i, /MemoryAssigned/i, /Uptime/i, /Status/i, /Version/i];
  const starts = labelPatterns.map((pattern) => header.search(pattern)).filter((value) => value >= 0);
  return lines.slice(headerIndex + 1).flatMap((line) => {
    if (!line.trim() || /^[-\s]+$/.test(line)) return [];
    const values = fixedColumns(line, starts);
    if (!values[0]) return [];
    return [{
      Name: values[0],
      State: values[1],
      'CPUUsage(%)': values[2],
      'MemoryAssigned(M)': values[3],
      Uptime: values[4],
      Status: values[5],
      Version: values[6],
    }];
  });
}

const HOSTNAME_LIKE = /^[a-z0-9][a-z0-9._-]{0,63}$/i;

/** `adb devices [-l]` output: "List of devices attached" then one `serial state [key:value…]` line per device. */
function parseAdbDevices(lines: string[]): InputRecord[] | null {
  const headerIndex = lines.findIndex((line) => /^list of devices attached$/i.test(line.trim()));
  if (headerIndex < 0) return null;
  return lines.slice(headerIndex + 1).flatMap((line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('*')) return [];
    const [serial, state = 'device', ...qualifiers] = trimmed.split(/\s+/);
    if (!serial) return [];
    const model = qualifiers.find((item) => item.startsWith('model:'))?.slice('model:'.length);
    return [{
      Id: serial,
      Name: model ? model.replaceAll('_', ' ') : serial,
      State: state,
      GuestOS: 'Android',
      Hypervisor: serial.startsWith('emulator-') || serial.includes(':5555') ? 'Android emulator' : 'USB-connected device',
      Qualifiers: qualifiers.join(' '),
    }];
  });
}

/**
 * Generic batch list, one device per line. Columns are positional
 * `name, ip, mac, os, type` (trailing columns optional); a line of bare
 * hostname tokens is treated as several devices.
 */
function parseGenericNative(text: string): InputRecord[] {
  const lines = text.split(/\r?\n/);
  const adb = parseAdbDevices(lines);
  if (adb) return adb;
  return lines.flatMap((line) => {
    const row = line.trim();
    if (!row) return [];
    const columns = row.split(/[,;\t]/).map((column) => column.trim());
    if (columns.length === 1) {
      const tokens = columns[0].split(/\s+/);
      if (tokens.length > 1) {
        const joined = tokens.slice(1).join(';');
        const ipAddress = ipValues(joined)[0];
        const macAddress = macValues(joined)[0];
        if (ipAddress || macAddress) {
          return [{ Name: tokens[0], ...(ipAddress ? { IPAddress: ipAddress } : {}), ...(macAddress ? { MacAddress: macAddress } : {}) }];
        }
      }
      return [{ Name: columns[0] }];
    }
    if (columns.slice(1).every((column) => !column || HOSTNAME_LIKE.test(column)) && !columns.slice(1).some((column) => validIp(column))) {
      return columns.filter(Boolean).map((column) => ({ Name: column }));
    }
    return [{
      Name: columns[0],
      ...(columns[1] ? { IPAddress: columns[1] } : {}),
      ...(columns[2] ? { MacAddress: columns[2] } : {}),
      ...(columns[3] ? { GuestOS: columns[3] } : {}),
      ...(columns[4] ? { AssetType: columns[4] } : {}),
    }];
  });
}

function jsonRecords(text: string): InputRecord[] {
  const parsed = JSON.parse(text) as unknown;
  const value = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
    ? ((parsed as Record<string, unknown>).data ?? (parsed as Record<string, unknown>).value ?? parsed)
    : parsed;
  const rows = Array.isArray(value) ? value : [value];
  return rows.filter((row): row is InputRecord => Boolean(row) && typeof row === 'object' && !Array.isArray(row));
}

function sourceFormat(text: string, sourceFile?: string): VmInventorySourceFormat {
  const trimmed = text.trimStart();
  if (trimmed.startsWith('{') || trimmed.startsWith('[') || sourceFile?.toLowerCase().endsWith('.json')) return 'json';
  const firstLine = trimmed.split(/\r?\n/, 1)[0] ?? '';
  if (sourceFile?.toLowerCase().endsWith('.csv')
    || ((firstLine.includes(',') || firstLine.includes('\t') || firstLine.includes(';'))
      && firstLine.toLowerCase().includes('name'))) return 'csv';
  return 'native';
}

export function parseVmInventory(
  platform: VmInventoryPlatform,
  text: string,
  options: VmInventoryParseOptions = {},
): ParsedVmInventory {
  if (!text.trim()) throw new Error('Paste or select a VM inventory first');
  const format = sourceFormat(text, options.sourceFile);
  let inputs: InputRecord[];
  try {
    inputs = format === 'json'
      ? jsonRecords(text)
      : format === 'csv'
        ? parseCsv(text)
        : platform === 'esxi'
          ? parseEsxiNative(text)
          : platform === 'proxmox'
            ? parseProxmoxNative(text)
            : platform === 'hyperv'
              ? parseHyperVNative(text)
              : parseGenericNative(text);
  } catch (reason) {
    if (reason instanceof SyntaxError) throw new Error(`Invalid JSON VM inventory: ${reason.message}`);
    throw reason;
  }

  const warnings: string[] = [];
  if (platform === 'proxmox') {
    const skipped = inputs.filter((input) => {
      const type = cleanText(read(keyed(input), 'type'));
      return type && !['qemu', 'lxc', 'vm', 'container', 'ct'].includes(type.toLowerCase());
    }).length;
    if (skipped) warnings.push(`Skipped ${skipped} Proxmox cluster resource(s) that were not virtual machines or containers.`);
    inputs = inputs.filter((input) => {
      const type = cleanText(read(keyed(input), 'type'));
      return !type || ['qemu', 'lxc', 'vm', 'container', 'ct'].includes(type.toLowerCase());
    });
  }

  const records: ImportedVmInventory[] = [];
  const identities = new Set<string>();
  let missingNames = 0;
  let duplicates = 0;
  for (const input of inputs) {
    const record = normalizeRecord(platform, format, input, options, warnings);
    if (!record) {
      missingNames += 1;
      continue;
    }
    if (identities.has(record.identityKey)) {
      duplicates += 1;
      continue;
    }
    identities.add(record.identityKey);
    records.push(record);
  }
  if (missingNames) warnings.push(`Skipped ${missingNames} row(s) without a VM name.`);
  if (duplicates) warnings.push(`Skipped ${duplicates} duplicate VM identity row(s).`);
  if (format === 'native' && platform === 'hyperv') {
    warnings.push('The default Get-VM table does not include VMId. Set an inventory scope or use the documented CSV/JSON command for stronger re-import matching.');
  }
  if (format === 'native' && platform === 'esxi' && !options.inventoryScope) {
    warnings.push('ESXi VMid values are host-local. Set the inventory scope to the ESXi host name for reliable matching across repeated imports.');
  }
  if (!records.length) throw new Error(platform === 'generic'
    ? 'No device records were recognized — provide a name for each device'
    : `No ${PLATFORM_LABELS[platform]} VM records were recognized`);
  return {
    platform,
    sourceFormat: format,
    ...(options.sourceFile ? { sourceFile: options.sourceFile } : {}),
    ...(options.inventoryScope?.trim() ? { inventoryScope: options.inventoryScope.trim() } : {}),
    records,
    warnings,
  };
}

export function readStoredVmInventory(properties: string | null | undefined): ImportedVmInventory | null {
  if (!properties?.trim()) return null;
  try {
    const parsed = JSON.parse(properties) as Partial<ImportedVmInventory>;
    return parsed.schema === VM_INVENTORY_SCHEMA
      && ['esxi', 'proxmox', 'hyperv', 'generic'].includes(parsed.platform ?? '')
      && typeof parsed.identityKey === 'string'
      && typeof parsed.name === 'string'
      ? parsed as ImportedVmInventory
      : null;
  } catch {
    return null;
  }
}

function ipv4Number(address: string): number | null {
  const octets = address.split('.');
  if (octets.length !== 4 || octets.some((octet) => !/^\d{1,3}$/.test(octet) || Number(octet) > 255)) return null;
  return octets.reduce((value, octet) => (value * 256) + Number(octet), 0) >>> 0;
}

function networkForIp(networks: Network[], address: string): Network | undefined {
  const ip = ipv4Number(address);
  if (ip === null) return undefined;
  const matches = networks.filter((network) => {
    const [baseText, prefixText] = network.subnet.split('/');
    const base = ipv4Number(baseText);
    const prefix = Number(prefixText);
    if (base === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
    const size = 2 ** (32 - prefix);
    return Math.floor(ip / size) === Math.floor(base / size);
  });
  return matches.sort((left, right) => Number(right.subnet.split('/')[1]) - Number(left.subnet.split('/')[1]))[0];
}

function existingAssetFor(
  record: ImportedVmInventory,
  assets: Asset[],
): { asset: Asset; stored: ImportedVmInventory } | undefined {
  const imported = assets
    .map((asset) => ({ asset, stored: readStoredVmInventory(asset.properties) }))
    .filter((item): item is { asset: Asset; stored: ImportedVmInventory } => Boolean(item.stored));
  const exact = imported.find((item) => item.stored.identityKey === record.identityKey);
  if (exact) return exact;
  if (record.nativeId) {
    const sameId = imported.filter((item) =>
      item.stored.platform === record.platform
      && item.stored.nativeId?.toLowerCase() === record.nativeId?.toLowerCase()
      && (!item.stored.inventoryScope
        || !record.inventoryScope
        || item.stored.inventoryScope.toLowerCase() === record.inventoryScope.toLowerCase()));
    if (sameId.length === 1) return sameId[0];
  }
  const sameName = imported.filter((item) =>
    item.stored.platform === record.platform
    && item.stored.name.toLowerCase() === record.name.toLowerCase()
    && (item.stored.inventoryScope ?? item.stored.hypervisor ?? '').toLowerCase()
      === (record.inventoryScope ?? record.hypervisor ?? '').toLowerCase());
  return sameName.length === 1 ? sameName[0] : undefined;
}

function storedProperties(record: ImportedVmInventory, existing?: Asset): ImportedVmInventory {
  const stored = readStoredVmInventory(existing?.properties);
  let legacyProperties = stored?.legacyProperties;
  if (!stored && existing?.properties?.trim()) {
    try {
      legacyProperties = JSON.parse(existing.properties) as JsonValue;
    } catch {
      legacyProperties = existing.properties;
    }
  }
  return legacyProperties === undefined ? record : { ...record, legacyProperties };
}

function change(
  changes: PartialChange[],
  entityType: string,
  targetId: string,
  values: Record<string, JsonValue | undefined>,
): void {
  changes.push({
    change_id: `vm-inventory-${entityType}-${targetId}`,
    entity_type: entityType,
    operation: 'upsert',
    target_id: targetId,
    values,
  });
}

export function buildVmInventoryImport(
  parsed: ParsedVmInventory,
  inventory: VmImportInventory,
): BuiltVmInventoryImport {
  const changes: PartialChange[] = [];
  const warnings = [...parsed.warnings];
  for (const record of parsed.records) {
    const matched = existingAssetFor(record, inventory.assets);
    const existing = matched?.asset;
    const assetId = existing?.id ?? uuidv4();
    const desiredNics = Math.max(record.ipAddresses.length, record.macAddresses.length);
    const existingInventoryNics = inventory.networkInterfaces.filter((item) =>
      item.asset_id === assetId && /^Inventory NIC \d+$/.test(item.name));
    const existingPrimary = inventory.networkInterfaces.find((item) => item.asset_id === assetId && item.is_primary);
    const preserveManualPrimary = Boolean(existingPrimary && !/^Inventory NIC \d+$/.test(existingPrimary.name));
    const retainStaleProjection = desiredNics === 0 && existingInventoryNics.length > 0;
    const primaryIp = preserveManualPrimary || retainStaleProjection
      ? existing?.ip_address ?? ''
      : record.ipAddresses[0] ?? '';
    const primaryMac = preserveManualPrimary || retainStaleProjection
      ? existing?.mac_address ?? null
      : record.macAddresses[0] ?? null;
    const primaryNetwork = primaryIp ? networkForIp(inventory.networks, primaryIp) : undefined;
    change(changes, 'asset', assetId, {
      network_id: primaryNetwork?.id ?? existing?.network_id ?? null,
      name: record.name,
      ip_address: primaryIp,
      mac_address: primaryMac,
      asset_type: record.assetType
        ?? classifyGuestOs(record.guestOs)
        ?? existing?.asset_type
        ?? (parsed.platform === 'generic' ? 'workstation' : 'vm'),
      os: record.guestOs ?? existing?.os ?? null,
      user_name: record.userName ?? existing?.user_name ?? null,
      compromise_status: existing?.compromise_status ?? 'unknown',
      investigation_status: existing?.investigation_status ?? 'not_started',
      properties: storedProperties(record, existing) as unknown as JsonValue,
      scan_results: existing?.scan_results ?? null,
    });

    for (let index = 0; index < desiredNics; index += 1) {
      const name = `Inventory NIC ${index + 1}`;
      const existingInterface = existingInventoryNics.find((item) => item.name === name);
      const ipAddress = record.ipAddresses[index] ?? '';
      const network = ipAddress ? networkForIp(inventory.networks, ipAddress) : undefined;
      change(changes, 'network_interface', existingInterface?.id ?? uuidv4(), {
        asset_id: assetId,
        name,
        ip_address: ipAddress,
        mac_address: record.macAddresses[index] ?? null,
        network_id: network?.id ?? existingInterface?.network_id ?? null,
        is_primary: !preserveManualPrimary && index === 0,
      });
    }
    if (existingInventoryNics.length > desiredNics) {
      warnings.push(`${record.name}: ${existingInventoryNics.length - desiredNics} older inventory NIC(s) were retained because reviewed partial imports never delete evidence.`);
    }
  }
  if (!changes.length) throw new Error('The VM inventory did not produce any importable assets');
  const sourceLabel = parsed.platform === 'generic'
    ? `Batch device list${parsed.inventoryScope ? ` (${parsed.inventoryScope})` : ''}`
    : `${PLATFORM_LABELS[parsed.platform]} VM inventory${parsed.inventoryScope ? ` (${parsed.inventoryScope})` : ''}`;
  return {
    document: JSON.stringify({
      format: 'dfir-investigator-partial',
      format_version: 1,
      case_id: inventory.caseId,
      source: sourceLabel,
      changes,
    }, null, 2),
    warnings,
    changeCount: changes.length,
  };
}

export function platformLabel(platform: VmInventoryPlatform): string {
  return PLATFORM_LABELS[platform];
}

export interface VmHostEntry {
  asset: Asset;
  inventory: ImportedVmInventory;
}

export interface VmHostGroup {
  /** Hypervisor / node the VMs run on; empty when none was recorded. */
  host: string;
  platforms: VmInventoryPlatform[];
  entries: VmHostEntry[];
}

const HOST_COLLATOR = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

/**
 * Groups every asset that carries an imported VM inventory under the
 * hypervisor it runs on (`hypervisor`, falling back to the inventory scope).
 * Hosts sort by name with VMs sorted by name inside each host; hosts without
 * a recorded name collect at the end.
 */
export function groupVmsByHost(assets: Asset[]): VmHostGroup[] {
  const groups = new Map<string, VmHostGroup>();
  for (const asset of assets) {
    const inventory = readStoredVmInventory(asset.properties);
    if (!inventory) continue;
    const host = (inventory.hypervisor ?? inventory.inventoryScope ?? '').trim();
    const group = groups.get(host.toLowerCase()) ?? { host, platforms: [], entries: [] };
    if (!group.platforms.includes(inventory.platform)) group.platforms.push(inventory.platform);
    group.entries.push({ asset, inventory });
    groups.set(host.toLowerCase(), group);
  }
  return [...groups.values()].map((group) => ({
    ...group,
    entries: [...group.entries].sort((left, right) =>
      HOST_COLLATOR.compare(left.inventory.name || left.asset.name, right.inventory.name || right.asset.name)
      || left.asset.id.localeCompare(right.asset.id)),
  })).sort((left, right) =>
    (left.host ? 0 : 1) - (right.host ? 0 : 1) || HOST_COLLATOR.compare(left.host, right.host));
}

/**
 * Builds the XMind topic tree for the VM inventory: one branch per hypervisor
 * host, one leaf per VM titled `hostname · IP` (plus compromise status), with
 * the power state as an XMind label. Returns null when no VMs are recorded.
 */
export function buildVmHostTree(assets: Asset[]): XmindTopic | null {
  const groups = groupVmsByHost(assets);
  if (!groups.length) return null;
  const total = groups.reduce((sum, group) => sum + group.entries.length, 0);
  return {
    id: 'vm-inventory-root',
    title: `VM inventory · ${total} ${total === 1 ? 'VM' : 'VMs'} on ${groups.length} ${groups.length === 1 ? 'host' : 'hosts'}`,
    children: groups.map((group) => ({
      id: `vm-host-${group.host.toLowerCase().replace(/[^a-z0-9._-]+/g, '-') || 'unassigned'}`,
      title: `${group.host || 'Unassigned host'} · ${group.entries.length} ${group.entries.length === 1 ? 'VM' : 'VMs'}`,
      labels: group.platforms.map(platformLabel),
      children: group.entries.map(({ asset, inventory }) => {
        const addresses = inventory.ipAddresses.length ? inventory.ipAddresses : (asset.ip_address ? [asset.ip_address] : []);
        const status = asset.compromise_status === 'suspected' || asset.compromise_status === 'infected'
          ? ` · ${asset.compromise_status}`
          : '';
        return {
          id: `vm-${asset.id}`,
          title: `${inventory.name || asset.name} · ${addresses.join(', ') || 'No IP'}${status}`,
          ...(inventory.state ? { labels: [inventory.state] } : {}),
        };
      }),
    })),
  };
}
