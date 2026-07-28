import { v4 as uuidv4 } from 'uuid';
import type { Asset, JsonValue, Network, NetworkInterface } from '@/types';

export type VmInventoryPlatform = 'esxi' | 'proxmox' | 'hyperv';
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
};

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
): ImportedVmInventory | null {
  const fields = keyed(input);
  const name = cleanText(read(fields, 'name', 'vmname', 'displayname'));
  if (!name) return null;

  let nativeId = cleanText(read(fields, 'nativeid', 'vmid', 'id'));
  let hypervisor = cleanText(read(fields, 'hypervisor', 'vmhost', 'host', 'node', 'computername'));
  let kind: VmKind = 'virtual-machine';
  let state = cleanText(read(fields, 'state', 'status', 'powerstate'));
  let guestOs = cleanText(read(fields, 'guestos', 'guestid', 'osfullname', 'operatingsystem', 'guest'));
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
  } else {
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
            : parseHyperVNative(text);
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
    const record = normalizeRecord(platform, format, input, options);
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
  if (!records.length) throw new Error(`No ${PLATFORM_LABELS[platform]} VM records were recognized`);
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
      && ['esxi', 'proxmox', 'hyperv'].includes(parsed.platform ?? '')
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
      asset_type: 'vm',
      os: record.guestOs ?? existing?.os ?? null,
      user_name: existing?.user_name ?? null,
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
  return {
    document: JSON.stringify({
      format: 'dfir-investigator-partial',
      format_version: 1,
      case_id: inventory.caseId,
      source: `${PLATFORM_LABELS[parsed.platform]} VM inventory${parsed.inventoryScope ? ` (${parsed.inventoryScope})` : ''}`,
      changes,
    }, null, 2),
    warnings,
    changeCount: changes.length,
  };
}

export function platformLabel(platform: VmInventoryPlatform): string {
  return PLATFORM_LABELS[platform];
}
