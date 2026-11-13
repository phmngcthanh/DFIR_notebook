/**
 * Recognizes indicators in pasted text so a reverse engineer's or log
 * analyst's list goes into the case in one step: defanged values are
 * refanged, each value gets a type, and duplicates collapse.
 *
 * Types mirror the core's `IOC_TYPES` (db.rs). Detection is a suggestion;
 * the investigator can retype any value before it is saved.
 */
import { isIpAddress } from '@/lib/subnet-match';

export const IOC_TYPES = ['IP', 'Hash', 'Domain', 'URL', 'Email', 'Registry', 'Mutex', 'FilePath', 'FileName', 'Process'] as const;
export type IocType = (typeof IOC_TYPES)[number];

export const IOC_TYPE_LABELS: Record<IocType, string> = {
  IP: 'IP',
  Hash: 'Hash',
  Domain: 'Domain',
  URL: 'URL',
  Email: 'Email',
  Registry: 'Registry',
  Mutex: 'Mutex',
  FilePath: 'File path',
  FileName: 'File name',
  Process: 'Process',
};

export function iocTypeLabel(type: string): string {
  return IOC_TYPE_LABELS[type as IocType] ?? type;
}

/** Undo common defanging: hxxp(s), [.], (.), {.}, [dot], [:], [://], [@], [at]. */
export function refang(value: string): string {
  return value
    .trim()
    .replace(/\[\s*:\s*\/\s*\/\s*\]/g, '://')
    .replace(/\[\s*:\s*\]/g, ':')
    .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)|\{dot\}/gi, '.')
    .replace(/\[\s*@\s*\]|\[at\]|\(at\)|\{at\}/gi, '@')
    .replace(/\[\s*\/\s*\]/g, '/')
    .replace(/\bh(?:xx|XX|\*\*)p(s?)(?=:\/\/)/g, 'http$1')
    .replace(/\bfxp(?=:\/\/)/gi, 'ftp');
}

/** True when the original text was deliberately defanged, which marks it as an indicator. */
export function wasDefanged(value: string): boolean {
  return refang(value) !== value.trim();
}

const HASH = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$/i;
const URL_PATTERN = /^(?:https?|ftp):\/\/[^\s/$.?#][^\s]*$/i;
const EMAIL = /^[^\s@]+@[^\s@]+\.[a-z]{2,63}$/i;
const DOMAIN = /^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/i;
const REGISTRY = /^(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)(?:\\|:\\)/i;
const WINDOWS_PATH = /^(?:[a-z]:\\|\\\\[^\\\s]+\\|%[a-z_]+%\\)/i;
const UNIX_PATH = /^\/(?:[^/\s]+\/)+[^/\s]*$|^~\/[^\s]+$/;
/** Extensions that make `name.ext` a file name rather than a domain. */
const FILE_EXTENSIONS = new Set([
  'exe', 'dll', 'sys', 'scr', 'com', 'bat', 'cmd', 'ps1', 'psm1', 'psd1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh',
  'hta', 'lnk', 'msi', 'msp', 'jar', 'py', 'sh', 'elf', 'so', 'dylib', 'bin', 'dat', 'tmp', 'iso', 'img', 'vhd', 'vhdx',
  'doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'pptm', 'pdf', 'rtf', 'one', 'zip', 'rar', '7z', 'gz',
  'tar', 'cab', 'apk', 'ipa', 'dmg', 'pkg', 'deb', 'rpm', 'txt', 'log', 'csv', 'ini', 'cfg', 'xml', 'json', 'db',
]);

/** Strip wrapping quotes, brackets, and trailing sentence punctuation from a token. */
function cleanToken(token: string): string {
  let value = token.trim();
  value = value.replace(/^[("'`<{]+/, '').replace(/[)"'`>},;!?]+$/, '');
  // A sentence-final period, but not a defanged or real trailing label dot.
  value = value.replace(/\.+$/, '');
  return value;
}

/** The IOC type a single value most likely is, or null when nothing fits. */
export function detectIocType(raw: string): IocType | null {
  const value = refang(cleanToken(raw));
  if (!value || value.length > 2048) return null;
  if (isIpAddress(value)) return 'IP';
  if (HASH.test(value)) return 'Hash';
  if (URL_PATTERN.test(value)) return 'URL';
  if (EMAIL.test(value)) return 'Email';
  if (REGISTRY.test(value)) return 'Registry';
  if (WINDOWS_PATH.test(value) || UNIX_PATH.test(value)) return 'FilePath';
  const lastLabel = value.split('.').pop()?.toLowerCase() ?? '';
  if (/^[^\\/\s]+\.[a-z0-9]{1,5}$/i.test(value) && FILE_EXTENSIONS.has(lastLabel)) return 'FileName';
  if (DOMAIN.test(value)) return 'Domain';
  return null;
}

/** The form stored in the case: refanged, and lower-cased where case carries no meaning. */
export function normalizeIocValue(type: IocType | string, raw: string): string {
  const value = refang(cleanToken(raw));
  switch (type) {
    case 'Domain':
      return value.toLowerCase().replace(/\.$/, '');
    case 'Hash':
    case 'Email':
      return value.toLowerCase();
    default:
      return value;
  }
}

/** Key for "is this the same indicator?" — type plus case-insensitive value. */
export function iocKey(type: IocType | string, value: string): string {
  return `${type}|${normalizeIocValue(type, value).toLowerCase()}`;
}

export interface IocCandidate {
  /** Refanged value as it will be stored. */
  value: string;
  /** Text as it appeared in the paste. */
  original: string;
  type: IocType | null;
  defanged: boolean;
}

/**
 * Report labels that say what follows: "Mutex: X", "Process: svc.exe",
 * "SHA256: …". The label is the analyst's own statement.
 */
const LABELLED_TYPES: [RegExp, IocType][] = [
  [/^mutex(?:es)?(?: names?)?$/i, 'Mutex'],
  [/^process(?:es)?(?: names?)?$/i, 'Process'],
  [/^(?:registry(?: keys?| values?)?|reg keys?|run keys?)$/i, 'Registry'],
  [/^(?:file ?paths?|paths?)$/i, 'FilePath'],
  [/^(?:file ?names?|files?|dropped files?)$/i, 'FileName'],
  [/^(?:hash(?:es)?|md5|sha-?1|sha-?256|sha-?512)$/i, 'Hash'],
  [/^domains?$/i, 'Domain'],
  [/^(?:ips?|ip addresses?|ipv[46])$/i, 'IP'],
  [/^(?:urls?|uris?)$/i, 'URL'],
  [/^(?:e-?mails?|e-?mail addresses?|senders?)$/i, 'Email'],
];
/** Detection cannot recognize these, so the label decides. For the rest a detected type wins ("File: C:\x.exe" is a path). */
const LABEL_DECIDES = new Set<IocType>(['Mutex', 'Process']);
/** Values of these types may contain commas, so a labelled line holds exactly one. */
const ONE_VALUE_PER_LINE = new Set<IocType>(['FilePath', 'Registry', 'Process']);

/** "Label: value[, value…]" with a label that names an indicator type, or null. */
function labelledValues(line: string): { type: IocType; values: string[] } | null {
  // A space after the colon keeps "C:\path" and "hxxps://" from reading as labels.
  const match = /^([a-z][a-z0-9 -]{0,23}?)\s*:\s+(\S.*)$/i.exec(line);
  if (!match) return null;
  const type = LABELLED_TYPES.find(([pattern]) => pattern.test(match[1].trim()))?.[1];
  if (!type) return null;
  const rest = match[2].trim();
  const values = ONE_VALUE_PER_LINE.has(type) ? [rest] : rest.split(/\s*[,;]\s*/);
  return { type, values: values.filter(Boolean) };
}

/**
 * Pull indicators out of pasted text. A line holding a single value is taken
 * whole (so a path with spaces survives); a line labelled with a type
 * ("Mutex: X") takes its type from the label; otherwise every recognizable
 * token on the line is extracted. Lines with one unrecognized token are kept
 * with no type (mutex and process names look like anything), prose is ignored.
 */
export function extractIocCandidates(text: string): IocCandidate[] {
  const seen = new Set<string>();
  const candidates: IocCandidate[] = [];
  const add = (original: string, type: IocType | null) => {
    const value = type ? normalizeIocValue(type, original) : refang(cleanToken(original));
    if (!value) return;
    const key = type ? iocKey(type, value) : `?|${value.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    candidates.push({ value, original: original.trim(), type, defanged: wasDefanged(cleanToken(original)) });
  };
  for (const rawLine of text.split(/\r?\n/)) {
    // Drop list bullets and numbering a report might carry.
    const line = rawLine.trim().replace(/^(?:[-*•]|\d+[.)])\s+/, '');
    if (!line) continue;
    const whole = detectIocType(line);
    if (whole) {
      add(line, whole);
      continue;
    }
    const labelled = labelledValues(line);
    if (labelled) {
      for (const value of labelled.values) {
        add(value, LABEL_DECIDES.has(labelled.type) ? labelled.type : detectIocType(value) ?? labelled.type);
      }
      continue;
    }
    const tokens = line.split(/[\s,;|]+/).filter(Boolean);
    const detected = tokens.map((token) => [token, detectIocType(token)] as const).filter(([, type]) => type !== null);
    if (detected.length) {
      for (const [token, type] of detected) add(token, type);
    } else if (tokens.length === 1) {
      add(tokens[0], null);
    }
  }
  return candidates;
}
