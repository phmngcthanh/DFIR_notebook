/**
 * Turns the list an investigator is looking at — already filtered and sorted —
 * into text that leaves the app: a CSV file for spreadsheets and reports, or
 * tab-separated text on the clipboard for pasting into a chat, ticket, or
 * spreadsheet cell range.
 */

export type ListCell = string | number | boolean | null | undefined;

export interface ListTable {
  header: string[];
  rows: ListCell[][];
}

function cellText(value: ListCell): string {
  if (value === null || value === undefined) return '';
  return String(value);
}

/**
 * Spreadsheet programs execute a cell that starts with `=`, `+`, `-`, `@`, tab,
 * or carriage return as a formula. Case data is attacker-influenced (hostnames,
 * log messages, IOCs), so such cells are prefixed with an apostrophe.
 */
function neutralizeFormula(text: string): string {
  return /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
}

function csvField(value: ListCell): string {
  const text = neutralizeFormula(cellText(value));
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

/** RFC 4180 CSV with CRLF line endings and a header row. */
export function toCsv(table: ListTable): string {
  return [table.header, ...table.rows].map((row) => row.map(csvField).join(',')).join('\r\n') + '\r\n';
}

/** Tab-separated rows; tabs and line breaks inside a cell become spaces. */
export function toTsv(table: ListTable): string {
  return [table.header, ...table.rows]
    .map((row) => row.map((value) => neutralizeFormula(cellText(value).replace(/[\t\r\n]+/g, ' '))).join('\t'))
    .join('\n');
}

/** Copy text to the clipboard, falling back to a hidden textarea where the async API is unavailable (plain HTTP). */
export async function copyText(text: string): Promise<void> {
  if (navigator.clipboard?.writeText && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  area.style.position = 'fixed';
  area.style.opacity = '0';
  document.body.appendChild(area);
  area.select();
  try {
    if (!document.execCommand('copy')) throw new Error('The browser refused to copy');
  } finally {
    area.remove();
  }
}

/** A filename-safe stem with today's date, e.g. `ir-42-assets-2026-11-11.csv`. */
export function exportFileName(caseName: string | undefined, list: string, extension: string): string {
  const stem = (caseName ?? 'case').trim().toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'case';
  return `${stem}-${list}-${new Date().toISOString().slice(0, 10)}.${extension}`;
}
