import { describe, expect, it } from 'vitest';
import { exportFileName, toCsv, toTsv } from './list-export';

describe('list export', () => {
  it('writes RFC 4180 CSV and quotes delimiters, quotes, and line breaks', () => {
    const csv = toCsv({
      header: ['Name', 'Note'],
      rows: [['APP01', 'Finance owns it, "probably"'], ['DB01', 'line one\nline two'], ['EMPTY', null]],
    });
    expect(csv).toBe('Name,Note\r\nAPP01,"Finance owns it, ""probably"""\r\nDB01,"line one\nline two"\r\nEMPTY,\r\n');
  });

  it('neutralizes cells a spreadsheet would run as formulas', () => {
    const csv = toCsv({ header: ['Value'], rows: [['=HYPERLINK("http://x")'], ['+1'], ['-cmd'], ['@SUM(A1)'], ['10.0.0.5']] });
    expect(csv.split('\r\n').slice(1, 6)).toEqual([`"'=HYPERLINK(""http://x"")"`, "'+1", "'-cmd", "'@SUM(A1)", '10.0.0.5']);
  });

  it('copies as tab-separated rows with in-cell tabs and newlines flattened', () => {
    expect(toTsv({ header: ['A', 'B'], rows: [['x\ty', 'two\r\nlines'], [1, true]] })).toBe('A\tB\nx y\ttwo lines\n1\ttrue');
  });

  it('builds a dated, filename-safe export name', () => {
    expect(exportFileName('IR 42 / Client', 'assets', 'csv')).toMatch(/^ir-42-client-assets-\d{4}-\d{2}-\d{2}\.csv$/);
    expect(exportFileName(undefined, 'timeline', 'csv')).toMatch(/^case-timeline-/);
  });
});
