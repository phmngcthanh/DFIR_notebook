import { describe, expect, it } from 'vitest';
import { fromLocalInput, observedLabel, originLabel, relationPhrase, relationTitle, toLocalInput } from './environment';

describe('relations', () => {
  it('reads a stored relation as a sentence, from either side', () => {
    expect(relationPhrase('runs_on')).toBe('runs on');
    expect(relationPhrase('runs_on', 'in')).toBe('hosts');
    expect(relationPhrase('something-new')).toBe('is related to');
    expect(relationTitle({ source_name: 'APP01', target_name: 'ESX01', relation_type: 'runs_on' })).toBe('APP01 runs on ESX01');
  });

  it('gives no title to anything that is not a named relation', () => {
    expect(relationTitle({ source_name: 'APP01', relation_type: 'runs_on' })).toBeNull();
    expect(relationTitle({ name: 'APP01' })).toBeNull();
    expect(relationTitle(null)).toBeNull();
    expect(relationTitle('APP01 runs on ESX01')).toBeNull();
  });
});

describe('origin and time helpers', () => {
  it('names where an asset came from, and treats anything unknown as not recorded', () => {
    expect(originLabel('discovered')).toBe('Discovered by us');
    expect(originLabel('client_inventory')).toBe("In the client's inventory");
    expect(originLabel(undefined)).toBe('Not recorded');
    expect(originLabel('rumour')).toBe('Not recorded');
  });

  it('round-trips a stored time through the minute-precision date field', () => {
    const stored = '2026-11-12T09:30:00.000Z';
    expect(toLocalInput(stored)).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/);
    expect(fromLocalInput(toLocalInput(stored))).toBe(stored);
    expect(toLocalInput(null)).toBe('');
    expect(toLocalInput('not a time')).toBe('');
    expect(fromLocalInput('')).toBe('');
    expect(fromLocalInput('not a time')).toBe('');
  });

  it('shows nothing for a missing or unreadable observation time', () => {
    expect(observedLabel(undefined)).toBe('');
    expect(observedLabel('nope')).toBe('');
    expect(observedLabel('2026-11-12T09:30:00.000Z')).toMatch(/2026/);
  });
});
