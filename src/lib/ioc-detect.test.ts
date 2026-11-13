import { describe, expect, it } from 'vitest';
import { detectIocType, extractIocCandidates, iocKey, normalizeIocValue, refang } from './ioc-detect';

describe('refang', () => {
  it('undoes the common defanging styles', () => {
    expect(refang('hxxps[:]//cdn.bad[.]site/x.ps1')).toBe('https://cdn.bad.site/x.ps1');
    expect(refang('hxxp://evil(.)example/a')).toBe('http://evil.example/a');
    expect(refang('203[.]0[.]113[.]9')).toBe('203.0.113.9');
    expect(refang('ops[at]evil[dot]example')).toBe('ops@evil.example');
    expect(refang('plain.example')).toBe('plain.example');
  });
});

describe('detectIocType', () => {
  it.each([
    ['10.0.0.15', 'IP'],
    ['2001:db8::5', 'IP'],
    ['44d88612fea8a8f36de82e1278abb02f', 'Hash'],
    ['3395856ce81f2b7382dee72602f798b642f14140', 'Hash'],
    ['hxxps://cdn.bad[.]site/stage2.ps1', 'URL'],
    ['ops@evil.example', 'Email'],
    ['HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'Registry'],
    ['C:\\Users\\Public\\svc.exe', 'FilePath'],
    ['\\\\fileserver\\share\\drop.dll', 'FilePath'],
    ['/tmp/.x/payload', 'FilePath'],
    ['invoice.pdf.exe', 'FileName'],
    ['evil[.]example', 'Domain'],
    ['update.bad-cdn.co.uk', 'Domain'],
  ])('%s is %s', (value, type) => {
    expect(detectIocType(value)).toBe(type);
  });

  it('leaves prose and bare names untyped', () => {
    expect(detectIocType('the')).toBeNull();
    expect(detectIocType('Global\\MsWinZonesCacheCounterMutexA')).toBeNull();
  });
});

describe('extractIocCandidates', () => {
  it('pulls typed indicators out of a pasted report, refanged and without duplicates', () => {
    const candidates = extractIocCandidates([
      '- C2: hxxps://cdn.bad[.]site/stage2.ps1 and evil[.]example',
      '- Dropper hash 44D88612FEA8A8F36DE82E1278ABB02F (same as 44d88612fea8a8f36de82e1278abb02f)',
      'C:\\Program Files\\Common Files\\svc host.exe',
      'MsWinZonesCacheCounterMutexA',
      'Contacted the client about this today.',
    ].join('\n'));
    expect(candidates.map((item) => [item.type, item.value])).toEqual([
      ['URL', 'https://cdn.bad.site/stage2.ps1'],
      ['Domain', 'evil.example'],
      ['Hash', '44d88612fea8a8f36de82e1278abb02f'],
      ['FilePath', 'C:\\Program Files\\Common Files\\svc host.exe'],
      [null, 'MsWinZonesCacheCounterMutexA'],
    ]);
    expect(candidates[0].defanged).toBe(true);
    expect(candidates[2].defanged).toBe(false);
  });

  it('takes the type from a report label when one names it', () => {
    const candidates = extractIocCandidates([
      'Mutex: MsWinZonesCacheCounterMutexA',
      'Mutexes: Global\\Foo1, Global\\Bar2',
      'Process: svchost32.exe',
      'Registry: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\updater',
      'File: C:\\Users\\Public\\svchost32.exe',
      'IP: 198.51.100[.]7',
      'C2: hxxps://cdn.bad[.]site/stage2.ps1',
      'Note: check this with finance',
      'Drops C:\\Users\\Public\\ab.exe',
    ].join('\n'));
    expect(candidates.map((item) => [item.type, item.value])).toEqual([
      ['Mutex', 'MsWinZonesCacheCounterMutexA'],
      ['Mutex', 'Global\\Foo1'],
      ['Mutex', 'Global\\Bar2'],
      ['Process', 'svchost32.exe'],
      ['Registry', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\updater'],
      ['FilePath', 'C:\\Users\\Public\\svchost32.exe'],
      ['IP', '198.51.100.7'],
      ['URL', 'https://cdn.bad.site/stage2.ps1'],
      ['FilePath', 'C:\\Users\\Public\\ab.exe'],
    ]);
  });

  it('keys values case-insensitively per type', () => {
    expect(iocKey('Domain', 'Evil[.]Example')).toBe(iocKey('Domain', 'evil.example'));
    expect(normalizeIocValue('Hash', 'ABCDEF0123456789ABCDEF0123456789')).toBe('abcdef0123456789abcdef0123456789');
  });
});
