import { describe, expect, it } from 'vitest';
import { buildZip, crc32 } from './zip-writer';

describe('zip-writer', () => {
  it('matches the standard CRC-32 check value', () => {
    expect(crc32(new TextEncoder().encode('123456789'))).toBe(0xcbf43926);
    expect(crc32(new Uint8Array(0))).toBe(0);
  });

  it('round-trips stored entries with correct sizes and offsets', () => {
    const first = new TextEncoder().encode('{"hello":"world"}');
    const second = new TextEncoder().encode('second entry');
    const archive = buildZip([
      { name: 'a.json', data: first },
      { name: 'nested/b.txt', data: second },
    ]);
    const view = new DataView(archive.buffer, archive.byteOffset, archive.byteLength);
    let eocd = -1;
    for (let index = archive.length - 22; index >= 0; index -= 1) {
      if (view.getUint32(index, true) === 0x06054b50) { eocd = index; break; }
    }
    expect(eocd).toBeGreaterThan(0);
    const decoder = new TextDecoder();
    let cursor = view.getUint32(eocd + 16, true);
    const payloads: string[] = [];
    for (let entry = 0; entry < 2; entry += 1) {
      const nameLength = view.getUint16(cursor + 28, true);
      const name = decoder.decode(archive.subarray(cursor + 46, cursor + 46 + nameLength));
      const localOffset = view.getUint32(cursor + 42, true);
      const localNameLength = view.getUint16(localOffset + 26, true);
      const size = view.getUint32(localOffset + 18, true);
      payloads.push(`${name}:${decoder.decode(archive.subarray(localOffset + 30 + localNameLength, localOffset + 30 + localNameLength + size))}`);
      cursor += 46 + nameLength;
    }
    expect(payloads).toEqual(['a.json:{"hello":"world"}', 'nested/b.txt:second entry']);
  });
});
