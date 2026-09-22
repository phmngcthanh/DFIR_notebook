import { describe, expect, it } from 'vitest';
import { buildDrawioXml, buildXmindArchive, buildXmindContent, type TopologyExportModel } from './topology-export';
import { crc32 } from './zip-writer';

const model: TopologyExportModel = {
  title: 'ACME <incident> 2026',
  nodes: [
    { id: 'mindmap-root', label: 'ACME case\n3 subnets', kind: 'root', x: 0, y: 0, width: 190, height: 84 },
    { id: 'network-dmz', label: 'DMZ\n10.0.1.0/24', kind: 'zone', x: 500, y: -300, width: 400, height: 300, zoneTone: 'dmz' },
    { id: 'asset-web', label: 'web-01\n10.0.1.10', kind: 'asset', x: 460, y: -320, width: 128, height: 58, parent: 'network-dmz', status: 'infected' },
    { id: 'network-lan', label: 'LAN\n10.0.2.0/24', kind: 'zone', x: 500, y: 300, width: 400, height: 300 },
    { id: 'asset-pc', label: 'pc-07\n10.0.2.7', kind: 'asset', x: 460, y: 320, width: 128, height: 58, parent: 'network-lan' },
    { id: 'firewall-edge', label: 'Edge firewall\nPalo Alto Firewall', kind: 'firewall', x: 640, y: -320, width: 126, height: 70, parent: 'network-dmz' },
    { id: 'asset-loose', label: 'unknown host\nNo IP', kind: 'asset', x: 0, y: 900, width: 128, height: 58 },
  ],
  edges: [
    { id: 'connection-1', source: 'network-dmz', target: 'network-lan', label: 'filtered · fw-1', kind: 'connection' },
    { id: 'branch-1', source: 'mindmap-root', target: 'network-dmz', kind: 'branch' },
  ],
};

describe('buildDrawioXml', () => {
  const xml = buildDrawioXml(model);

  it('wraps a well-formed mxfile the draw.io importer accepts', () => {
    expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>')).toBe(true);
    expect(xml).toContain('<mxfile');
    expect(xml).toContain('<mxGraphModel');
    expect(xml).toContain('<mxCell id="0"/>');
  });

  it('escapes label content and encodes line breaks as character references', () => {
    expect(xml).toContain('name="ACME &lt;incident&gt; 2026"');
    expect(xml).toContain('DMZ&#10;10.0.1.0/24');
    expect(xml).not.toContain('DMZ\n10.0.1.0/24');
  });

  it('parents zone members so they drag together, with relative coordinates', () => {
    expect(xml).toContain('<mxCell id="network-dmz"');
    expect(xml).toContain('<mxGeometry x="300" y="-450" width="400" height="300" as="geometry"/>');
    expect(xml).toMatch(/<mxCell id="asset-web"[^>]*parent="network-dmz">/);
    // web-01 top-left (396,-349) minus zone top-left (300,-450) = (96,101)
    expect(xml).toContain('<mxGeometry x="96" y="101" width="128" height="58" as="geometry"/>');
  });

  it('emits every node, connection, and branch with draw.io styling', () => {
    for (const id of ['mindmap-root', 'asset-pc', 'asset-loose', 'firewall-edge', 'connection-1', 'branch-1']) {
      expect(xml).toContain(`id="${id}"`);
    }
    expect(xml).toContain('source="network-dmz" target="network-lan"');
    expect(xml).toContain('value="filtered · fw-1"');
    expect(xml).toContain('strokeColor=#DC2626');
    expect(xml).toContain('shape=hexagon');
  });
});

describe('buildXmind', () => {
  it('builds a sheet with zones as branches, devices as leaves, and status in titles', () => {
    const parsed = JSON.parse(buildXmindContent(model)) as Array<{
      rootTopic: { title: string; children?: { attached: Array<{ id: string; title: string; children?: { attached: Array<{ title: string }> } }> } };
      relationships?: Array<{ end1Id: string; end2Id: string; title: string }>;
    }>;
    expect(parsed).toHaveLength(1);
    expect(parsed[0].rootTopic.title).toBe('ACME case · 3 subnets');
    const zoneTitles = parsed[0].rootTopic.children?.attached.map((zone) => zone.title) ?? [];
    expect(zoneTitles).toContain('DMZ · 10.0.1.0/24');
    expect(zoneTitles.some((title) => title.startsWith('Unassigned · 1 device'))).toBe(true);
    const dmz = parsed[0].rootTopic.children!.attached.find((zone) => zone.id === 'network-dmz')!;
    expect(dmz.children?.attached.map((leaf) => leaf.title)).toEqual(['web-01 · 10.0.1.10 · infected', 'Edge firewall · Palo Alto Firewall']);
    expect(parsed[0].relationships).toEqual([{ id: 'connection-1', class: 'relationship', end1Id: 'network-dmz', end2Id: 'network-lan', title: 'filtered · fw-1' }]);
  });

  it('packs a stored-entry zip with the three members XMind requires', () => {
    const archive = buildXmindArchive(model);
    const view = new DataView(archive.buffer, archive.byteOffset, archive.byteLength);
    expect(view.getUint32(0, true)).toBe(0x04034b50); // starts with a local file header

    let eocd = -1;
    for (let index = archive.length - 22; index >= 0; index -= 1) {
      if (view.getUint32(index, true) === 0x06054b50) { eocd = index; break; }
    }
    expect(eocd).toBeGreaterThan(0);

    const count = view.getUint16(eocd + 10, true);
    expect(count).toBe(3);

    // Walk the central directory: names, stored payloads, and CRCs must line up.
    const names: string[] = [];
    let cursor = view.getUint32(eocd + 16, true);
    const decoder = new TextDecoder();
    for (let index = 0; index < count; index += 1) {
      expect(view.getUint32(cursor, true)).toBe(0x02014b50);
      const nameLength = view.getUint16(cursor + 28, true);
      const size = view.getUint32(cursor + 24, true);
      const name = decoder.decode(archive.subarray(cursor + 46, cursor + 46 + nameLength));
      names.push(name);
      const localOffset = view.getUint32(cursor + 42, true);
      const localNameLength = view.getUint16(localOffset + 26, true);
      const dataStart = localOffset + 30 + localNameLength;
      const data = archive.subarray(dataStart, dataStart + size);
      expect(view.getUint32(cursor + 16, true)).toBe(crc32(data));
      if (name === 'content.json') {
        const sheet = JSON.parse(decoder.decode(data)) as Array<{ class: string }>;
        expect(sheet[0].class).toBe('sheet');
      }
      cursor += 46 + nameLength;
    }
    expect(names).toEqual(['content.json', 'metadata.json', 'manifest.json']);
  });
});
