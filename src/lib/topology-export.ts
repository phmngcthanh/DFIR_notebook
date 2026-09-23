/**
 * Generates shareable diagram files from a snapshot of the network topology:
 * an uncompressed `.drawio` (mxGraph XML) that opens in diagrams.net and
 * draw.io desktop, and a `.xmind` (XMind 2020+ JSON-in-zip) mindmap grouping
 * every device under its subnet. Both are pure functions over the model the
 * topology page snapshots from its canvas, so they stay testable without
 * Cytoscape.
 */
import { branding } from '@/config/branding';
import { buildZip, type ZipEntry } from './zip-writer';

export type TopologyExportNodeKind = 'root' | 'zone' | 'asset' | 'firewall';
export type TopologyExportEdgeKind = 'connection' | 'nic' | 'branch';

export interface TopologyExportNode {
  id: string;
  label: string;
  kind: TopologyExportNodeKind;
  /** Center coordinates and on-screen size, straight from the canvas. */
  x: number;
  y: number;
  width: number;
  height: number;
  parent?: string;
  /** Compromise status coloring for assets. */
  status?: string;
  zoneTone?: 'default' | 'dmz' | 'dms' | 'wan';
  shape?: 'box' | 'router' | 'switch' | 'firewall';
}

export interface TopologyExportEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  kind: TopologyExportEdgeKind;
}

export interface TopologyExportModel {
  title: string;
  nodes: TopologyExportNode[];
  edges: TopologyExportEdge[];
}

const ZONE_COLORS: Record<NonNullable<TopologyExportNode['zoneTone']>, { fill: string; stroke: string }> = {
  default: { fill: '#F0F9FF', stroke: '#0891B2' },
  dmz: { fill: '#FFF7ED', stroke: '#EA580C' },
  dms: { fill: '#FEFCE8', stroke: '#CA8A04' },
  wan: { fill: '#EFF6FF', stroke: '#2563EB' },
};

function escapeXml(value: string): string {
  return value.replace(/[\n&<>"']/g, (character) => {
    switch (character) {
      case '\n': return '&#10;';
      case '&': return '&amp;';
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '"': return '&quot;';
      default: return '&apos;';
    }
  });
}

function drawioNodeStyle(node: TopologyExportNode): string {
  const base = 'whiteSpace=wrap;html=1;';
  if (node.kind === 'root') {
    return `${base}rounded=1;arcSize=30;fillColor=#0E7490;strokeColor=#155E75;fontColor=#F8FAFC;fontStyle=1;fontSize=14`;
  }
  if (node.kind === 'zone') {
    const colors = ZONE_COLORS[node.zoneTone ?? 'default'];
    return `${base}rounded=1;arcSize=8;verticalAlign=top;fontSize=13;fontStyle=1;strokeWidth=3;fillColor=${colors.fill};strokeColor=${colors.stroke}`;
  }
  if (node.kind === 'firewall') {
    return `${base}shape=hexagon;perimeter=hexagonPerimeter2;fixedSize=1;fillColor=#FEF3C7;strokeColor=#D97706;strokeWidth=3;fontSize=11`;
  }
  if (node.status === 'infected') {
    return `${base}rounded=1;fillColor=#FEF2F2;strokeColor=#DC2626;strokeWidth=4;fontSize=11`;
  }
  if (node.status === 'suspected') {
    return `${base}rounded=1;fillColor=#FFFBEB;strokeColor=#D97706;strokeWidth=4;fontSize=11`;
  }
  if (node.shape === 'router') {
    return `${base}shape=rhombus;fillColor=#EEF2FF;strokeColor=#4F46E5;strokeWidth=3;fontSize=11`;
  }
  if (node.shape === 'switch') {
    return `${base}rounded=0;fillColor=#ECFEFF;strokeColor=#0E7490;strokeWidth=3;fontSize=11`;
  }
  return `${base}rounded=1;fillColor=#FFFFFF;strokeColor=#64748B;fontSize=11`;
}

function drawioEdgeStyle(edge: TopologyExportEdge): string {
  if (edge.kind === 'branch') {
    return 'edgeStyle=none;rounded=1;strokeColor=#0E7490;strokeWidth=6;endArrow=none;opacity=60';
  }
  if (edge.kind === 'connection') {
    return 'edgeStyle=none;rounded=1;dashed=1;strokeColor=#0891B2;strokeWidth=3;fontSize=9';
  }
  return 'edgeStyle=none;rounded=1;dashed=1;dashPattern=1 4;strokeColor=#7C3AED;strokeWidth=2;fontSize=8';
}

/** Uncompressed draw.io XML — diagrams.net opens this without any deflate step. */
export function buildDrawioXml(model: TopologyExportModel): string {
  const nodeById = new Map(model.nodes.map((node) => [node.id, node]));
  const cells: string[] = [];
  model.nodes.forEach((node) => {
    // Zone children keep containment: coordinates relative to the zone's
    // top-left so dragging a zone in draw.io moves its devices with it.
    const parent = node.parent ? nodeById.get(node.parent) : undefined;
    const zoneParent = parent?.kind === 'zone' ? parent : undefined;
    const originX = zoneParent ? zoneParent.x - zoneParent.width / 2 : 0;
    const originY = zoneParent ? zoneParent.y - zoneParent.height / 2 : 0;
    const x = Math.round(node.x - node.width / 2 - originX);
    const y = Math.round(node.y - node.height / 2 - originY);
    cells.push(
      `        <mxCell id="${escapeXml(node.id)}" value="${escapeXml(node.label)}" style="${drawioNodeStyle(node)}" vertex="1" parent="${zoneParent ? escapeXml(zoneParent.id) : '1'}">` +
      `<mxGeometry x="${x}" y="${y}" width="${Math.round(node.width)}" height="${Math.round(node.height)}" as="geometry"/></mxCell>`,
    );
  });
  model.edges.forEach((edge) => {
    cells.push(
      `        <mxCell id="${escapeXml(edge.id)}" value="${escapeXml(edge.label ?? '')}" style="${drawioEdgeStyle(edge)}" edge="1" parent="1" source="${escapeXml(edge.source)}" target="${escapeXml(edge.target)}">` +
      `<mxGeometry relative="1" as="geometry"/></mxCell>`,
    );
  });
  return `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<mxfile host="${escapeXml(branding.productName)}" type="device">\n` +
    `  <diagram id="network-topology" name="${escapeXml(model.title)}">\n` +
    `    <mxGraphModel dx="800" dy="600" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1169" pageHeight="826" math="0" shadow="0">\n` +
    `      <root>\n        <mxCell id="0"/>\n        <mxCell id="1" parent="0"/>\n${cells.join('\n')}\n      </root>\n` +
    `    </mxGraphModel>\n  </diagram>\n</mxfile>\n`;
}

/** Topic tree other features (e.g. the VM inventory export) can build directly. */
export interface XmindTopic {
  id: string;
  title: string;
  labels?: string[];
  children?: XmindTopic[];
}

export interface XmindRelationship {
  id: string;
  end1Id: string;
  end2Id: string;
  title: string;
}

function xmindTopic(node: XmindTopic): {
  id: string;
  class: 'topic';
  title: string;
  labels?: string[];
  children?: { attached: ReturnType<typeof xmindTopic>[] };
} {
  return {
    id: node.id,
    class: 'topic',
    title: node.title,
    ...(node.labels?.length ? { labels: node.labels } : {}),
    ...(node.children?.length ? { children: { attached: node.children.map(xmindTopic) } } : {}),
  };
}

/** Serializes one sheet with its root topic tree as XMind `content.json`. */
export function buildXmindContentFromTree(
  sheetId: string,
  sheetTitle: string,
  root: XmindTopic,
  relationships: XmindRelationship[] = [],
): string {
  const sheet = {
    id: sheetId,
    class: 'sheet',
    title: sheetTitle,
    rootTopic: xmindTopic(root),
    ...(relationships.length
      ? { relationships: relationships.map((edge) => ({ ...edge, class: 'relationship' })) }
      : {}),
  };
  return JSON.stringify([sheet]);
}

function xmindArchive(contentJson: string): Uint8Array {
  const encoder = new TextEncoder();
  const entries: ZipEntry[] = [
    { name: 'content.json', data: encoder.encode(contentJson) },
    { name: 'metadata.json', data: encoder.encode(JSON.stringify({ creator: { name: branding.productName, version: branding.version } })) },
    { name: 'manifest.json', data: encoder.encode(JSON.stringify({ 'file-entries': { 'content.json': {}, 'metadata.json': {} } })) },
  ];
  return buildZip(entries);
}

/** A complete `.xmind` file built straight from a topic tree. */
export function buildXmindArchiveFromTree(
  sheetTitle: string,
  root: XmindTopic,
  relationships: XmindRelationship[] = [],
): Uint8Array {
  return xmindArchive(buildXmindContentFromTree('sheet-xmind-export', sheetTitle, root, relationships));
}

function xmindTitle(node: TopologyExportNode): string {
  const title = node.label.replaceAll('\n', ' · ');
  return node.status === 'suspected' || node.status === 'infected' ? `${title} · ${node.status}` : title;
}

/** The sheet array XMind 2020+ expects as `content.json`. */
export function buildXmindContent(model: TopologyExportModel): string {
  const zones = model.nodes.filter((node) => node.kind === 'zone');
  const leavesByParent = new Map<string, TopologyExportNode[]>();
  model.nodes.forEach((node) => {
    if (node.kind !== 'asset' && node.kind !== 'firewall') return;
    const items = leavesByParent.get(node.parent ?? '') ?? [];
    items.push(node);
    leavesByParent.set(node.parent ?? '', items);
  });
  const topicFor = (node: TopologyExportNode): XmindTopic => ({
    id: node.id,
    title: xmindTitle(node),
  });
  const zoneTopics: XmindTopic[] = zones.map((zone) => {
    const attached = (leavesByParent.get(zone.id) ?? []).map(topicFor);
    return { id: zone.id, title: xmindTitle(zone), ...(attached.length ? { children: attached } : {}) };
  });
  const unassigned = leavesByParent.get('') ?? [];
  if (unassigned.length) {
    zoneTopics.push({
      id: 'unassigned-devices',
      title: `Unassigned · ${unassigned.length} ${unassigned.length === 1 ? 'device' : 'devices'}`,
      children: unassigned.map(topicFor),
    });
  }
  const root = model.nodes.find((node) => node.kind === 'root');
  const relationships: XmindRelationship[] = model.edges
    .filter((edge) => edge.kind === 'connection')
    .map((edge) => ({ id: edge.id, end1Id: edge.source, end2Id: edge.target, title: edge.label ?? '' }));
  return buildXmindContentFromTree('sheet-network-topology', model.title, {
    id: root?.id ?? 'network-topology',
    title: root ? xmindTitle(root) : model.title,
    ...(zoneTopics.length ? { children: zoneTopics } : {}),
  }, relationships);
}

/** A complete `.xmind` file: content, metadata, and manifest in a stored zip. */
export function buildXmindArchive(model: TopologyExportModel): Uint8Array {
  return xmindArchive(buildXmindContent(model));
}
