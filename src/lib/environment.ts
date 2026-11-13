/**
 * Labels and small helpers for the environment fields of Phase 2: where an
 * asset came from, how assets relate to one another, and when one was last
 * seen. The values mirror `ASSET_ORIGINS` and `RELATION_TYPES` in db.rs.
 */
import type { AssetOrigin, RelationType } from '@/types';

export const ASSET_ORIGINS: { value: AssetOrigin; label: string }[] = [
  { value: 'unknown', label: 'Not recorded' },
  { value: 'client_inventory', label: "In the client's inventory" },
  { value: 'discovered', label: 'Discovered by us' },
];

export function originLabel(origin?: string | null): string {
  return ASSET_ORIGINS.find((item) => item.value === origin)?.label ?? 'Not recorded';
}

/** How a source asset reads against its target ("APP01 runs on ESX01") and the other way round. */
export const RELATION_TYPES: { value: RelationType; out: string; in: string }[] = [
  { value: 'runs_on', out: 'runs on', in: 'hosts' },
  { value: 'managed_by', out: 'is managed by', in: 'manages' },
  { value: 'backs_up_to', out: 'backs up to', in: 'receives backups from' },
  { value: 'depends_on', out: 'depends on', in: 'is depended on by' },
  { value: 'connects_to', out: 'connects to', in: 'is connected from' },
  { value: 'other', out: 'is related to', in: 'is related to' },
];

export function relationPhrase(type: string, direction: 'out' | 'in' = 'out'): string {
  const entry = RELATION_TYPES.find((item) => item.value === type);
  return entry ? entry[direction] : 'is related to';
}

/**
 * "APP01 runs on ESX01" for a stored relation, or null when the value is not
 * one. History and merge reviews use it, because a relation has no name.
 */
export function relationTitle(value: unknown): string | null {
  if (typeof value !== 'object' || value === null) return null;
  const record = value as Record<string, unknown>;
  const [source, target, type] = [record.source_name, record.target_name, record.relation_type];
  return typeof source === 'string' && source && typeof target === 'string' && target && typeof type === 'string'
    ? `${source} ${relationPhrase(type)} ${target}`
    : null;
}

/** `datetime-local` input value (local time, minutes) for an RFC 3339 timestamp. */
export function toLocalInput(iso?: string | null): string {
  if (!iso) return '';
  const date = new Date(iso);
  if (Number.isNaN(date.valueOf())) return '';
  const pad = (value: number) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** RFC 3339 UTC for a `datetime-local` value; empty when there is none or it is not a date. */
export function fromLocalInput(value: string): string {
  if (!value.trim()) return '';
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? '' : date.toISOString();
}

/** "13 Nov 2026, 08:30", or an empty string when the timestamp is missing or unreadable. */
export function observedLabel(iso?: string | null): string {
  if (!iso) return '';
  const date = new Date(iso);
  if (Number.isNaN(date.valueOf())) return '';
  return date.toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}
