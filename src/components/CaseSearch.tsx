/**
 * Case-wide search (Ctrl+K): one box for hostnames, IPs, MACs, hashes, IOC
 * values, and text in notes, events, and captures. Choosing a result opens
 * the screen that holds it with the record in view.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { Clock, FileText, Inbox, Loader2, Route, Search, Server, Shield, ShieldAlert, Wifi } from 'lucide-react';
import { invoke } from '@/lib/api';
import type { ApiResponse, SearchHit } from '@/types';

interface Props {
  onClose: () => void;
  onOpen: (hit: SearchHit) => void;
}

const GROUPS: { type: string; label: string; icon: React.ReactNode }[] = [
  { type: 'asset', label: 'Assets', icon: <Server size={14} /> },
  { type: 'network', label: 'Networks', icon: <Wifi size={14} /> },
  { type: 'firewall', label: 'Firewalls', icon: <Shield size={14} /> },
  { type: 'ioc', label: 'Indicators', icon: <ShieldAlert size={14} /> },
  { type: 'timeline_event', label: 'Timeline', icon: <Clock size={14} /> },
  { type: 'note', label: 'Notes', icon: <FileText size={14} /> },
  { type: 'capture', label: 'Captures', icon: <Inbox size={14} /> },
  { type: 'attack_edge', label: 'Attack paths', icon: <Route size={14} /> },
];

export default function CaseSearch({ onClose, onOpen }: Props) {
  const [query, setQuery] = useState('');
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [active, setActive] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => { inputRef.current?.focus(); }, []);

  useEffect(() => {
    const term = query.trim();
    if (term.length < 2) {
      setHits([]);
      setError('');
      return;
    }
    let cancelled = false;
    setLoading(true);
    const timer = window.setTimeout(async () => {
      try {
        const response = await invoke<ApiResponse<SearchHit[]>>('search_case_records', { query: term, limit: 60 });
        if (cancelled) return;
        if (!response.success) throw new Error(response.error || 'Search failed');
        setHits(response.data ?? []);
        setActive(0);
        setError('');
      } catch (reason) {
        if (!cancelled) setError(String(reason));
      } finally {
        if (!cancelled) setLoading(false);
      }
    }, 150);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [query]);

  // Results grouped by kind; keyboard order follows the displayed order.
  const ordered = useMemo(() => GROUPS.flatMap((group) => hits.filter((hit) => hit.entity_type === group.type)), [hits]);

  const choose = (hit: SearchHit | undefined) => { if (hit) onOpen(hit); };

  const onKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === 'Escape') { event.preventDefault(); onClose(); }
    else if (event.key === 'ArrowDown') { event.preventDefault(); setActive((index) => Math.min(index + 1, Math.max(ordered.length - 1, 0))); }
    else if (event.key === 'ArrowUp') { event.preventDefault(); setActive((index) => Math.max(index - 1, 0)); }
    else if (event.key === 'Enter') { event.preventDefault(); choose(ordered[active]); }
  };

  let position = -1;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-slate-900/50 p-4 pt-[10vh]" role="dialog" aria-modal="true" aria-label="Search the case" onMouseDown={onClose}>
      <div className="w-full max-w-2xl overflow-hidden rounded-lg bg-white shadow-2xl" onMouseDown={(event) => event.stopPropagation()}>
        <div className="flex items-center gap-2 border-b px-3">
          {loading ? <Loader2 size={16} className="animate-spin text-slate-400" /> : <Search size={16} className="text-slate-400" />}
          <input
            ref={inputRef}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={onKeyDown}
            aria-label="Search the case"
            placeholder="Hostname, IP, MAC, hash, indicator, or any text…"
            className="h-12 flex-1 bg-transparent text-sm outline-none"
          />
          <kbd className="rounded border bg-slate-50 px-1.5 text-[10px] text-slate-500">Esc</kbd>
        </div>
        <div className="max-h-[60vh] overflow-y-auto p-2" role="listbox" aria-label="Search results">
          {error && <p className="p-3 text-sm text-red-600">{error}</p>}
          {!error && query.trim().length < 2 && <p className="p-3 text-sm text-slate-500">Search hostnames, IPs, MACs, hashes, indicators, notes, timeline events, and captures across the whole case.</p>}
          {!error && query.trim().length >= 2 && !loading && ordered.length === 0 && <p className="p-3 text-sm text-slate-500">Nothing in this case matches “{query.trim()}”.</p>}
          {GROUPS.map((group) => {
            const groupHits = hits.filter((hit) => hit.entity_type === group.type);
            if (!groupHits.length) return null;
            return (
              <div key={group.type} className="mb-2">
                <p className="flex items-center gap-1.5 px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-slate-500">{group.icon}{group.label}</p>
                {groupHits.map((hit) => {
                  position += 1;
                  const index = position;
                  return (
                    <button
                      key={`${hit.entity_type}:${hit.entity_id}`}
                      type="button"
                      role="option"
                      aria-selected={index === active}
                      onMouseEnter={() => setActive(index)}
                      onClick={() => choose(hit)}
                      className={`block w-full rounded px-2 py-1.5 text-left ${index === active ? 'bg-cyan-50' : 'hover:bg-slate-50'}`}
                    >
                      <span className="block truncate text-sm font-medium text-slate-800">{hit.title || hit.entity_id}</span>
                      <span className="block truncate text-xs text-slate-500"><span className="font-medium">{hit.field}</span>{hit.detail && hit.detail !== hit.title ? `: ${hit.detail}` : ''}</span>
                    </button>
                  );
                })}
              </div>
            );
          })}
        </div>
        <p className="border-t px-3 py-2 text-[11px] text-slate-500">↑ ↓ to move · Enter to open · Ctrl+K anywhere to search again</p>
      </div>
    </div>
  );
}
