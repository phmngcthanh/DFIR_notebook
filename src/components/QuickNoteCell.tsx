/**
 * Inline investigator remark on a single entity row (asset, network/subnet,
 * firewall). The note lives on the entity itself — set through the
 * `set_entity_quick_note` command — so it survives snapshots, expert merges,
 * and history attribution like any other field, without opening the full
 * edit form or creating a formal case note.
 */
import { useEffect, useRef, useState } from 'react';
import { StickyNote } from 'lucide-react';
import { toast } from 'sonner';
import { invoke } from '@/lib/api';
import type { ApiResponse } from '@/types';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { cn } from '@/lib/utils';

interface QuickNoteCellProps {
  entityType: 'asset' | 'network' | 'firewall';
  id: string;
  note?: string | null;
  /** Signal the parent to re-fetch so the saved note renders everywhere. */
  onSaved?: () => void;
}

export default function QuickNoteCell({ entityType, id, note, onSaved }: QuickNoteCellProps) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState('');
  const [saving, setSaving] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (editing) textareaRef.current?.focus();
  }, [editing]);

  const openEditor = () => {
    setDraft(note ?? '');
    setEditing(true);
  };

  const save = async () => {
    setSaving(true);
    const response = await invoke<ApiResponse<boolean>>('set_entity_quick_note', {
      entityType,
      id,
      quickNote: draft.trim() || null,
    });
    setSaving(false);
    if (!response.success) {
      toast.error(response.error ?? 'Could not save the note');
      return;
    }
    setEditing(false);
    onSaved?.();
  };

  if (editing) {
    return (
      <div className='flex w-56 flex-col gap-1' onKeyDown={(event) => { if (event.key === 'Escape') setEditing(false); }}>
        <Textarea ref={textareaRef} rows={3} value={draft} onChange={(event) => setDraft(event.target.value)} placeholder='Quick note…' className='text-xs' />
        <div className='flex gap-1'>
          <Button size='sm' disabled={saving} onClick={() => void save()}>Save</Button>
          <Button size='sm' variant='outline' disabled={saving} onClick={() => setEditing(false)}>Cancel</Button>
        </div>
      </div>
    );
  }

  const text = note ?? undefined;
  const hasNote = Boolean(text);
  return (
    <button type='button' onClick={openEditor} title={text ?? 'Add a quick note'} className='flex max-w-56 items-start gap-1 text-left text-xs text-slate-600 hover:text-slate-900'>
      <StickyNote size={14} className={cn('mt-0.5 shrink-0', hasNote ? 'text-amber-500' : 'text-slate-400')} />
      <span className={cn('line-clamp-2 break-words', !hasNote && 'italic text-slate-400')}>{hasNote ? text : 'note'}</span>
    </button>
  );
}
