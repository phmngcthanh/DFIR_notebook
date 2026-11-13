/**
 * Capture: record what was just learned before it is lost, from any screen
 * (Alt+C). Only the text is required. It is saved verbatim with who captured
 * it and when; turning it into assets, indicators, or notes happens later in
 * the Capture inbox.
 */
import { useEffect, useRef, useState } from 'react';
import { Inbox, Loader2, X } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { invoke } from '@/lib/api';
import { useDraft, useDraftDiscard } from '@/lib/drafts';
import type { ApiResponse, Capture } from '@/types';

interface Props {
  onClose: () => void;
  onCaptured: (capture: Capture) => void;
}

export default function CaptureDialog({ onClose, onCaptured }: Props) {
  // Persisted: a half-typed capture survives a crash or a closed window.
  const [text, setText] = useDraft('capture.text', '', { persist: true });
  const [source, setSource] = useDraft('capture.source', '', { persist: true });
  const discardDraft = useDraftDiscard();
  const [saving, setSaving] = useState(false);
  const textRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    textRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  const save = async (another: boolean) => {
    if (!text.trim()) {
      toast.error('Type or paste what you learned first');
      return;
    }
    setSaving(true);
    try {
      const response = await invoke<ApiResponse<Capture>>('create_new_capture', {
        content: text,
        source: source.trim() || null,
      });
      if (!response.success || !response.data) throw new Error(response.error || 'Could not save the capture');
      onCaptured(response.data);
      if (another) {
        // The next note from the same meeting usually has the same source.
        setText('');
        textRef.current?.focus();
      } else {
        // Closing unmounts the dialog before a cleared field would render, so
        // forget the draft directly. The source goes too: a remembered source
        // would silently mislabel the next, unrelated capture.
        discardDraft('capture.');
        onClose();
      }
    } catch (reason) {
      toast.error(String(reason));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-slate-900/50 p-4 pt-[12vh]" role="dialog" aria-modal="true" aria-label="Capture" onMouseDown={onClose}>
      <div className="w-full max-w-2xl rounded-lg bg-white shadow-2xl" onMouseDown={(event) => event.stopPropagation()}>
        <div className="flex items-start justify-between gap-3 border-b p-4">
          <div>
            <h2 className="flex items-center gap-2 text-lg font-semibold text-slate-800"><Inbox size={18} className="text-cyan-600" />Capture</h2>
            <p className="mt-1 text-xs text-slate-500">Save it now, sort it out later. Only the text is required; it is kept exactly as written.</p>
          </div>
          <Button size="sm" variant="ghost" aria-label="Close capture" onClick={onClose}><X size={16} /></Button>
        </div>
        <div className="space-y-3 p-4">
          <div className="space-y-1">
            <Label htmlFor="capture-text">What did you learn? *</Label>
            <Textarea
              id="capture-text"
              ref={textRef}
              rows={7}
              value={text}
              onChange={(event) => setText(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
                  event.preventDefault();
                  void save(false);
                }
              }}
              placeholder="APP01, 10.0.0.15, probably on ESX03. Finance says they own it. Ask infrastructure for logs."
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="capture-source">Source</Label>
            <Input id="capture-source" value={source} onChange={(event) => setSource(event.target.value)} placeholder="Who or what it came from: finance interview, infra e-mail, log review…" />
          </div>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-2 border-t p-4">
          <p className="text-xs text-slate-500">Ctrl+Enter saves · Esc closes and keeps the text</p>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => void save(true)} disabled={saving}>Save and capture another</Button>
            <Button onClick={() => void save(false)} disabled={saving} className="bg-cyan-600 hover:bg-cyan-700">
              {saving && <Loader2 size={15} className="mr-1 animate-spin" />}Save
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
