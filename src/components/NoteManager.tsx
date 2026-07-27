import { Fragment, useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { invoke } from '@/lib/api';
import { Eye, FileText, Pencil, Plus, Save, Search, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import type { ApiResponse, Note } from '@/types';

interface Props { refreshTrigger: number }

export default function NoteManager({ refreshTrigger }: Props) {
  const [notes, setNotes] = useState<Note[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [preview, setPreview] = useState(false);
  const [search, setSearch] = useState('');

  const loadNotes = useCallback(async () => {
    try {
      const response = await invoke<ApiResponse<Note[]>>('list_notes');
      if (!response.success) throw new Error(response.error || 'Could not load notes');
      setNotes(response.data ?? []);
    } catch (reason) { toast.error(String(reason)); }
  }, []);
  useEffect(() => { void loadNotes(); }, [loadNotes, refreshTrigger]);

  const reset = () => { setShowForm(false); setEditingId(null); setTitle(''); setContent(''); setPreview(false); };
  const startNew = () => { reset(); setShowForm(true); };
  const startEdit = (note: Note) => { setEditingId(note.id); setTitle(note.title); setContent(note.content); setPreview(false); setShowForm(true); };
  const save = async () => {
    if (!title.trim()) { toast.error('Note title is required'); return; }
    try {
      const response = await invoke<ApiResponse<Note>>(editingId ? 'update_existing_note' : 'create_new_note', { id: editingId, title: title.trim(), content: content.trim() });
      if (!response.success) throw new Error(response.error || 'Could not save note');
      toast.success(editingId ? 'Note updated' : 'Note created'); reset(); await loadNotes();
    } catch (reason) { toast.error(String(reason)); }
  };
  const remove = async (id: string) => {
    if (!confirm('Delete this note?')) return;
    try { const response = await invoke<ApiResponse<boolean>>('remove_note', { id }); if (!response.success) throw new Error(response.error || 'Could not delete note'); await loadNotes(); }
    catch (reason) { toast.error(String(reason)); }
  };
  const filtered = useMemo(() => { const term = search.trim().toLowerCase(); return notes.filter((note) => !term || `${note.title} ${note.content}`.toLowerCase().includes(term)); }, [notes, search]);

  return <div className="space-y-4 p-6">
    <div className="flex items-center justify-between"><div><h2 className="flex items-center gap-2 text-2xl font-bold text-slate-800"><FileText className="text-cyan-600" />Investigation Notes</h2><p className="text-sm text-slate-500">Versioned notes with safe local Markdown preview</p></div><Button onClick={startNew} className="bg-cyan-600 hover:bg-cyan-700"><Plus size={16} className="mr-2" />New Note</Button></div>
    <div className="relative"><Search size={15} className="absolute left-3 top-2.5 text-slate-400" /><Input className="pl-9" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search notes…" /></div>
    {showForm && <Card><CardHeader><div className="flex items-center justify-between"><CardTitle className="text-sm">{editingId ? 'Edit Note' : 'New Note'}</CardTitle><Button variant={preview ? 'default' : 'outline'} size="sm" onClick={() => setPreview((value) => !value)}><Eye size={14} className="mr-2" />{preview ? 'Edit text' : 'Preview'}</Button></div></CardHeader><CardContent className="space-y-3"><div className="space-y-1"><Label>Title *</Label><Input value={title} onChange={(event) => setTitle(event.target.value)} /></div><div className="space-y-1"><Label>Content (Markdown; raw HTML is displayed as text)</Label>{preview ? <div className="min-h-48 rounded border bg-white p-4"><SafeMarkdown content={content} /></div> : <Textarea rows={10} value={content} onChange={(event) => setContent(event.target.value)} placeholder="# Finding\n\nDescribe evidence, commands, and conclusions…" />}</div><div className="flex gap-2"><Button onClick={() => void save()}><Save size={15} className="mr-2" />{editingId ? 'Update' : 'Save'}</Button><Button variant="outline" onClick={reset}>Cancel</Button></div></CardContent></Card>}
    <div className="grid gap-4 lg:grid-cols-2">{filtered.length === 0 ? <div className="col-span-2 py-10 text-center text-slate-400">No matching notes.</div> : filtered.map((note) => <Card key={note.id}><CardHeader className="pb-2"><div className="flex items-start justify-between"><CardTitle className="text-sm">{note.title}</CardTitle><div><Button size="sm" variant="ghost" onClick={() => startEdit(note)}><Pencil size={14} /></Button><Button size="sm" variant="ghost" onClick={() => void remove(note.id)}><Trash2 size={14} className="text-red-500" /></Button></div></div></CardHeader><CardContent><div className="max-h-64 overflow-hidden text-sm"><SafeMarkdown content={note.content} /></div><p className="mt-3 border-t pt-2 text-xs text-slate-400">Updated {displayTime(note.updated_at)}</p></CardContent></Card>)}</div>
  </div>;
}

function SafeMarkdown({ content }: { content: string }) {
  const lines = content.replaceAll('\r\n', '\n').split('\n');
  const blocks: ReactNode[] = [];
  let index = 0;
  while (index < lines.length) {
    const line = lines[index];
    if (line.startsWith('```')) {
      const language = line.slice(3).trim(); const code: string[] = []; index += 1;
      while (index < lines.length && !lines[index].startsWith('```')) { code.push(lines[index]); index += 1; }
      index += index < lines.length ? 1 : 0;
      blocks.push(<pre key={`code-${index}`} className="my-2 overflow-x-auto rounded bg-slate-900 p-3 text-xs text-slate-100"><code data-language={language}>{code.join('\n')}</code></pre>); continue;
    }
    const heading = /^(#{1,3})\s+(.+)$/.exec(line);
    if (heading) { const level = heading[1].length; const className = level === 1 ? 'mt-3 text-xl font-bold' : level === 2 ? 'mt-3 text-lg font-semibold' : 'mt-2 font-semibold'; blocks.push(<div key={`heading-${index}`} role="heading" aria-level={level} className={className}>{inlineMarkdown(heading[2], index)}</div>); index += 1; continue; }
    if (/^[-*]\s+/.test(line)) { const items: string[] = []; while (index < lines.length && /^[-*]\s+/.test(lines[index])) { items.push(lines[index].replace(/^[-*]\s+/, '')); index += 1; } blocks.push(<ul key={`list-${index}`} className="my-2 list-disc space-y-1 pl-5">{items.map((item, itemIndex) => <li key={itemIndex}>{inlineMarkdown(item, itemIndex)}</li>)}</ul>); continue; }
    if (line.startsWith('> ')) { blocks.push(<blockquote key={`quote-${index}`} className="my-2 border-l-4 border-slate-300 pl-3 text-slate-600">{inlineMarkdown(line.slice(2), index)}</blockquote>); index += 1; continue; }
    if (!line.trim()) { index += 1; continue; }
    const paragraph = [line]; index += 1;
    while (index < lines.length && lines[index].trim() && !/^(#{1,3})\s+|^[-*]\s+|^>\s+|^```/.test(lines[index])) { paragraph.push(lines[index]); index += 1; }
    blocks.push(<p key={`paragraph-${index}`} className="my-2 whitespace-pre-wrap leading-6 text-slate-700">{inlineMarkdown(paragraph.join('\n'), index)}</p>);
  }
  return <div className="break-words">{blocks.length ? blocks : <span className="text-slate-400">Nothing to preview.</span>}</div>;
}

function inlineMarkdown(text: string, keySeed: number): ReactNode[] {
  const tokens = text.split(/(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\([^)]+\)|\*[^*]+\*)/g);
  return tokens.filter(Boolean).map((token, index) => {
    const key = `${keySeed}-${index}`;
    if (token.startsWith('**') && token.endsWith('**')) return <strong key={key}>{token.slice(2, -2)}</strong>;
    if (token.startsWith('`') && token.endsWith('`')) return <code key={key} className="rounded bg-slate-100 px-1 py-0.5 text-xs">{token.slice(1, -1)}</code>;
    if (token.startsWith('*') && token.endsWith('*')) return <em key={key}>{token.slice(1, -1)}</em>;
    const link = /^\[([^\]]+)\]\(([^)]+)\)$/.exec(token);
    if (link) { const href = safeLink(link[2]); return href ? <a key={key} href={href} target="_blank" rel="noreferrer" className="text-cyan-700 underline">{link[1]}</a> : <Fragment key={key}>{link[1]} ({link[2]})</Fragment>; }
    return <Fragment key={key}>{token}</Fragment>;
  });
}
function safeLink(value: string) { try { const url = new URL(value); return ['http:', 'https:', 'mailto:'].includes(url.protocol) ? url.toString() : null; } catch { return null; } }
function displayTime(value: string) { const date = new Date(value); return Number.isNaN(date.valueOf()) ? value : date.toLocaleString(); }
