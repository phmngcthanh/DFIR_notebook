import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { TEAM_PRESETS } from '@/lib/teams';

/** Free-text team with the usual DFIR teams offered as suggestions. */
export default function TeamField({ value, onChange, id = 'expert-team' }: { value: string; onChange: (value: string) => void; id?: string }) {
  return (
    <div className="space-y-2">
      <Label htmlFor={id}>Team</Label>
      <Input id={id} list={`${id}-presets`} value={value} onChange={(event) => onChange(event.target.value)} placeholder="e.g. Log analysis" autoComplete="off" />
      <datalist id={`${id}-presets`}>{TEAM_PRESETS.map((team) => <option key={team} value={team} />)}</datalist>
      <p className="text-xs text-slate-500">Recorded with your changes so work can be followed per team. It never limits what you can edit.</p>
    </div>
  );
}
