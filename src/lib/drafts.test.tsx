import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { draftScope, pruneDrafts, useDraft } from './drafts';

function DraftField({ label }: { label: string }) {
  const [value, setValue] = useDraft(`test.${label}`, '');
  return <input aria-label={label} value={value} onChange={(event) => setValue(event.target.value)} />;
}

function InCase({ caseId, children }: { caseId: string; children: React.ReactNode }) {
  return <draftScope.Provider value={caseId}>{children}</draftScope.Provider>;
}

describe('useDraft', () => {
  it('restores unsaved input after the view unmounts and mounts again', async () => {
    const user = userEvent.setup();
    const first = render(<DraftField label="Finding" />);
    await user.type(screen.getByLabelText('Finding'), 'APP01 probably on ESX03');
    first.unmount();

    render(<DraftField label="Finding" />);
    expect(screen.getByLabelText('Finding')).toHaveValue('APP01 probably on ESX03');
  });

  it('keeps drafts per case and drops other cases when pruned', async () => {
    const user = userEvent.setup();
    const caseA = render(<InCase caseId="case-a"><DraftField label="Note" /></InCase>);
    await user.type(screen.getByLabelText('Note'), 'case A draft');
    caseA.unmount();

    const caseB = render(<InCase caseId="case-b"><DraftField label="Note" /></InCase>);
    expect(screen.getByLabelText('Note')).toHaveValue('');
    caseB.unmount();

    const again = render(<InCase caseId="case-a"><DraftField label="Note" /></InCase>);
    expect(screen.getByLabelText('Note')).toHaveValue('case A draft');
    again.unmount();

    // Opening case B (or locking, which prunes with null) forgets case A.
    pruneDrafts('case-b');
    render(<InCase caseId="case-a"><DraftField label="Note" /></InCase>);
    expect(screen.getByLabelText('Note')).toHaveValue('');
  });
});
