import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import {
  configureDraftPersistence, draftScope, endDraftPersistence, flushDrafts, hydrateDrafts,
  MAX_PERSISTED_DRAFT_BYTES, pruneDrafts, useDraft, useDraftDiscard,
} from './drafts';

function DraftField({ label, persist = false }: { label: string; persist?: boolean }) {
  const [value, setValue] = useDraft(`test.${label}`, '', { persist });
  return <input aria-label={label} value={value} onChange={(event) => setValue(event.target.value)} />;
}

function DiscardButton({ prefix }: { prefix: string }) {
  const discard = useDraftDiscard();
  return <button type="button" onClick={() => discard(prefix)}>Discard</button>;
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

describe('persisted drafts', () => {
  it('restores what was saved for the case without saving it again', async () => {
    const save = vi.fn().mockResolvedValue(undefined);
    hydrateDrafts('case-a', { 'test.Finding': 'APP01 probably on ESX03' });
    configureDraftPersistence('case-a', save);
    render(<InCase caseId="case-a"><DraftField label="Finding" persist /></InCase>);
    expect(screen.getByLabelText('Finding')).toHaveValue('APP01 probably on ESX03');

    // Edited and put back before the debounce fires: nothing to save.
    fireEvent.change(screen.getByLabelText('Finding'), { target: { value: 'APP02' } });
    fireEvent.change(screen.getByLabelText('Finding'), { target: { value: 'APP01 probably on ESX03' } });
    await flushDrafts();
    expect(save).not.toHaveBeenCalled();
  });

  it('saves only opted-in drafts of the open case, in one batch', async () => {
    const user = userEvent.setup();
    const save = vi.fn().mockResolvedValue(undefined);
    configureDraftPersistence('case-a', save);
    render(
      <>
        <InCase caseId="case-a">
          <DraftField label="Finding" persist />
          <DraftField label="Filter" />
        </InCase>
        <InCase caseId="case-b"><DraftField label="Other" persist /></InCase>
      </>,
    );
    await user.type(screen.getByLabelText('Finding'), 'APP01');
    await user.type(screen.getByLabelText('Filter'), 'esx');
    await user.type(screen.getByLabelText('Other'), 'not this case');
    await flushDrafts();

    expect(save).toHaveBeenLastCalledWith({ 'test.Finding': 'APP01' });
    for (const [batch] of save.mock.calls) {
      expect(Object.keys(batch)).toEqual(['test.Finding']);
    }
  });

  it('deletes the saved copy when the form is discarded', async () => {
    const user = userEvent.setup();
    const save = vi.fn().mockResolvedValue(undefined);
    hydrateDrafts('case-a', { 'test.Finding': 'half-written finding' });
    configureDraftPersistence('case-a', save);
    const view = render(
      <InCase caseId="case-a"><DraftField label="Finding" persist /><DiscardButton prefix="test." /></InCase>,
    );
    await user.click(screen.getByRole('button', { name: 'Discard' }));
    await flushDrafts();
    expect(save).toHaveBeenCalledWith({ 'test.Finding': null });

    view.unmount();
    render(<InCase caseId="case-a"><DraftField label="Finding" persist /></InCase>);
    expect(screen.getByLabelText('Finding')).toHaveValue('');
  });

  it('keeps oversized drafts in memory only and drops an older saved copy', async () => {
    const save = vi.fn().mockResolvedValue(undefined);
    hydrateDrafts('case-a', { 'test.Pasted': 'short' });
    configureDraftPersistence('case-a', save);
    const view = render(
      <InCase caseId="case-a"><DraftField label="Pasted" persist /><DraftField label="Fresh" persist /></InCase>,
    );
    const huge = 'x'.repeat(MAX_PERSISTED_DRAFT_BYTES + 1);
    fireEvent.change(screen.getByLabelText('Pasted'), { target: { value: huge } });
    fireEvent.change(screen.getByLabelText('Fresh'), { target: { value: huge } });
    await flushDrafts();
    expect(save).toHaveBeenCalledTimes(1);
    expect(save).toHaveBeenCalledWith({ 'test.Pasted': null });

    view.unmount();
    render(<InCase caseId="case-a"><DraftField label="Fresh" persist /></InCase>);
    expect(screen.getByLabelText('Fresh')).toHaveValue(huge);
  });

  it('retries a failed save on the next flush', async () => {
    const save = vi.fn().mockRejectedValueOnce(new Error('database is locked')).mockResolvedValue(undefined);
    configureDraftPersistence('case-a', save);
    render(<InCase caseId="case-a"><DraftField label="Finding" persist /></InCase>);
    fireEvent.change(screen.getByLabelText('Finding'), { target: { value: 'APP01' } });
    await flushDrafts();
    await flushDrafts();
    expect(save).toHaveBeenCalledTimes(2);
    expect(save).toHaveBeenLastCalledWith({ 'test.Finding': 'APP01' });
  });

  it('flushes when the case is locked and saves nothing after that', async () => {
    const save = vi.fn().mockResolvedValue(undefined);
    configureDraftPersistence('case-a', save);
    render(<InCase caseId="case-a"><DraftField label="Finding" persist /></InCase>);
    fireEvent.change(screen.getByLabelText('Finding'), { target: { value: 'APP01' } });
    await endDraftPersistence();
    expect(save).toHaveBeenCalledWith({ 'test.Finding': 'APP01' });

    fireEvent.change(screen.getByLabelText('Finding'), { target: { value: 'APP02' } });
    await flushDrafts();
    expect(save).toHaveBeenCalledTimes(1);
  });
});
