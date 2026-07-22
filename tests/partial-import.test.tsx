import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import PartialImportPanel from '@/components/PartialImportPanel';
import type { PartialImportPreview } from '@/types';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@/lib/api', () => ({ invoke: invokeMock, downloadText: vi.fn(), pickTextFile: vi.fn() }));

const preview: PartialImportPreview = {
  preview_id: 'preview-1', case_id: 'case-1', source: 'Expert extraction', source_kind: 'partial', warnings: [],
  changes: [
    {
      id: 'timeline-1', entity_type: 'timeline_event', entity_id: 'event-1', operation: 'create', title: 'Suspicious login',
      valid: true, recommended_selected: true, fields: [{ field: 'description', incoming: 'Suspicious login' }],
    },
    {
      id: 'note-1', entity_type: 'note', entity_id: 'note-1', operation: 'update', title: 'Expert finding',
      valid: true, recommended_selected: false, fields: [{ field: 'content', current: 'Local', incoming: 'Expert' }],
    },
  ],
};

describe('plain partial import review', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    invokeMock.mockImplementation(async (command: string) => {
      if (command === 'preview_partial_import_text') return { success: true, data: preview };
      if (command === 'validate_pending_partial_import') return { success: true, data: { valid: true, errors: [], selected_count: 2, create_count: 1, update_count: 1 } };
      if (command === 'apply_pending_partial_import') return { success: true, data: { created: 1, updated: 1, entities: { timeline_event: 1, note: 1 }, commit_id: 'commit-1' } };
      throw new Error(`Unexpected command: ${command}`);
    });
  });

  it('previews without mutation and requires a reviewed section policy before apply', async () => {
    const onApplied = vi.fn();
    const user = userEvent.setup();
    render(<PartialImportPanel disabled={false} onApplied={onApplied} />);

    fireEvent.change(screen.getByPlaceholderText(/Paste dfir-investigator-partial JSON/), { target: { value: '{"format":"dfir-investigator-partial"}' } });
    await user.click(screen.getByRole('button', { name: 'Parse, verify, and preview' }));
    await screen.findByText('Expert extraction');
    expect(invokeMock).not.toHaveBeenCalledWith('apply_pending_partial_import', expect.anything());

    const notesSection = screen.getByText('Expert notes').closest('div.overflow-hidden');
    expect(notesSection).not.toBeNull();
    await user.click(within(notesSection as HTMLElement).getByRole('button', { name: 'Use incoming versions' }));
    await user.click(screen.getByRole('button', { name: 'Validate and confirm 2' }));

    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('validate_pending_partial_import', {
      previewId: 'preview-1', selectedChangeIds: ['timeline-1', 'note-1'],
    }));
    expect(window.confirm).toHaveBeenCalled();
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('apply_pending_partial_import', {
      previewId: 'preview-1', selectedChangeIds: ['timeline-1', 'note-1'],
    }));
    expect(onApplied).toHaveBeenCalled();
  });
});
