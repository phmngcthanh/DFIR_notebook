import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import ExportImport from '@/components/ExportImport';
import type { MergePreview } from '@/types';

const { invokeMock, pickTextFileMock, downloadTextMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  pickTextFileMock: vi.fn(),
  downloadTextMock: vi.fn(),
}));
vi.mock('@/lib/api', () => ({
  invoke: invokeMock,
  pickTextFile: pickTextFileMock,
  downloadText: downloadTextMock,
}));

const preview: MergePreview = {
  bundle_id: 'bundle-1', case_id: 'case-1', base_commit_id: 'base', head_commit_id: 'head', exported_by: 'Bob', exported_at: '2025-01-02T00:00:00Z', common_base: true,
  changes: [
    { id: 'network:n1', source_change_ids: ['c1'], entity_type: 'network', entity_id: 'n1', operation: 'update', classification: 'clean', author_name: 'Bob', message: 'Updated network', before: { id: 'n1', name: 'Office' }, local: { id: 'n1', name: 'Office' }, incoming: { id: 'n1', name: 'Office LAN' }, suggested: { id: 'n1', name: 'Office LAN' }, fields: [{ field: 'name', base: 'Office', local: 'Office', incoming: 'Office LAN', conflict: false }] },
    { id: 'asset:a1', source_change_ids: ['c2'], entity_type: 'asset', entity_id: 'a1', operation: 'update', classification: 'conflict', author_name: 'Bob', message: 'Updated PC', before: { id: 'a1', name: 'PC', ip_address: '10.0.0.2' }, local: { id: 'a1', name: 'PC', ip_address: '10.0.0.3' }, incoming: { id: 'a1', name: 'PC', ip_address: '10.0.0.4' }, suggested: { id: 'a1', name: 'PC', ip_address: '10.0.0.3' }, fields: [{ field: 'ip_address', base: '10.0.0.2', local: '10.0.0.3', incoming: '10.0.0.4', conflict: true }] },
  ],
};

describe('offline expert bundle review', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    pickTextFileMock.mockReset();
    downloadTextMock.mockReset();
    invokeMock.mockImplementation(async (command: string) => {
      if (command === 'list_case_history') return { success: true, data: [] };
      if (command === 'load_change_bundle_text') return { success: true, data: preview };
      if (command === 'apply_pending_change_bundle') return { success: true, data: { applied: 1, skipped: 1, merge_commit_id: 'merge-1' } };
      throw new Error(`Unexpected command: ${command}`);
    });
  });

  it('selects clean edits and leaves conflicts for the team to decide', async () => {
    const user = userEvent.setup(); const onImport = vi.fn();
    pickTextFileMock.mockResolvedValue({ name: 'changes-Bob.json', text: '{"bundle":true}' });
    render(<ExportImport refreshTrigger={0} onImport={onImport} />);
    await user.click(screen.getByRole('button', { name: 'Load for review' }));
    await screen.findByText(/2 entity changes/);

    // The browser reads the file; only its text reaches the server.
    expect(invokeMock).toHaveBeenCalledWith('load_change_bundle_text', { contents: '{"bundle":true}', password: null });

    const checkboxes = screen.getAllByRole('checkbox').filter((element) => !element.closest('label'));
    expect(checkboxes[0]).toBeChecked();
    expect(checkboxes[1]).not.toBeChecked();
    await user.click(screen.getByRole('button', { name: 'Apply 1 selected' }));

    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('apply_pending_change_bundle', {
      bundleId: 'bundle-1',
      decisions: [
        { change_id: 'network:n1', selected: true },
        { change_id: 'asset:a1', selected: false },
      ],
    }));
    expect(onImport).toHaveBeenCalled();
  });

  it('passes a confirmed portable password only for encrypted snapshot downloads', async () => {
    invokeMock.mockImplementation(async (command: string) => {
      if (command === 'list_case_history') return { success: true, data: [] };
      if (command === 'export_case_json') return { success: true, data: '{"dfirx":true}' };
      throw new Error(`Unexpected command: ${command}`);
    });
    const user = userEvent.setup();
    render(<ExportImport refreshTrigger={0} onImport={vi.fn()} />);
    await user.click(screen.getByRole('checkbox', { name: 'Encrypt downloaded snapshots' }));
    await user.type(screen.getByLabelText('Export password'), 'portable-secret');
    await user.type(screen.getByLabelText('Confirm password'), 'portable-secret');
    await user.click(screen.getByRole('button', { name: 'Download snapshot' }));

    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('export_case_json', { password: 'portable-secret' }));
    expect(downloadTextMock).toHaveBeenCalledWith('case-backup.dfirx', '{"dfirx":true}');
  });
});
