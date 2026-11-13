import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import ExportImport from '@/components/ExportImport';
import type { HandoverStatus } from '@/types';

const { invokeMock, toastMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  toastMock: { error: vi.fn(), success: vi.fn(), info: vi.fn() },
}));
// The desktop shell: each expert works on their own copy and hands work over on removable media.
vi.mock('@/lib/api', () => ({
  invoke: invokeMock,
  pickTextFile: vi.fn(),
  downloadText: vi.fn(),
  session: { hasSessions: false, hasLiveCollaboration: false, hasLocalCaseFiles: true },
}));
vi.mock('sonner', () => ({ toast: toastMock }));

function status(overrides: Partial<HandoverStatus>): HandoverStatus {
  return {
    head_commit_id: 'head', shared_base_commit_id: 'base', base_created_at: '2026-11-11T18:00:00Z',
    base_on_main_path: true, commits_since_base: 3, changes_since_base: 5, last_change_at: '2026-11-12T07:30:00Z',
    ...overrides,
  };
}

function mockCase(handover: HandoverStatus) {
  invokeMock.mockImplementation(async (command: string) => {
    switch (command) {
      case 'list_case_history': return { success: true, data: [] };
      case 'get_handover_status': return { success: true, data: handover };
      case 'save_change_bundle_to_file': return { success: true, data: 'saved' };
      case 'save_full_backup':
        return {
          success: true,
          data: {
            path: 'E:\\handover\\incident-7.db', eventLogPath: 'E:\\handover\\incident-7.dfirlogs',
            manifestPath: 'E:\\handover\\incident-7.db.sha256', bytes: 4096, eventLogBytes: 2048, caseName: 'Incident 7',
          },
        };
      default: throw new Error(`Unexpected command: ${command}`);
    }
  });
}

describe('offline handover guide', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    Object.values(toastMock).forEach((mock) => mock.mockReset());
  });

  it('shows the work waiting to be handed in and saves it as a bundle', async () => {
    const user = userEvent.setup();
    mockCase(status({}));
    render(<ExportImport refreshTrigger={0} onImport={vi.fn()} />);

    expect(await screen.findByText(/^5 changes in 3 saves since the shared baseline/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save change bundle' }));
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('save_change_bundle_to_file', { password: null }));
    expect(toastMock.success).toHaveBeenCalledWith('Change bundle saved', { description: 'A .sha256 checksum file was written beside it.' });
  });

  it('has nothing to hand in until something changes', async () => {
    mockCase(status({ commits_since_base: 0, changes_since_base: 0 }));
    render(<ExportImport refreshTrigger={0} onImport={vi.fn()} />);
    expect(await screen.findByText(/^No changes since the shared baseline/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save change bundle' })).toBeDisabled();
  });

  it('asks for the latest master when this copy lacks the shared baseline', async () => {
    mockCase(status({ base_on_main_path: false }));
    render(<ExportImport refreshTrigger={0} onImport={vi.fn()} />);
    expect(await screen.findByText(/does not contain the shared baseline\. Restore the latest master/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save change bundle' })).toBeDisabled();
  });

  it('saves a full backup with the case password and then forgets the password', async () => {
    const user = userEvent.setup();
    mockCase(status({}));
    render(<ExportImport refreshTrigger={0} onImport={vi.fn()} />);
    await screen.findByText(/since the shared baseline/);

    const backup = screen.getByRole('button', { name: 'Save full backup' });
    expect(backup).toBeDisabled();
    await user.type(screen.getByLabelText('Case password for backup'), 'case-secret');
    await user.click(backup);

    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('save_full_backup', { password: 'case-secret' }));
    expect(toastMock.success).toHaveBeenCalledWith('Full backup saved: E:\\handover\\incident-7.db', {
      description: 'Includes the event-log store. Checksums are in incident-7.db.sha256.',
    });
    await waitFor(() => expect(screen.getByLabelText('Case password for backup')).toHaveValue(''));
  });
});
