import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import CaseSetup from './LocalCaseSetup';

const { invokeMock, toastMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  toastMock: { error: vi.fn(), success: vi.fn(), info: vi.fn() },
}));
vi.mock('@/lib/api', () => ({ invoke: invokeMock }));
vi.mock('sonner', () => ({ toast: toastMock }));

describe('LocalCaseSetup database passwords', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    toastMock.success.mockReset();
    localStorage.clear();
  });

  it('keeps session attribution and the database password separate', async () => {
    const user = userEvent.setup();
    const onComplete = vi.fn();
    invokeMock.mockResolvedValue({ success: true, data: 'case-id' });
    render(<CaseSetup mode="new" onComplete={onComplete} onCancel={vi.fn()} />);

    await user.type(screen.getByLabelText('Case name *'), 'Incident 7');
    await user.type(screen.getByLabelText('Session expert name *'), 'Expert A');
    await user.type(screen.getByLabelText('Database file password *'), 'sixsix');
    await user.type(screen.getByLabelText('Confirm password *'), 'sixsix');
    await user.click(screen.getByRole('button', { name: 'Create Case' }));

    expect(invokeMock).toHaveBeenCalledWith('create_new_case', expect.objectContaining({
      expertName: 'Expert A',
      databasePassword: 'sixsix',
    }));
    expect(onComplete).toHaveBeenCalledOnce();
  });

  it('does not submit a new case when password confirmation differs', async () => {
    const user = userEvent.setup();
    render(<CaseSetup mode="new" onComplete={vi.fn()} onCancel={vi.fn()} />);
    await user.type(screen.getByLabelText('Case name *'), 'Incident 8');
    await user.type(screen.getByLabelText('Session expert name *'), 'Expert B');
    await user.type(screen.getByLabelText('Database file password *'), 'database-secret-1');
    await user.type(screen.getByLabelText('Confirm password *'), 'database-secret-2');
    await user.click(screen.getByRole('button', { name: 'Create Case' }));
    expect(screen.getByRole('alert')).toHaveTextContent('do not match');
    expect(invokeMock).not.toHaveBeenCalled();
  });

  it('uses the entered database password to unlock an existing file', async () => {
    const user = userEvent.setup();
    invokeMock.mockResolvedValue({ success: true, data: 'Case opened' });
    render(<CaseSetup mode="open" onComplete={vi.fn()} onCancel={vi.fn()} />);
    await user.type(screen.getByLabelText('Database file password *'), 'existing-secret');
    await user.click(screen.getByRole('button', { name: 'Select and Unlock Case' }));
    expect(invokeMock).toHaveBeenCalledWith('open_existing_case', { databasePassword: 'existing-secret' });
  });

  it('restores a full backup with its password and reports the checksum check', async () => {
    const user = userEvent.setup();
    const onComplete = vi.fn();
    invokeMock.mockResolvedValue({
      success: true,
      data: {
        path: 'D:\\cases\\incident-7.db',
        caseName: 'Incident 7',
        manifest: { status: 'verified', files: ['incident-7.db', 'incident-7.dfirlogs'] },
        restoredEventLogs: true,
      },
    });
    render(<CaseSetup mode="open" onComplete={onComplete} onCancel={vi.fn()} />);
    await user.click(screen.getByRole('button', { name: 'Restore a full backup or redistributed master' }));
    await user.click(screen.getByRole('button', { name: 'Select Backup and Restore' }));
    expect(screen.getByRole('alert')).toHaveTextContent('Enter the backup password');
    expect(invokeMock).not.toHaveBeenCalled();

    await user.type(screen.getByLabelText('Database file password *'), 'backup-secret');
    await user.click(screen.getByRole('button', { name: 'Select Backup and Restore' }));
    expect(invokeMock).toHaveBeenCalledWith('restore_full_backup', { password: 'backup-secret' });
    expect(toastMock.success).toHaveBeenCalledWith('Restored Incident 7 with its event logs', {
      description: 'Checksums verified for incident-7.db, incident-7.dfirlogs.',
    });
    expect(onComplete).toHaveBeenCalledOnce();
    expect(screen.getByLabelText('Database file password *')).toHaveValue('');
  });
});
