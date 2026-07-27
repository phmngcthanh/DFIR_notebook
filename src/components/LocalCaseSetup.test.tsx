import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import CaseSetup from './LocalCaseSetup';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@/lib/api', () => ({ invoke: invokeMock }));

describe('LocalCaseSetup database passwords', () => {
  beforeEach(() => {
    invokeMock.mockReset();
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
});
