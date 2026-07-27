import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import CasePicker from './CasePicker';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@/lib/api', () => ({ invoke: invokeMock }));

const localCases = [
  { file_name: 'acme-intrusion.db', size_bytes: 245760, modified_at: '2026-07-19T10:00:00Z' },
  { file_name: 'retail-breach.db', size_bytes: 1048576, modified_at: '2026-07-18T08:00:00Z' },
];

describe('CasePicker', () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it('lists local case files with sizes', async () => {
    invokeMock.mockResolvedValue({ success: true, data: localCases });
    render(<CasePicker onComplete={vi.fn()} />);
    await waitFor(() => expect(screen.getByText('acme-intrusion.db')).toBeInTheDocument());
    expect(invokeMock).toHaveBeenCalledWith('list_local_cases');
    expect(screen.getByText('retail-breach.db')).toBeInTheDocument();
    expect(screen.getByText(/240\.0 KB/)).toBeInTheDocument();
  });

  it('unlocks a selected case with the entered password', async () => {
    const user = userEvent.setup();
    const onComplete = vi.fn();
    invokeMock.mockImplementation(async (command: string) => {
      if (command === 'list_local_cases') return { success: true, data: localCases };
      return { success: true, data: 'Case opened' };
    });
    render(<CasePicker onComplete={onComplete} />);
    await waitFor(() => expect(screen.getByText('acme-intrusion.db')).toBeInTheDocument());

    await user.click(screen.getByText('acme-intrusion.db'));
    await user.type(screen.getByLabelText('Database file password'), 'field-secret');
    await user.click(screen.getByRole('button', { name: 'Unlock Case' }));

    expect(invokeMock).toHaveBeenCalledWith('open_local_case', {
      fileName: 'acme-intrusion.db',
      databasePassword: 'field-secret',
    });
    expect(onComplete).toHaveBeenCalledOnce();
  });

  it('shows the empty state and a new-case entry point', async () => {
    invokeMock.mockResolvedValue({ success: true, data: [] });
    render(<CasePicker onComplete={vi.fn()} />);
    await waitFor(() => expect(screen.getByText(/No case files on this device yet/)).toBeInTheDocument());
    expect(screen.getByRole('button', { name: /New Case/ })).toBeInTheDocument();
  });
});
