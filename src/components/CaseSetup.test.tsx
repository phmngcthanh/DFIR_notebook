import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { SessionPayload } from '@/lib/api';
import CaseSetup from './CaseSetup';

const { listCasesMock, unlockCaseMock, createCaseMock } = vi.hoisted(() => ({
  listCasesMock: vi.fn(),
  unlockCaseMock: vi.fn(),
  createCaseMock: vi.fn(),
}));
vi.mock('@/lib/api', () => ({
  listCases: listCasesMock,
  unlockCase: unlockCaseMock,
  createCase: createCaseMock,
}));

function session(): SessionPayload {
  return {
    token: 'token',
    caseId: 'incident-7',
    case: null,
    expert: { name: 'Expert A', session_id: 'session-1', scope_network_ids: [] },
    revision: 0,
  };
}

describe('CaseSetup', () => {
  beforeEach(() => {
    listCasesMock.mockReset();
    unlockCaseMock.mockReset();
    createCaseMock.mockReset();
    localStorage.clear();
    listCasesMock.mockResolvedValue({ cases: ['incident-7'], allowCreate: true });
  });

  it('signs in with the case password alone — there is no username', async () => {
    const user = userEvent.setup();
    const onSession = vi.fn();
    unlockCaseMock.mockResolvedValue(session());
    render(<CaseSetup onSession={onSession} />);

    await waitFor(() => expect(screen.getByLabelText('Case *')).toBeInTheDocument());
    await user.type(screen.getByLabelText('Expert name *'), 'Expert A');
    await user.type(screen.getByLabelText('Case database password *'), 'existing-secret');
    await user.click(screen.getByRole('button', { name: 'Unlock Case' }));

    await waitFor(() => expect(unlockCaseMock).toHaveBeenCalledWith({
      caseId: 'incident-7',
      password: 'existing-secret',
      expertName: 'Expert A',
    }));
    expect(onSession).toHaveBeenCalledOnce();
  });

  it('keeps session attribution and the database password separate when creating a case', async () => {
    const user = userEvent.setup();
    const onSession = vi.fn();
    createCaseMock.mockResolvedValue(session());
    render(<CaseSetup onSession={onSession} />);

    await waitFor(() => expect(screen.getByRole('button', { name: /Create a new case/ })).toBeInTheDocument());
    await user.click(screen.getByRole('button', { name: /Create a new case/ }));
    await user.type(screen.getByLabelText('Case name *'), 'Incident 7');
    await user.type(screen.getByLabelText('Session expert name *'), 'Expert A');
    await user.type(screen.getByLabelText('Case database password *'), 'sixsix');
    await user.type(screen.getByLabelText('Confirm password *'), 'sixsix');
    await user.click(screen.getByRole('button', { name: 'Create Case' }));

    await waitFor(() => expect(createCaseMock).toHaveBeenCalledWith(expect.objectContaining({
      expertName: 'Expert A',
      databasePassword: 'sixsix',
    })));
    expect(onSession).toHaveBeenCalledOnce();
  });

  it('does not submit a new case when password confirmation differs', async () => {
    const user = userEvent.setup();
    render(<CaseSetup onSession={vi.fn()} />);

    await waitFor(() => expect(screen.getByRole('button', { name: /Create a new case/ })).toBeInTheDocument());
    await user.click(screen.getByRole('button', { name: /Create a new case/ }));
    await user.type(screen.getByLabelText('Case name *'), 'Incident 8');
    await user.type(screen.getByLabelText('Session expert name *'), 'Expert B');
    await user.type(screen.getByLabelText('Case database password *'), 'database-secret-1');
    await user.type(screen.getByLabelText('Confirm password *'), 'database-secret-2');
    await user.click(screen.getByRole('button', { name: 'Create Case' }));

    expect(screen.getByRole('alert')).toHaveTextContent('do not match');
    expect(createCaseMock).not.toHaveBeenCalled();
  });
});
