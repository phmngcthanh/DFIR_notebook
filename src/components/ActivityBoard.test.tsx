import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { HistoryCommit } from '@/types';
import ActivityBoard from './ActivityBoard';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@/lib/api', () => ({ invoke: invokeMock }));

function commit(overrides: Partial<HistoryCommit>): HistoryCommit {
  return {
    id: 'commit-1',
    author_name: 'Expert A',
    session_id: 'session-1',
    message: 'Edited case',
    created_at: '2026-07-18T09:00:00Z',
    parent_ids: ['parent-1'],
    changes: [],
    ...overrides,
  };
}

const history: HistoryCommit[] = [
  commit({
    id: 'baseline',
    author_name: 'system',
    session_id: 'system',
    message: 'Legacy case baseline',
  }),
  commit({
    id: 'commit-a1',
    message: 'Added compromised host',
    changes: [{
      id: 'change-1', entity_type: 'asset', entity_id: 'asset-1', operation: 'create',
      base_revision: 0, new_revision: 1, created_at: '2026-07-18T09:00:00Z',
      after: { name: 'WEB-SRV-01', ip_address: '10.0.0.5' },
    }],
  }),
  commit({
    id: 'commit-b1',
    author_name: 'Expert B',
    session_id: 'session-2',
    message: 'Marked asset suspicious',
    created_at: '2026-07-18T14:30:00Z',
    changes: [{
      id: 'change-2', entity_type: 'asset', entity_id: 'asset-1', operation: 'update',
      base_revision: 1, new_revision: 2, created_at: '2026-07-18T14:30:00Z',
      before: { name: 'WEB-SRV-01', is_suspicious: false, updated_at: '2026-07-18T09:00:00Z' },
      after: { name: 'WEB-SRV-01', is_suspicious: true, updated_at: '2026-07-18T14:30:00Z' },
    }],
  }),
  commit({
    id: 'commit-merge',
    message: 'Merged bundle from Expert B',
    created_at: '2026-07-19T08:00:00Z',
    parent_ids: ['commit-a1', 'commit-b1'],
  }),
];

describe('ActivityBoard', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    invokeMock.mockResolvedValue({ success: true, data: history });
  });

  it('shows one lane per expert and hides the system baseline', async () => {
    render(<ActivityBoard refreshTrigger={0} />);
    await waitFor(() => expect(screen.getByText('Expert A')).toBeInTheDocument());
    expect(invokeMock).toHaveBeenCalledWith('list_case_history', { limit: 1000 });
    expect(screen.getByText('Expert B')).toBeInTheDocument();
    expect(screen.queryByText('Legacy case baseline')).not.toBeInTheDocument();
    expect(screen.getByText('2 experts')).toBeInTheDocument();
    expect(screen.getByText('2 sessions')).toBeInTheDocument();
  });

  it('summarizes commits and marks merge commits', async () => {
    render(<ActivityBoard refreshTrigger={0} />);
    await waitFor(() => expect(screen.getByText('Added compromised host')).toBeInTheDocument());
    expect(screen.getByText('create asset')).toBeInTheDocument();
    expect(screen.getByText('merge')).toBeInTheDocument();
  });

  it('renders readable field diffs for updates', async () => {
    render(<ActivityBoard refreshTrigger={0} />);
    await waitFor(() => expect(screen.getByText('Marked asset suspicious')).toBeInTheDocument());
    expect(screen.getAllByText('WEB-SRV-01', { exact: false }).length).toBeGreaterThan(0);
    expect(screen.getByText('is suspicious:', { exact: false })).toBeInTheDocument();
    expect(screen.getByText('false')).toBeInTheDocument();
    expect(screen.getByText('true')).toBeInTheDocument();
  });
});
