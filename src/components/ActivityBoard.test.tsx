import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
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

describe('ActivityBoard teams and merged work', () => {
  const merged: HistoryCommit[] = [
    commit({
      id: 'lead-merge',
      author_name: 'Lead',
      session_id: 'session-lead',
      message: 'Merged bundle from Rev Analyst',
      scope: { team: 'Coordination' },
      created_at: '2026-07-20T18:00:00Z',
      parent_ids: ['base', 'bundle-head'],
      changes: [{
        id: 'merge-change-1', entity_type: 'ioc', entity_id: 'ioc-1', operation: 'create',
        base_revision: 0, new_revision: 1, created_at: '2026-07-20T18:00:00Z', after: { value: 'evil.example' },
      }],
      merged_commits: [{
        commit_id: 'rev-1',
        bundle_id: 'bundle-1',
        author_name: 'Rev Analyst',
        session_id: 'session-rev',
        message: 'Added C2 domain from sample A',
        scope: { team: 'Malware reverse engineering' },
        created_at: '2026-07-20T11:00:00Z',
        changes: [
          { id: 'rev-change-1', entity_type: 'ioc', entity_id: 'ioc-1', operation: 'create', applied: true },
          { id: 'rev-change-2', entity_type: 'note', entity_id: 'note-1', operation: 'create', applied: false },
        ],
      }],
    }),
  ];

  beforeEach(() => {
    invokeMock.mockReset();
    invokeMock.mockResolvedValue({ success: true, data: merged });
  });

  it("puts merged-in work in its author's lane, marked with who merged it", async () => {
    render(<ActivityBoard refreshTrigger={0} />);
    const original = await screen.findByText('Added C2 domain from sample A');
    const card = original.closest('details') as HTMLElement;
    expect(within(card).getByText('merged by Lead')).toBeInTheDocument();
    expect(within(card).getByText('not taken in the merge')).toBeInTheDocument();
    expect(screen.getByText('Rev Analyst')).toBeInTheDocument();
    expect(screen.getByText('Malware reverse engineering')).toBeInTheDocument();
    expect(screen.getByText(/brings in 1 original commit$/)).toBeInTheDocument();
    expect(screen.getByText('2 experts')).toBeInTheDocument();
  });

  it('filters the board to one team', async () => {
    const user = userEvent.setup();
    render(<ActivityBoard refreshTrigger={0} />);
    await screen.findByText('Added C2 domain from sample A');

    await user.click(screen.getByRole('combobox', { name: 'Filter by team' }));
    await user.click(await screen.findByRole('option', { name: 'Malware reverse engineering' }));

    expect(screen.getByText('Added C2 domain from sample A')).toBeInTheDocument();
    expect(screen.queryByText('Merged bundle from Rev Analyst')).not.toBeInTheDocument();
    expect(screen.getByText('1 expert')).toBeInTheDocument();
  });
});
