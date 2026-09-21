import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import EventLogPanel from './EventLogPanel';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));

vi.mock('@/lib/api', () => ({
  invoke: invokeMock,
  isDesktop: false,
  pickTextFile: vi.fn(),
}));

function statusPayload(open: boolean) {
  return { success: true, data: { open, fileName: 'case.dfirlogs', batches: open ? { batchCount: 1, recordCount: 2 } : null } };
}

// Typing a full log line plus the debounced search needs more than the
// 5 s default on slow runners.
const LONG = 60000;

describe('EventLogPanel', () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it('asks for the case password while the evidence store is closed', async () => {
    invokeMock.mockResolvedValue(statusPayload(false));
    render(<EventLogPanel refreshTrigger={0} />);

    expect(await screen.findByText('Open the event-log evidence store')).toBeInTheDocument();
    expect(screen.getByText('case.dfirlogs')).toBeInTheDocument();
  });

  it('imports pasted syslog text and promotes a selected record into the timeline', async () => {
    invokeMock.mockImplementation(async (command: string, args?: Record<string, unknown>) => {
      switch (command) {
        case 'get_event_log_store_status':
          return statusPayload(true);
        case 'list_event_log_batches':
          return { success: true, data: [] };
        case 'list_assets':
          return { success: true, data: [] };
        case 'import_event_log_text':
          return { success: true, data: { batchId: 'batch-1', imported: 1, skipped: 0 } };
        case 'search_event_log_records':
          return {
            success: true,
            data: {
              total: 1,
              rows: [{
                id: 7, batchId: 'batch-1', kind: 'syslog', eventTimeUtc: '2026-07-19T14:25:30.000Z',
                rawTime: null, host: 'fw-01', provider: 'sshd', channel: 'LOG_AUTHPRIV',
                eventId: null, level: 'info', message: 'Accepted publickey for root',
              }],
            },
          };
        case 'promote_event_logs_to_timeline':
          return { success: true, data: { created: 1 } };
        default:
          expect(args).toBeInstanceOf(Object);
          return { success: true, data: null };
      }
    });
    const onChanged = vi.fn();
    const user = userEvent.setup();
    render(<EventLogPanel refreshTrigger={0} onChanged={onChanged} />);

    await screen.findByText('Import an offline copy');
    await user.type(
      screen.getByPlaceholderText(/Jul 19 14:25:30 fw-01 sshd/),
      'Jul 19 14:25:30 fw-01 sshd[4321]: Accepted publickey for root',
    );
    await user.click(screen.getByRole('button', { name: 'Import pasted text' }));
    expect(await invokeMock.mock.calls.find(([command]) => command === 'import_event_log_text')).toBeDefined();

    const row = await screen.findByText('Accepted publickey for root');
    expect(row).toBeInTheDocument();
    const checkboxes = screen.getAllByRole('checkbox');
    await user.click(checkboxes[checkboxes.length - 1]);
    await user.click(screen.getByRole('button', { name: 'Promote to timeline' }));

    await vi.waitFor(() => {
      expect(invokeMock).toHaveBeenCalledWith('promote_event_logs_to_timeline', {
        recordIds: [7],
        assetId: null,
        severity: 'medium',
        eventType: 'event_log',
      });
    });
    expect(onChanged).toHaveBeenCalled();
  }, LONG);
});
