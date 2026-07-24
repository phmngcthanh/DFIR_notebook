import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Ioc } from '@/types';
import IocManager from './IocManager';

const { invokeMock, downloadTextMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  downloadTextMock: vi.fn(),
}));
vi.mock('@/lib/api', () => ({ invoke: invokeMock, downloadText: downloadTextMock }));

function ioc(overrides: Partial<Ioc>): Ioc {
  return {
    id: 'ioc-1', ioc_type: 'IP', value: '10.0.0.5', description: '',
    threat_level: 'high', created_at: '2026-07-25T10:00:00Z', ...overrides,
  };
}

describe('IocManager export', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    downloadTextMock.mockReset();
  });

  it('exports the visible IOCs as CSV via a download', async () => {
    invokeMock.mockImplementation(async (command: string) => {
      if (command === 'list_iocs') return { success: true, data: [ioc({ id: 'ioc-1' }), ioc({ id: 'ioc-2', value: '10.0.0.6' })] };
      if (command === 'export_iocs_csv') return { success: true, data: 'id,type,value,threat_level,description,first_seen,last_seen,created_at\r\n' };
      throw new Error(`Unexpected command: ${command}`);
    });
    const user = userEvent.setup();
    render(<IocManager refreshTrigger={0} />);
    await waitFor(() => expect(screen.getByText('10.0.0.5')).toBeInTheDocument());

    await user.click(screen.getByRole('button', { name: /Export CSV/i }));

    // Sends the currently visible ids; server formats them.
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('export_iocs_csv', { ids: ['ioc-1', 'ioc-2'] }));
    expect(downloadTextMock).toHaveBeenCalledWith(expect.stringMatching(/^iocs-.*\.csv$/), expect.stringContaining('id,type,value'));
  });

  it('does not call the server when there are no IOCs to export', async () => {
    invokeMock.mockImplementation(async (command: string) => {
      if (command === 'list_iocs') return { success: true, data: [] };
      throw new Error(`Unexpected command: ${command}`);
    });
    render(<IocManager refreshTrigger={0} />);
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('list_iocs'));

    // With no IOCs the export buttons are disabled, so no export command fires.
    expect(screen.getByRole('button', { name: /Export CSV/i })).toBeDisabled();
    expect(screen.getByRole('button', { name: /Export STIX/i })).toBeDisabled();
    expect(invokeMock).not.toHaveBeenCalledWith('export_iocs_csv', expect.anything());
  });
});
