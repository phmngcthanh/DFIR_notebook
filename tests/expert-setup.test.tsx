import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import ExpertSetup from '@/components/ExpertSetup';
import type { ExpertIdentity, Network } from '@/types';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@/lib/api', () => ({ invoke: invokeMock }));

const network: Network = { id: 'zone-1', name: 'Office', subnet: '10.0.0.0/24', network_type: 'LAN', description: '', created_at: '2025-01-01T00:00:00Z' };

describe('expert session setup', () => {
  beforeEach(() => {
    localStorage.clear();
    invokeMock.mockReset();
    invokeMock.mockImplementation(async (command: string) => {
      if (command === 'list_networks') return { success: true, data: [network] };
      if (command === 'set_current_expert') return { success: true, data: { name: 'Alice', session_id: 'session-1', scope_label: 'Room 204', scope_network_ids: ['zone-1'] } satisfies ExpertIdentity };
      throw new Error(`Unexpected command: ${command}`);
    });
  });

  it('requires a name and sends optional soft scope for attribution', async () => {
    const onComplete = vi.fn();
    const user = userEvent.setup();
    render(<ExpertSetup onComplete={onComplete} />);
    await screen.findByText('Office');

    await user.click(screen.getByRole('button', { name: 'Start session' }));
    expect(screen.getByText('Expert name is required')).toBeInTheDocument();

    await user.type(screen.getByLabelText('Expert name *'), ' Alice ');
    await user.type(screen.getByLabelText('Optional assignment'), 'Room 204');
    await user.click(screen.getByLabelText('Office'));
    await user.click(screen.getByRole('button', { name: 'Start session' }));

    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('set_current_expert', {
      name: 'Alice', scopeLabel: 'Room 204', scopeNetworkIds: ['zone-1'],
    }));
    expect(onComplete).toHaveBeenCalledWith(expect.objectContaining({ name: 'Alice', scope_label: 'Room 204' }));
    expect(localStorage.getItem('dfir-expert-name')).toBe('Alice');
  });
});
