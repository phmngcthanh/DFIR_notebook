import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Network, Site } from '@/types';
import NetworkManager from './NetworkManager';

const { invokeMock, toastMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  toastMock: { error: vi.fn(), success: vi.fn(), info: vi.fn() },
}));
vi.mock('@/lib/api', () => ({ invoke: invokeMock }));
vi.mock('sonner', () => ({ toast: toastMock }));

const hq: Site = { id: 'site-1', name: 'HQ Berlin', location: 'Alexanderplatz 1', description: 'Head office', created_at: '' };
const lan: Network = {
  id: 'net-1', name: 'Office LAN', subnet: '10.0.0.0/24', network_type: 'LAN', description: '', created_at: '',
  site_id: 'site-1', owner: 'IT Operations', operator: 'SecureCo MSP',
};

function field(label: string): HTMLInputElement {
  const found = screen.getAllByText(label).find((element) => element.tagName === 'LABEL');
  return found!.parentElement!.querySelector('input, textarea') as HTMLInputElement;
}

describe('NetworkManager sites and responsibility', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    Object.values(toastMock).forEach((mock) => mock.mockReset());
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    invokeMock.mockImplementation(async (command: string) => {
      switch (command) {
        case 'list_networks': return { success: true, data: [lan] };
        case 'list_network_connections':
        case 'list_firewalls': return { success: true, data: [] };
        case 'list_sites': return { success: true, data: [hq] };
        case 'create_new_site':
        case 'create_new_network':
        case 'update_existing_network': return { success: true, data: {} };
        case 'remove_site': return { success: false, error: 'Site is still used by 1 networks. Move those records to another site first.' };
        default: throw new Error(`Unexpected command: ${command}`);
      }
    });
  });

  it('shows each zone with its site and who owns and runs it', async () => {
    render(<NetworkManager refreshTrigger={0} />);
    expect(await screen.findByText('Office LAN')).toBeInTheDocument();
    expect(screen.getByText('HQ Berlin')).toBeInTheDocument();
    expect(screen.getByText('Owner: IT Operations')).toBeInTheDocument();
    expect(screen.getByText('Operated by: SecureCo MSP')).toBeInTheDocument();
  });

  it('adds a zone with its owner, operator, and site', async () => {
    const user = userEvent.setup();
    render(<NetworkManager refreshTrigger={0} />);
    await screen.findByText('Office LAN');
    await user.click(screen.getByRole('button', { name: /Add Zone/ }));
    fireEvent.change(field('Name *'), { target: { value: 'Plant OT' } });
    fireEvent.change(field('Owner (who governs it)'), { target: { value: 'Engineering' } });
    fireEvent.change(field('Operated by'), { target: { value: 'Plant IT' } });
    await user.click(screen.getByRole('combobox', { name: 'Site' }));
    await user.click(await screen.findByRole('option', { name: 'HQ Berlin' }));
    await user.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('create_new_network', expect.objectContaining({
      name: 'Plant OT', networkType: 'LAN', vlanId: null,
      context: { siteId: 'site-1', owner: 'Engineering', operator: 'Plant IT' },
    })));
  });

  it('lists sites with their zones, adds one, and shows why a site in use cannot be deleted', async () => {
    const user = userEvent.setup();
    render(<NetworkManager refreshTrigger={0} />);
    await screen.findByText('Office LAN');
    await user.click(screen.getByRole('tab', { name: /Sites/ }));
    expect(await screen.findByText('Alexanderplatz 1')).toBeInTheDocument();
    expect(screen.getByText('Office LAN', { selector: 'td' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /Add Site/ }));
    fireEvent.change(field('Name *'), { target: { value: 'DC East' } });
    fireEvent.change(field('Location'), { target: { value: 'Rack 12' } });
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('create_new_site', { id: null, name: 'DC East', location: 'Rack 12', description: null }));

    const row = screen.getByText('HQ Berlin').closest('tr') as HTMLElement;
    await user.click(row.querySelector('svg.lucide-trash-2')!.closest('button')!);
    await waitFor(() => expect(toastMock.error).toHaveBeenCalledWith('Error: Site is still used by 1 networks. Move those records to another site first.'));
  });
});
