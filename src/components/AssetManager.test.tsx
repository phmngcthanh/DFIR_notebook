import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Asset, AssetRelation, NetworkInterface, Site } from '@/types';
import AssetManager from './AssetManager';

const { invokeMock, toastMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  toastMock: { error: vi.fn(), success: vi.fn(), info: vi.fn(), warning: vi.fn() },
}));
vi.mock('@/lib/api', () => ({ invoke: invokeMock, downloadText: vi.fn(), downloadBytes: vi.fn(), pickTextFile: vi.fn() }));
vi.mock('sonner', () => ({ toast: toastMock }));

const asset = (overrides: Partial<Asset> & { id: string; name: string }): Asset => ({
  ip_address: '', asset_type: 'server', suspicious: false, compromise_status: 'unknown', investigation_status: 'not_started', created_at: '', ...overrides,
});

const hq: Site = { id: 'site-1', name: 'HQ Berlin', location: '', description: '', created_at: '' };
let assets: Asset[] = [];
let interfaces: NetworkInterface[] = [];
let relations: AssetRelation[] = [];

const expert = { name: 'Analyst A', session_id: 's1', scope_network_ids: [] };

function field(label: string): HTMLInputElement {
  const found = screen.getAllByText(label).find((element) => element.tagName === 'LABEL');
  return found!.parentElement!.querySelector('input, textarea') as HTMLInputElement;
}

describe('AssetManager environment fields', () => {
  beforeEach(() => {
    assets = [
      asset({ id: 'a', name: 'APP01', ip_address: '10.0.0.15', origin: 'discovered', owner: 'Finance', site_id: 'site-1', last_observed: '2026-11-12T09:30:45.000Z' }),
      asset({ id: 'b', name: 'DB02', ip_address: '10.0.0.40', origin: 'client_inventory' }),
      asset({ id: 'c', name: 'PRINTER', ip_address: '10.0.0.60' }),
      asset({ id: 'host', name: 'ESX01', asset_type: 'hypervisor' }),
    ];
    interfaces = [];
    relations = [{ id: 'rel-1', source_asset_id: 'a', source_name: 'APP01', target_asset_id: 'host', target_name: 'ESX01', relation_type: 'runs_on', note: '', created_at: '' }];
    invokeMock.mockReset();
    Object.values(toastMock).forEach((mock) => mock.mockReset());
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    invokeMock.mockImplementation(async (command: string) => {
      switch (command) {
        case 'get_current_case_info': return { success: true, data: { id: 'case-1', name: 'Incident 7' } };
        case 'list_assets': return { success: true, data: assets };
        case 'list_networks': return { success: true, data: [] };
        case 'list_network_interfaces': return { success: true, data: interfaces };
        case 'get_infection_summary': return { success: true, data: { entities: [], iocs: [] } };
        case 'list_sites': return { success: true, data: [hq] };
        case 'list_asset_relations': return { success: true, data: relations };
        case 'create_new_asset':
        case 'update_existing_asset': return { success: true, data: assets[0] };
        default: throw new Error(`Unexpected command: ${command}`);
      }
    });
  });

  it('shows where each asset came from, who owns it, and where it runs, and filters to what was discovered', async () => {
    const user = userEvent.setup();
    render(<AssetManager refreshTrigger={0} expert={expert} />);
    const row = (await screen.findByText('APP01')).closest('tr') as HTMLElement;
    expect(within(row).getByText('discovered')).toBeInTheDocument();
    expect(within(row).getByText('Finance')).toBeInTheDocument();
    expect(within(row).getByText('on ESX01')).toBeInTheDocument();
    expect(within(row).getByText('HQ Berlin')).toBeInTheDocument();
    expect(within(row).getByText(/^seen /)).toBeInTheDocument();
    expect(within(screen.getByText('DB02').closest('tr') as HTMLElement).getByText('client inventory')).toBeInTheDocument();

    await user.click(screen.getAllByRole('combobox').find((element) => element.textContent === 'All origins')!);
    await user.click(await screen.findByRole('option', { name: 'Discovered, not in client inventory' }));
    expect(screen.getByText('APP01')).toBeInTheDocument();
    expect(screen.queryByText('DB02')).not.toBeInTheDocument();
    expect(screen.queryByText('PRINTER')).not.toBeInTheDocument();
  });

  it('finds assets by owner or site in the search box', async () => {
    render(<AssetManager refreshTrigger={0} expert={expert} />);
    await screen.findByText('APP01');
    fireEvent.change(screen.getByPlaceholderText('Search name, IP, MAC, OS, user, or owner…'), { target: { value: 'finance' } });
    expect(screen.getByText('APP01')).toBeInTheDocument();
    expect(screen.queryByText('DB02')).not.toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText('Search name, IP, MAC, OS, user, or owner…'), { target: { value: 'berlin' } });
    expect(screen.getByText('APP01')).toBeInTheDocument();
  });

  it('warns before adding a machine that is already in the case, then sends the environment fields with the new one', async () => {
    const user = userEvent.setup();
    render(<AssetManager refreshTrigger={0} expert={expert} />);
    await screen.findByText('APP01');
    await user.click(screen.getByRole('button', { name: /Add Asset/ }));
    fireEvent.change(field('Name *'), { target: { value: 'app01.corp.local' } });
    fireEvent.change(field('IP address'), { target: { value: '10.0.0.15' } });
    fireEvent.change(field('Owner (department)'), { target: { value: 'Finance' } });
    fireEvent.change(field('Operated by'), { target: { value: 'SecureCo MSP' } });

    vi.spyOn(window, 'confirm').mockReturnValueOnce(false);
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(window.confirm).toHaveBeenCalledWith(expect.stringContaining('APP01 (10.0.0.15): same IP address and name'));
    expect(invokeMock).not.toHaveBeenCalledWith('create_new_asset', expect.anything());

    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('create_new_asset', expect.objectContaining({
      name: 'app01.corp.local', ipAddress: '10.0.0.15', assetType: 'workstation',
      context: { siteId: '', owner: 'Finance', operator: 'SecureCo MSP', origin: 'unknown', lastObserved: '' },
    })));
  });

  it('edits an asset without rounding its stored observation time, and clears what was emptied', async () => {
    const user = userEvent.setup();
    render(<AssetManager refreshTrigger={0} expert={expert} />);
    const row = (await screen.findByText('APP01')).closest('tr') as HTMLElement;
    await user.click(row.querySelector('svg.lucide-pencil')!.closest('button')!);
    expect(field('Owner (department)')).toHaveValue('Finance');

    fireEvent.change(field('Owner (department)'), { target: { value: '' } });
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('update_existing_asset', expect.objectContaining({ id: 'a', name: 'APP01' })));
    const call = invokeMock.mock.calls.find(([command]) => command === 'update_existing_asset')!;
    const context = (call[1] as { context: Record<string, unknown> }).context;
    // Emptied fields go as empty strings (the core clears them); the untouched time is left out.
    expect(context).toEqual({ siteId: 'site-1', owner: '', operator: '', origin: 'discovered', lastObserved: undefined });
    expect('lastObserved' in JSON.parse(JSON.stringify(context))).toBe(false);
  });

  it('opens the duplicate check from the header and shows how many pairs there are', async () => {
    const user = userEvent.setup();
    assets.push(asset({ id: 'dup', name: 'app01.corp.local', ip_address: '10.0.0.15' }));
    render(<AssetManager refreshTrigger={0} expert={expert} />);
    await screen.findByText('APP01');
    await user.click(await screen.findByRole('button', { name: /Possible duplicates \(1\)/ }));
    expect(await screen.findByText('Very likely the same machine')).toBeInTheDocument();
  });
});
