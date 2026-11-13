import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Asset, NetworkInterface } from '@/types';
import DuplicatePanel from './DuplicateAssetsPanel';

const { invokeMock, toastMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  toastMock: { error: vi.fn(), success: vi.fn(), info: vi.fn() },
}));
vi.mock('@/lib/api', () => ({ invoke: invokeMock }));
vi.mock('sonner', () => ({ toast: toastMock }));

const asset = (overrides: Partial<Asset> & { id: string; name: string }): Asset => ({
  ip_address: '', asset_type: 'server', suspicious: false, compromise_status: 'unknown', investigation_status: 'not_started', created_at: '', ...overrides,
});
const nic = (assetId: string, overrides: Partial<NetworkInterface>): NetworkInterface => ({
  id: `${assetId}-${overrides.ip_address}`, asset_id: assetId, name: 'Primary', ip_address: '', is_primary: true, ...overrides,
});

const assets = [
  asset({ id: 'a', name: 'APP01', ip_address: '10.0.0.5', origin: 'discovered' }),
  asset({ id: 'b', name: 'app01.corp.local', ip_address: '10.0.0.5', owner: 'Finance', origin: 'client_inventory' }),
  asset({ id: 'c', name: 'LONER', ip_address: '10.9.9.9' }),
];
const interfaces = [nic('a', { ip_address: '10.0.0.5', mac_address: 'aa:bb:cc:00:00:01' }), nic('b', { ip_address: '10.0.0.5', mac_address: 'AA-BB-CC-00-00-01' })];

describe('DuplicateAssetsPanel', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    Object.values(toastMock).forEach((mock) => mock.mockReset());
    vi.spyOn(window, 'confirm').mockReturnValue(true);
  });

  it('lists assets that look like one machine and merges the other into the one kept', async () => {
    const user = userEvent.setup();
    const onMerged = vi.fn();
    invokeMock.mockResolvedValue({
      success: true,
      data: { asset: assets[0], interfaces_moved: 1, interfaces_dropped: 1, timeline_events: 12, sightings: 1, attack_edges: 0, relations: 2 },
    });
    render(<DuplicatePanel assets={assets} interfaces={interfaces} onMerged={onMerged} onClose={vi.fn()} />);

    expect(screen.getByText('Very likely the same machine')).toBeInTheDocument();
    expect(screen.getByText('same MAC address, IP address and name')).toBeInTheDocument();
    expect(screen.queryByText('LONER')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Keep APP01 and merge app01.corp.local into it' }));
    expect(window.confirm).toHaveBeenCalledWith(expect.stringContaining('"app01.corp.local" is deleted'));
    await waitFor(() => expect(onMerged).toHaveBeenCalledOnce());
    expect(invokeMock).toHaveBeenCalledWith('merge_asset_records', { keepId: 'a', removeId: 'b' });
    expect(toastMock.success).toHaveBeenCalledWith('Merged app01.corp.local into APP01', {
      description: 'Moved 1 interface, 12 timeline events, 1 sighting, 0 attack paths and 2 relations.',
    });
  });

  it('merges nothing when the investigator declines, and shows the core\'s refusal', async () => {
    const user = userEvent.setup();
    vi.spyOn(window, 'confirm').mockReturnValueOnce(false);
    render(<DuplicatePanel assets={assets} interfaces={interfaces} onMerged={vi.fn()} onClose={vi.fn()} />);
    await user.click(screen.getByRole('button', { name: 'Keep app01.corp.local and merge APP01 into it' }));
    expect(invokeMock).not.toHaveBeenCalled();

    invokeMock.mockResolvedValue({ success: false, error: 'Asset to keep was not found' });
    await user.click(screen.getByRole('button', { name: 'Keep APP01 and merge app01.corp.local into it' }));
    await waitFor(() => expect(toastMock.error).toHaveBeenCalledWith('Error: Asset to keep was not found'));
  });

  it('says so when nothing looks duplicated', () => {
    render(<DuplicatePanel assets={[assets[2]]} interfaces={[]} onMerged={vi.fn()} onClose={vi.fn()} />);
    expect(screen.getByText('No two assets share a MAC address, a name, or an address.')).toBeInTheDocument();
  });
});
