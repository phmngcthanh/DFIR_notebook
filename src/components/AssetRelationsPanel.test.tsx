import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Asset, AssetRelation } from '@/types';
import AssetRelationsPanel from './AssetRelationsPanel';

const { invokeMock, toastMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  toastMock: { error: vi.fn(), success: vi.fn(), info: vi.fn() },
}));
vi.mock('@/lib/api', () => ({ invoke: invokeMock }));
vi.mock('sonner', () => ({ toast: toastMock }));

const asset = (overrides: Partial<Asset> & { id: string; name: string }): Asset => ({
  ip_address: '', asset_type: 'server', suspicious: false, compromise_status: 'unknown', investigation_status: 'not_started', created_at: '', ...overrides,
});
const vm = asset({ id: 'vm', name: 'APP01', asset_type: 'vm', ip_address: '10.0.0.15' });
const host = asset({ id: 'host', name: 'ESX01', asset_type: 'hypervisor', ip_address: '10.0.9.10' });
const other = asset({ id: 'other', name: 'DB02', asset_type: 'vm' });
const link = (overrides: Partial<AssetRelation>): AssetRelation => ({
  id: 'rel-1', source_asset_id: 'vm', target_asset_id: 'host', relation_type: 'runs_on', note: '', created_at: '', ...overrides,
});

describe('AssetRelationsPanel', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    Object.values(toastMock).forEach((mock) => mock.mockReset());
  });

  it('shows what the asset runs on and, from the host, what runs on it', () => {
    const { unmount } = render(<AssetRelationsPanel asset={vm} assets={[vm, host, other]} relations={[link({ note: 'vCenter export' })]} onChanged={vi.fn()} />);
    expect(screen.getByText('runs on', { exact: false })).toBeInTheDocument();
    expect(screen.getByText('vCenter export')).toBeInTheDocument();
    unmount();

    render(<AssetRelationsPanel asset={host} assets={[vm, host, other]} relations={[link({})]} onChanged={vi.fn()} />);
    expect(screen.getByLabelText('Asset relations')).toHaveTextContent('ESX01 hosts APP01');
  });

  it('adds a link to another asset, defaulting a VM to "runs on"', async () => {
    const user = userEvent.setup();
    const onChanged = vi.fn();
    invokeMock.mockResolvedValue({ success: true, data: link({ target_asset_id: 'host' }) });
    render(<AssetRelationsPanel asset={vm} assets={[vm, host, other]} relations={[]} onChanged={onChanged} />);
    expect(screen.getByText(/No links to other assets/)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Add relation' }));
    expect(screen.getByRole('combobox', { name: 'Relation type' })).toHaveTextContent('runs on');
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
    await user.click(screen.getByRole('combobox', { name: 'Related asset' }));
    // The asset itself is never offered as its own target.
    expect(screen.queryByRole('option', { name: /APP01/ })).not.toBeInTheDocument();
    await user.click(await screen.findByRole('option', { name: 'ESX01 (10.0.9.10)' }));
    await user.type(screen.getByLabelText('Note'), 'moved in May');
    await user.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => expect(onChanged).toHaveBeenCalledOnce());
    expect(invokeMock).toHaveBeenCalledWith('create_new_asset_relation', {
      sourceAssetId: 'vm', targetAssetId: 'host', relationType: 'runs_on', note: 'moved in May',
    });
  });

  it('removes a link, and shows the core\'s message when a link cannot be saved', async () => {
    const user = userEvent.setup();
    const onChanged = vi.fn();
    invokeMock.mockResolvedValue({ success: true, data: true });
    render(<AssetRelationsPanel asset={vm} assets={[vm, host]} relations={[link({})]} onChanged={onChanged} />);
    await user.click(screen.getByRole('button', { name: 'Remove link to ESX01' }));
    await waitFor(() => expect(onChanged).toHaveBeenCalledOnce());
    expect(invokeMock).toHaveBeenCalledWith('remove_asset_relation', { id: 'rel-1' });

    invokeMock.mockResolvedValue({ success: false, error: 'Those assets are already related this way' });
    await user.click(screen.getByRole('button', { name: 'Add relation' }));
    await user.click(screen.getByRole('combobox', { name: 'Related asset' }));
    await user.click(await screen.findByRole('option', { name: 'ESX01 (10.0.9.10)' }));
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(toastMock.error).toHaveBeenCalledWith('Error: Those assets are already related this way'));
  });
});
