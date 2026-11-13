import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Asset, Network, NetworkInterface, PartialImportPreview } from '@/types';
import DiscoveryImportPanel from './DiscoveryImportPanel';

const { invokeMock, toastMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  toastMock: { error: vi.fn(), success: vi.fn(), info: vi.fn(), warning: vi.fn() },
}));
vi.mock('@/lib/api', () => ({ invoke: invokeMock, pickTextFile: vi.fn() }));
vi.mock('sonner', () => ({ toast: toastMock }));

interface SentChange {
  change_id: string;
  entity_type: string;
  operation: string;
  target_id?: string;
  values: Record<string, unknown>;
}

const office = { id: 'net-office', name: 'Office LAN', subnet: '10.0.0.0/24' } as Network;
const app01 = { id: 'app', name: 'APP01', ip_address: '10.0.0.40', asset_type: 'server', suspicious: false, compromise_status: 'unknown', investigation_status: 'not_started', created_at: '' } as Asset;
const appNic = { id: 'nic-app', asset_id: 'app', name: 'Primary', ip_address: '10.0.0.40', is_primary: true } as NetworkInterface;
const inventory = { caseId: 'case-1', assets: [app01], networks: [office], networkInterfaces: [appNic] };

const ARP = '10.0.0.40 dev eth0 lladdr aa:bb:cc:dd:ee:40 REACHABLE\n10.0.0.99 dev eth0 lladdr aa:bb:cc:dd:ee:99 REACHABLE';

let sent: SentChange[] = [];

function previewOf(changes: SentChange[]): PartialImportPreview {
  return {
    preview_id: 'preview-1', case_id: 'case-1', source: 'ARP', source_kind: 'partial', warnings: [],
    changes: changes.map((change) => ({
      id: change.change_id, entity_type: change.entity_type, entity_id: change.target_id ?? change.change_id,
      title: String(change.values.name ?? change.values.ip_address ?? change.values.last_observed ?? change.change_id),
      operation: change.operation === 'upsert' ? 'create' : change.operation as 'update',
      valid: true, recommended_selected: true, fields: [],
    })),
  };
}

describe('DiscoveryImportPanel', () => {
  beforeEach(() => {
    sent = [];
    invokeMock.mockReset();
    Object.values(toastMock).forEach((mock) => mock.mockReset());
    invokeMock.mockImplementation(async (command: string, args?: Record<string, unknown>) => {
      switch (command) {
        case 'preview_partial_import_text':
          sent = (JSON.parse(String(args?.jsonData)) as { changes: SentChange[] }).changes;
          return { success: true, data: previewOf(sent) };
        case 'validate_pending_partial_import':
          return { success: true, data: { valid: true, errors: [], selected_count: sent.length, create_count: 0, update_count: 0 } };
        case 'apply_pending_partial_import':
          return { success: true, data: { created: 2, updated: 2, entities: {}, commit_id: 'commit-1' } };
        case 'discard_pending_partial_import': return { success: true, data: true };
        default: throw new Error(`Unexpected command: ${command}`);
      }
    });
  });

  const paste = (text: string) => fireEvent.change(screen.getByLabelText('Discovery output'), { target: { value: text } });

  it('reads an ARP table into rows, previews the chosen ones, and applies them as one reviewed import', async () => {
    const user = userEvent.setup();
    const onApplied = vi.fn();
    render(<DiscoveryImportPanel inventory={inventory} onApplied={onApplied} onClose={vi.fn()} />);
    paste(ARP);
    await user.click(screen.getByRole('button', { name: 'Read output' }));

    expect(screen.getByText('ARP / neighbor table')).toBeInTheDocument();
    expect(screen.getByText('2 hosts: 1 to add, 1 to update')).toBeInTheDocument();
    expect(screen.getByText(/Possibly: APP01 \(same IP address\)/)).toBeInTheDocument();
    expect(screen.getByText('Not in the case yet')).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Action for 10.0.0.40' })).toHaveTextContent('Update APP01');
    expect(invokeMock).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Review 2 hosts' }));
    await screen.findByRole('button', { name: /^Apply \d+ records?$/ });
    expect(sent.filter((change) => change.entity_type === 'asset').map((change) => [change.operation, change.values.name ?? Object.keys(change.values)])).toEqual([
      ['update', ['last_observed']],
      ['upsert', '10.0.0.99'],
    ]);
    // The matched asset's interface learns its MAC; the new host gets its own interface.
    expect(sent.some((change) => change.entity_type === 'network_interface' && change.operation === 'update' && change.target_id === 'nic-app')).toBe(true);
    expect(invokeMock).not.toHaveBeenCalledWith('apply_pending_partial_import', expect.anything());

    await user.click(screen.getByRole('button', { name: /^Apply \d+ records?$/ }));
    await waitFor(() => expect(onApplied).toHaveBeenCalledOnce());
    expect(invokeMock).toHaveBeenCalledWith('apply_pending_partial_import', { previewId: 'preview-1', selectedChangeIds: sent.map((change) => change.change_id) });
    expect(toastMock.success).toHaveBeenCalledWith('Recorded 2 new and 2 updated records from ARP / neighbor table');
    expect(screen.getByLabelText('Discovery output')).toHaveValue('');
  });

  it('leaves a host out when its row is skipped, and lets a new host be renamed first', async () => {
    const user = userEvent.setup();
    render(<DiscoveryImportPanel inventory={inventory} onApplied={vi.fn()} onClose={vi.fn()} />);
    paste(ARP);
    await user.click(screen.getByRole('button', { name: 'Read output' }));
    await user.click(screen.getByRole('combobox', { name: 'Action for 10.0.0.40' }));
    await user.click(await screen.findByRole('option', { name: 'Skip' }));
    fireEvent.change(screen.getByLabelText('New asset name'), { target: { value: 'PRINTER-3F' } });
    await user.click(screen.getByRole('button', { name: 'Review 1 host' }));

    await screen.findByRole('button', { name: /^Apply \d+ records?$/ });
    expect(sent.map((change) => [change.entity_type, change.values.name])).toEqual([['asset', 'PRINTER-3F'], ['network_interface', 'Primary']]);
  });

  it('explains output it cannot read and shows what needs a second look', async () => {
    const user = userEvent.setup();
    render(<DiscoveryImportPanel inventory={inventory} onApplied={vi.fn()} onClose={vi.fn()} />);
    paste('Finance says APP01 is theirs.');
    await user.click(screen.getByRole('button', { name: 'Read output' }));
    expect(toastMock.error).toHaveBeenCalledWith(expect.stringContaining('Could not tell what this output is'));

    paste('10.0.0.5 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n10.0.0.5 dev eth1 lladdr aa:bb:cc:dd:ee:02 STALE');
    await user.click(screen.getByRole('button', { name: 'Read output' }));
    expect(await screen.findByText(/10\.0\.0\.5 appears with 2 different MAC addresses/)).toBeInTheDocument();
  });
});
