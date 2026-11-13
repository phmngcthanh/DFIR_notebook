import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Capture, CaptureLink, PartialImportPreview } from '@/types';
import CaptureInbox from './CaptureInbox';

const { invokeMock, toastMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  toastMock: { error: vi.fn(), success: vi.fn(), info: vi.fn() },
}));
vi.mock('@/lib/api', () => ({ invoke: invokeMock }));
vi.mock('sonner', () => ({ toast: toastMock }));

interface SentChange {
  change_id: string;
  entity_type: string;
  operation: string;
  target_id?: string;
  values: Record<string, unknown>;
}

const fieldNote = 'APP01, 10.0.0.15, probably on ESX03. Finance says they own it. Beacons to evil[.]example.';

function capture(overrides: Partial<Capture>): Capture {
  return {
    id: 'capture-1', content: fieldNote, source: 'Finance interview', status: 'open',
    captured_by: 'Expert A', team: 'Network exploration', links: [], resolution: '',
    created_at: '2026-11-12T08:00:00Z', updated_at: '2026-11-12T08:00:00Z', ...overrides,
  };
}

let captures: Capture[] = [];
let sent: SentChange[] = [];

function previewOf(changes: SentChange[]): PartialImportPreview {
  return {
    preview_id: 'preview-1', case_id: 'case-1', source: 'Capture', source_kind: 'partial', warnings: [],
    changes: changes.map((change) => ({
      id: change.change_id, entity_type: change.entity_type, entity_id: change.target_id ?? change.change_id,
      title: String(change.values.name ?? change.values.value ?? change.change_id),
      operation: 'create', valid: true, recommended_selected: true, fields: [],
    })),
  };
}

describe('CaptureInbox', () => {
  beforeEach(() => {
    captures = [capture({}), capture({ id: 'capture-2', content: 'Old lead, already handled', source: '', status: 'processed' })];
    sent = [];
    invokeMock.mockReset();
    Object.values(toastMock).forEach((mock) => mock.mockReset());
    invokeMock.mockImplementation(async (command: string, args: Record<string, unknown> = {}) => {
      switch (command) {
        case 'list_captures': return { success: true, data: captures };
        case 'update_existing_capture':
          captures = captures.map((item) => (item.id === args.id
            ? { ...item, status: args.status as Capture['status'], links: args.links as CaptureLink[], resolution: String(args.resolution) }
            : item));
          return { success: true, data: captures.find((item) => item.id === args.id) };
        case 'create_new_note': return { success: true, data: { id: 'note-1', title: args.title, content: args.content } };
        case 'get_current_case_info': return { success: true, data: { id: 'case-1', name: 'Incident 7' } };
        case 'list_assets':
        case 'list_networks':
        case 'list_network_interfaces':
        case 'list_iocs':
          return { success: true, data: [] };
        case 'preview_partial_import_text':
          sent = (JSON.parse(String(args.jsonData)) as { changes: SentChange[] }).changes;
          return { success: true, data: previewOf(sent) };
        case 'validate_pending_partial_import':
          return { success: true, data: { valid: true, errors: [], selected_count: sent.length, create_count: sent.length, update_count: 0 } };
        case 'apply_pending_partial_import':
          return { success: true, data: { created: sent.length, updated: 0, entities: {}, commit_id: 'commit-1' } };
        case 'discard_pending_partial_import': return { success: true, data: true };
        default: throw new Error(`Unexpected command: ${command}`);
      }
    });
  });

  it('shows open captures with who captured them, and filters by status', async () => {
    const user = userEvent.setup();
    render(<CaptureInbox refreshTrigger={0} onCapture={vi.fn()} />);
    expect(await screen.findByText(fieldNote)).toBeInTheDocument();
    expect(screen.getByText(/captured by Expert A \(Network exploration\)/)).toBeInTheDocument();
    expect(screen.queryByText('Old lead, already handled')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /^Processed/ }));
    expect(screen.getByText('Old lead, already handled')).toBeInTheDocument();
    expect(screen.queryByText(fieldNote)).not.toBeInTheDocument();
  });

  it('processes a capture into the ticked asset and indicator and links them to it', async () => {
    const user = userEvent.setup();
    render(<CaptureInbox refreshTrigger={0} onCapture={vi.fn()} />);
    await screen.findByText(fieldNote);
    await user.click(screen.getByRole('button', { name: 'Process' }));
    // The button stays where it was, so a double-click cannot land on "Save as note".
    expect(screen.getByRole('button', { name: 'Process' })).toBeDisabled();

    expect(await screen.findByRole('checkbox', { name: 'Add asset APP01' })).toBeChecked();
    expect(screen.getByRole('checkbox', { name: 'Add asset ESX03' })).not.toBeChecked();
    expect(screen.getByRole('checkbox', { name: 'Add indicator evil.example' })).toBeChecked();
    await user.click(screen.getByRole('button', { name: 'Review 2 selected' }));

    await screen.findByRole('button', { name: 'Apply and mark processed' });
    const assetChange = sent.find((change) => change.entity_type === 'asset');
    const iocChange = sent.find((change) => change.entity_type === 'ioc');
    // Only what the note says: a host and its address, no invented type or VM inventory.
    expect(assetChange?.values).toEqual({ name: 'APP01', asset_type: 'other', ip_address: '10.0.0.15', network_id: null });
    expect(sent.find((change) => change.entity_type === 'network_interface')?.values).toEqual(expect.objectContaining({
      asset_id: assetChange?.target_id, name: 'Primary', ip_address: '10.0.0.15', is_primary: true,
    }));
    expect(screen.getByText('create asset: APP01 (10.0.0.15)')).toBeInTheDocument();
    expect(screen.getByText('2 to apply')).toBeInTheDocument();
    // ESX03 was only mentioned, so it stayed unticked and is not proposed.
    expect(sent.filter((change) => change.entity_type === 'asset').map((change) => change.values.name)).toEqual(['APP01']);
    expect(iocChange?.values).toEqual({
      ioc_type: 'Domain',
      value: 'evil.example',
      description: expect.stringMatching(/^From capture: APP01, 10\.0\.0\.15.*\(source: Finance interview\)$/),
      threat_level: 'medium',
    });
    expect(invokeMock).not.toHaveBeenCalledWith('apply_pending_partial_import', expect.anything());

    await user.click(screen.getByRole('button', { name: 'Apply and mark processed' }));
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('update_existing_capture', expect.objectContaining({
      id: 'capture-1',
      content: fieldNote,
      status: 'processed',
      links: [
        { entity_type: 'asset', entity_id: assetChange?.target_id, title: 'APP01' },
        { entity_type: 'ioc', entity_id: iocChange?.target_id, title: 'evil.example' },
      ],
    })));
    // Processed captures leave the Open view; the text itself was never changed.
    await waitFor(() => expect(screen.queryByText(fieldNote)).not.toBeInTheDocument());
    expect(toastMock.success).toHaveBeenCalled();
  });

  it('keeps a capture as a note that says who captured it and where it came from', async () => {
    const user = userEvent.setup();
    render(<CaptureInbox refreshTrigger={0} onCapture={vi.fn()} />);
    await screen.findByText(fieldNote);
    await user.click(screen.getByRole('button', { name: 'Save as note' }));

    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('create_new_note', {
      title: expect.stringMatching(/^APP01, 10\.0\.0\.15, probably on ESX03\..*…$/),
      content: expect.stringMatching(new RegExp(`^${fieldNote.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\n\\n---\\nSource: Finance interview\\nCaptured by Expert A \\(Network exploration\\) on `)),
    }));
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('update_existing_capture', expect.objectContaining({
      id: 'capture-1',
      status: 'processed',
      links: [{ entity_type: 'note', entity_id: 'note-1', title: expect.any(String) }],
    })));
  });
});
