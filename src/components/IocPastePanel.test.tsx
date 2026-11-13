import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Ioc, PartialImportPreview } from '@/types';
import IocPastePanel from './IocPastePanel';

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

const recorded: Ioc[] = [{
  id: 'ioc-0', ioc_type: 'IP', value: '198.51.100.7', description: '', threat_level: 'high', created_at: '2026-11-12T08:00:00Z',
}];

let sent: SentChange[] = [];
/** Values the core rejects, with its message. */
let rejected: Record<string, string> = {};

function previewOf(changes: SentChange[]): PartialImportPreview {
  return {
    preview_id: 'preview-1', case_id: 'case-1', source: 'Pasted indicator list', source_kind: 'partial', warnings: [],
    changes: changes.map((change) => {
      const value = String(change.values.value);
      const error = rejected[value];
      return {
        id: change.change_id, entity_type: 'ioc', entity_id: change.target_id ?? change.change_id, title: value,
        operation: error ? 'invalid' : 'create', valid: !error, error, recommended_selected: !error, fields: [],
      };
    }),
  };
}

function paste(lines: string[]) {
  fireEvent.change(screen.getByLabelText('Indicators to paste'), { target: { value: lines.join('\n') } });
}

describe('IocPastePanel', () => {
  beforeEach(() => {
    sent = [];
    rejected = {};
    invokeMock.mockReset();
    Object.values(toastMock).forEach((mock) => mock.mockReset());
    invokeMock.mockImplementation(async (command: string, args?: Record<string, unknown>) => {
      switch (command) {
        case 'get_current_case_info': return { success: true, data: { id: 'case-1', name: 'Incident 7' } };
        case 'preview_partial_import_text':
          sent = (JSON.parse(String(args?.jsonData)) as { changes: SentChange[] }).changes;
          return { success: true, data: previewOf(sent) };
        case 'validate_pending_partial_import':
          return { success: true, data: { valid: true, errors: [], selected_count: sent.length, create_count: sent.length, update_count: 0 } };
        case 'apply_pending_partial_import':
          return { success: true, data: { created: sent.length, updated: 0, entities: { ioc: sent.length }, commit_id: 'commit-1' } };
        case 'discard_pending_partial_import': return { success: true, data: true };
        default: throw new Error(`Unexpected command: ${command}`);
      }
    });
  });

  it('refangs and types pasted values, skips recorded ones, and adds the ticked ones in one reviewed import', async () => {
    const user = userEvent.setup();
    const onApplied = vi.fn();
    render(<IocPastePanel iocs={recorded} onApplied={onApplied} onClose={vi.fn()} />);
    paste(['evil[.]example', '198.51.100.7', '44D88612FEA8A8F36DE82E1278ABB02F', 'MsWinZonesCacheCounterMutexA']);
    await user.click(screen.getByRole('button', { name: 'Detect' }));

    expect(screen.getByRole('checkbox', { name: 'Add evil.example' })).toBeChecked();
    expect(screen.getByText('new · refanged')).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Add 198.51.100.7' })).toBeDisabled();
    expect(screen.getByText('already recorded')).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Add MsWinZonesCacheCounterMutexA' })).not.toBeChecked();
    expect(screen.getByText('needs a type')).toBeInTheDocument();

    await user.click(screen.getByRole('combobox', { name: 'Type of MsWinZonesCacheCounterMutexA' }));
    await user.click(await screen.findByRole('option', { name: 'Mutex' }));
    await user.type(screen.getByLabelText('Description for every added indicator'), 'Reverse team, sample A');
    await user.click(screen.getByRole('button', { name: 'Add 3 indicators' }));

    await waitFor(() => expect(onApplied).toHaveBeenCalledOnce());
    const description = 'Reverse team, sample A';
    expect(sent.map((change) => change.values)).toEqual([
      { ioc_type: 'Domain', value: 'evil.example', description, threat_level: 'medium' },
      { ioc_type: 'Hash', value: '44d88612fea8a8f36de82e1278abb02f', description, threat_level: 'medium' },
      { ioc_type: 'Mutex', value: 'MsWinZonesCacheCounterMutexA', description, threat_level: 'medium' },
    ]);
    expect(invokeMock).toHaveBeenCalledWith('apply_pending_partial_import', {
      previewId: 'preview-1', selectedChangeIds: ['paste-ioc-0', 'paste-ioc-1', 'paste-ioc-2'],
    });
    expect(toastMock.success).toHaveBeenCalledWith('Added 3 indicators');
    expect(screen.getByLabelText('Indicators to paste')).toHaveValue('');
  });

  it('shows the values the core rejects and adds nothing', async () => {
    const user = userEvent.setup();
    const onApplied = vi.fn();
    rejected = { 'invoice.pdf.exe': 'A file path must include a directory' };
    render(<IocPastePanel iocs={[]} onApplied={onApplied} onClose={vi.fn()} />);
    paste(['evil[.]example', 'invoice.pdf.exe']);
    await user.click(screen.getByRole('button', { name: 'Detect' }));

    // Typed as a file name; the investigator overrides it with a type that does not fit.
    await user.click(screen.getByRole('combobox', { name: 'Type of invoice.pdf.exe' }));
    await user.click(await screen.findByRole('option', { name: 'File path' }));
    await user.click(screen.getByRole('button', { name: 'Add 2 indicators' }));

    expect(await screen.findByText('invoice.pdf.exe: A file path must include a directory')).toBeInTheDocument();
    expect(invokeMock).toHaveBeenCalledWith('discard_pending_partial_import', { previewId: 'preview-1' });
    expect(invokeMock).not.toHaveBeenCalledWith('apply_pending_partial_import', expect.anything());
    expect(toastMock.error).toHaveBeenCalledWith(expect.stringContaining('1 value is not valid for the chosen type'));
    expect(onApplied).not.toHaveBeenCalled();
  });

  it('says so when the text holds no values', async () => {
    const user = userEvent.setup();
    render(<IocPastePanel iocs={[]} onApplied={vi.fn()} onClose={vi.fn()} />);
    paste(['Contacted the client about this today.']);
    await user.click(screen.getByRole('button', { name: 'Detect' }));
    expect(toastMock.info).toHaveBeenCalled();
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
  });
});
