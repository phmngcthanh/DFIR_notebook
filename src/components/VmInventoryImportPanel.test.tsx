import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import VmInventoryImportPanel from './VmInventoryImportPanel';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));

vi.mock('@/lib/api', () => ({
  invoke: invokeMock,
  pickTextFile: vi.fn(),
}));

describe('VmInventoryImportPanel', () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it('defaults to a pasted list and advances it into transactional review', async () => {
    invokeMock.mockResolvedValue({
      success: true,
      data: {
        preview_id: 'preview-1',
        case_id: 'case-1',
        source: 'Batch device list',
        source_kind: 'partial',
        warnings: [],
        changes: [
          {
            id: 'asset-change',
            entity_type: 'asset',
            entity_id: 'asset-1',
            operation: 'create',
            title: 'APP01',
            valid: true,
            recommended_selected: true,
            fields: [],
          },
          {
            id: 'nic-change',
            entity_type: 'network_interface',
            entity_id: 'nic-1',
            operation: 'create',
            title: 'Inventory NIC 1',
            valid: true,
            recommended_selected: true,
            fields: [],
          },
        ],
      },
    });
    const user = userEvent.setup();
    render(
      <VmInventoryImportPanel
        inventory={{ caseId: 'case-1', assets: [], networks: [], networkInterfaces: [] }}
        onApplied={vi.fn()}
        onClose={vi.fn()}
      />,
    );

    expect(screen.getByText('Paste / import assets')).toBeInTheDocument();
    expect(screen.getByRole('combobox')).toHaveTextContent('Pasted list (hostnames, IPs, CSV, adb)');
    expect(screen.getByText(/One device per line: name, ip, mac, os, type/)).toBeInTheDocument();
    await user.type(screen.getByPlaceholderText(/Paste devices here/), 'APP01, 10.0.0.15');
    await user.click(screen.getByRole('button', { name: 'Parse and review' }));

    expect(await screen.findByText('Transactional preview')).toBeInTheDocument();
    expect(screen.getByText('APP01')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Apply 2 reviewed records' })).toBeEnabled();
    expect(invokeMock).toHaveBeenCalledWith('preview_partial_import_text', {
      jsonData: expect.stringContaining('"dfir-vm-inventory-v1"'),
    });
  });

  it('keeps pasted text and the pending review when the panel is reopened', async () => {
    invokeMock.mockResolvedValue({
      success: true,
      data: { preview_id: 'preview-2', case_id: 'case-1', source: 'Batch device list', source_kind: 'partial', warnings: [], changes: [] },
    });
    const user = userEvent.setup();
    const props = {
      inventory: { caseId: 'case-1', assets: [], networks: [], networkInterfaces: [] },
      onApplied: vi.fn(),
      onClose: vi.fn(),
    };
    const first = render(<VmInventoryImportPanel {...props} />);
    await user.type(screen.getByPlaceholderText(/Paste devices here/), 'APP01, 10.0.0.15');
    await user.click(screen.getByRole('button', { name: 'Parse and review' }));
    await screen.findByText('Transactional preview');
    first.unmount();

    render(<VmInventoryImportPanel {...props} />);
    expect(screen.getByPlaceholderText(/Paste devices here/)).toHaveValue('APP01, 10.0.0.15');
    expect(screen.getByText('Transactional preview')).toBeInTheDocument();
  });
});
