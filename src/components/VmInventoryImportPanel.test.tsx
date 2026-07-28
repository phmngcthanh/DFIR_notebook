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

  it('renders vendor collection guidance and advances a parsed inventory into transactional review', async () => {
    invokeMock.mockResolvedValue({
      success: true,
      data: {
        preview_id: 'preview-1',
        case_id: 'case-1',
        source: 'VMware inventory',
        source_kind: 'partial',
        warnings: [],
        changes: [
          {
            id: 'asset-change',
            entity_type: 'asset',
            entity_id: 'asset-1',
            operation: 'create',
            title: 'Web Production',
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

    expect(screen.getByText('vim-cmd vmsvc/getallvms')).toBeInTheDocument();
    await user.type(
      screen.getByPlaceholderText('Paste VMware ESXi / vSphere VM inventory here…'),
      '"Id","Name","PowerState","MemoryGB"{enter}"VirtualMachine-vm-7","Web Production","PoweredOn","8"',
    );
    await user.click(screen.getByRole('button', { name: 'Parse and review' }));

    expect(await screen.findByText('Transactional preview')).toBeInTheDocument();
    expect(screen.getByText('Web Production')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Apply 2 reviewed records' })).toBeEnabled();
    expect(invokeMock).toHaveBeenCalledWith('preview_partial_import_text', {
      jsonData: expect.stringContaining('"dfir-vm-inventory-v1"'),
    });
  });
});
