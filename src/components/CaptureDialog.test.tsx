import { useState } from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { configureDraftPersistence, flushDrafts, hydrateDrafts } from '@/lib/drafts';
import type { Capture } from '@/types';
import CaptureDialog from './CaptureDialog';

const { invokeMock, toastMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  toastMock: { error: vi.fn(), success: vi.fn(), info: vi.fn() },
}));
vi.mock('@/lib/api', () => ({ invoke: invokeMock }));
vi.mock('sonner', () => ({ toast: toastMock }));

function saved(content: string, source: string): Capture {
  return {
    id: 'capture-1', content, source, status: 'open', captured_by: 'Expert A', team: 'Network exploration',
    links: [], resolution: '', created_at: '2026-11-12T08:00:00Z', updated_at: '2026-11-12T08:00:00Z',
  };
}

const textBox = () => screen.getByLabelText('What did you learn? *');

/** Like the app: closing the dialog unmounts it. */
function Host() {
  const [open, setOpen] = useState(true);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>Open capture</button>
      {open && <CaptureDialog onClose={() => setOpen(false)} onCaptured={vi.fn()} />}
    </>
  );
}

describe('CaptureDialog', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    toastMock.error.mockReset();
    invokeMock.mockImplementation(async (command: string, args: { content: string; source: string | null }) => {
      if (command === 'create_new_capture') return { success: true, data: saved(args.content, args.source ?? '') };
      throw new Error(`Unexpected command: ${command}`);
    });
  });

  it('saves the text exactly as typed with its source, then closes', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const onCaptured = vi.fn();
    render(<CaptureDialog onClose={onClose} onCaptured={onCaptured} />);

    expect(textBox()).toHaveFocus();
    await user.type(textBox(), '  APP01, 10.0.0.15{Enter}probably on ESX03  ');
    await user.type(screen.getByLabelText('Source'), 'Finance interview');
    await user.click(textBox());
    await user.keyboard('{Control>}{Enter}{/Control}');

    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('create_new_capture', {
      content: '  APP01, 10.0.0.15\nprobably on ESX03  ',
      source: 'Finance interview',
    }));
    expect(onCaptured).toHaveBeenCalledWith(expect.objectContaining({ id: 'capture-1' }));
    expect(onClose).toHaveBeenCalledOnce();
  });

  it('starts the next capture empty once one is saved, in memory and in the case file', async () => {
    const user = userEvent.setup();
    const save = vi.fn().mockResolvedValue(undefined);
    // A capture left half-typed before a restart, restored from the case.
    hydrateDrafts('', { 'capture.text': 'APP01 belongs to finance', 'capture.source': 'Finance interview' });
    configureDraftPersistence('', save);
    render(<Host />);
    expect(textBox()).toHaveValue('APP01 belongs to finance');

    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(invokeMock).toHaveBeenCalledWith('create_new_capture', { content: 'APP01 belongs to finance', source: 'Finance interview' });
    await flushDrafts();
    expect(save).toHaveBeenCalledWith({ 'capture.text': null, 'capture.source': null });

    await user.click(screen.getByRole('button', { name: 'Open capture' }));
    expect(textBox()).toHaveValue('');
    expect(screen.getByLabelText('Source')).toHaveValue('');
  });

  it('keeps the source and stays open to capture another', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(<CaptureDialog onClose={onClose} onCaptured={vi.fn()} />);
    await user.type(textBox(), 'APP01 belongs to finance');
    await user.type(screen.getByLabelText('Source'), 'Finance interview');
    await user.click(screen.getByRole('button', { name: 'Save and capture another' }));

    await waitFor(() => expect(textBox()).toHaveValue(''));
    expect(screen.getByLabelText('Source')).toHaveValue('Finance interview');
    expect(textBox()).toHaveFocus();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('refuses an empty capture', async () => {
    const user = userEvent.setup();
    render(<CaptureDialog onClose={vi.fn()} onCaptured={vi.fn()} />);
    await user.type(textBox(), '   ');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(toastMock.error).toHaveBeenCalledWith('Type or paste what you learned first');
    expect(invokeMock).not.toHaveBeenCalled();
  });

  it('closes with Esc and keeps the unsaved text for next time', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const first = render(<CaptureDialog onClose={onClose} onCaptured={vi.fn()} />);
    await user.type(textBox(), 'half a thought');
    await user.keyboard('{Escape}');
    expect(onClose).toHaveBeenCalledOnce();
    first.unmount();

    render(<CaptureDialog onClose={vi.fn()} onCaptured={vi.fn()} />);
    expect(textBox()).toHaveValue('half a thought');
    expect(invokeMock).not.toHaveBeenCalled();
  });
});
