import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { SearchHit } from '@/types';
import CaseSearch from './CaseSearch';

const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@/lib/api', () => ({ invoke: invokeMock }));

const indicator: SearchHit = { entity_type: 'ioc', entity_id: 'ioc-1', title: '10.0.0.15', field: 'Value', detail: '10.0.0.15' };
const asset: SearchHit = { entity_type: 'asset', entity_id: 'asset-1', title: 'APP01', field: 'IP address', detail: '10.0.0.15' };

const searchBox = () => screen.getByRole('textbox', { name: 'Search the case' });

describe('CaseSearch', () => {
  beforeEach(() => {
    invokeMock.mockReset();
    invokeMock.mockImplementation(async (command: string, args: { query: string }) => {
      if (command !== 'search_case_records') throw new Error(`Unexpected command: ${command}`);
      // The core returns the indicator first; the dialog still lists assets first.
      return { success: true, data: args.query === '10.0.0.15' ? [indicator, asset] : [] };
    });
  });

  it('searches the case once two characters are typed', async () => {
    const user = userEvent.setup();
    render(<CaseSearch onClose={vi.fn()} onOpen={vi.fn()} />);
    expect(searchBox()).toHaveFocus();

    await user.type(searchBox(), '1');
    expect(screen.getByText(/^Search hostnames, IPs/)).toBeInTheDocument();
    await user.type(searchBox(), '0.0.0.15');
    await screen.findByText('APP01');
    expect(invokeMock).toHaveBeenLastCalledWith('search_case_records', { query: '10.0.0.15', limit: 60 });
    expect(invokeMock).not.toHaveBeenCalledWith('search_case_records', { query: '1', limit: 60 });
  });

  it('groups results by kind and opens the one picked with the keyboard', async () => {
    const user = userEvent.setup();
    const onOpen = vi.fn();
    render(<CaseSearch onClose={vi.fn()} onOpen={onOpen} />);
    await user.type(searchBox(), '10.0.0.15');

    const options = await screen.findAllByRole('option');
    expect(options).toHaveLength(2);
    expect(options[0]).toHaveTextContent('APP01');
    expect(options[0]).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByText('Assets')).toBeInTheDocument();
    expect(screen.getByText('Indicators')).toBeInTheDocument();

    await user.keyboard('{ArrowDown}');
    expect(options[1]).toHaveAttribute('aria-selected', 'true');
    await user.keyboard('{Enter}');
    expect(onOpen).toHaveBeenCalledWith(indicator);
  });

  it('says when nothing matches and closes with Esc', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(<CaseSearch onClose={onClose} onOpen={vi.fn()} />);
    await user.type(searchBox(), 'zz-unknown');
    expect(await screen.findByText('Nothing in this case matches “zz-unknown”.')).toBeInTheDocument();

    await user.keyboard('{Escape}');
    expect(onClose).toHaveBeenCalledOnce();
  });
});
