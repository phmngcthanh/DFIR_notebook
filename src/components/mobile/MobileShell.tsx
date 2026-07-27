import { LockKeyhole, UserRound } from 'lucide-react';
import { useIsPortrait } from '@/hooks/use-platform';
import type { View } from '@/types';

export interface MobileNavItem {
  view: View;
  label: string;
  icon: React.ReactNode;
}

interface Props {
  navItems: MobileNavItem[];
  currentView: View;
  onNavigate: (view: View) => void;
  caseName: string;
  expertName?: string;
  scopeLabel?: string;
  onExpertClick: () => void;
  onLock: () => void;
  children: React.ReactNode;
}

/**
 * Tablet shell: top bar with case/expert identity, plus a landscape icon
 * rail or a portrait bottom bar (both scrollable) instead of the desktop
 * sidebar. Gated on platform detection in App.tsx — never on window width.
 */
export default function MobileShell({
  navItems, currentView, onNavigate, caseName, expertName, scopeLabel, onExpertClick, onLock, children,
}: Props) {
  const isPortrait = useIsPortrait();

  const nav = (horizontal: boolean) => (
    <nav
      aria-label="Main navigation"
      className={horizontal
        ? 'flex flex-shrink-0 items-stretch gap-1 overflow-x-auto border-t border-slate-700 bg-slate-900 px-1 py-1'
        : 'flex w-20 flex-shrink-0 flex-col items-stretch gap-1 overflow-y-auto border-r border-slate-700 bg-slate-900 px-1 py-2'}
    >
      {navItems.map((item) => (
        <button
          key={item.view}
          onClick={() => onNavigate(item.view)}
          className={`flex min-h-14 flex-col items-center justify-center gap-1 rounded-md px-2 py-1.5 text-[11px] leading-tight transition-colors ${
            currentView === item.view ? 'bg-cyan-600 text-white' : 'text-slate-300 hover:bg-slate-800'
          } ${horizontal ? 'min-w-16 flex-shrink-0' : ''}`}
        >
          {item.icon}
          <span className="truncate">{item.label}</span>
        </button>
      ))}
    </nav>
  );

  return (
    <div className="flex h-screen flex-col bg-gray-50">
      <header className="flex min-h-12 flex-shrink-0 items-center gap-3 bg-slate-900 px-3 py-1.5 text-white">
        <p className="min-w-0 flex-1 truncate text-sm font-semibold text-cyan-300">{caseName}</p>
        {expertName && (
          <button
            className="flex min-h-11 items-center gap-2 rounded bg-slate-800 px-3 text-left text-xs hover:bg-slate-700"
            onClick={onExpertClick}
          >
            <UserRound size={16} className="flex-shrink-0 text-cyan-400" />
            <span className="min-w-0">
              <span className="block max-w-40 truncate text-slate-200">{expertName}</span>
              {scopeLabel && <span className="block max-w-40 truncate text-slate-500">{scopeLabel}</span>}
            </span>
          </button>
        )}
        <button
          className="flex min-h-11 items-center gap-1 rounded border border-amber-700 px-3 text-xs text-amber-300 hover:bg-amber-950/40"
          onClick={onLock}
        >
          <LockKeyhole size={14} />Lock
        </button>
      </header>
      {isPortrait ? (
        <>
          <main className="min-h-0 flex-1 overflow-auto">{children}</main>
          {nav(true)}
        </>
      ) : (
        <div className="flex min-h-0 flex-1">
          {nav(false)}
          <main className="min-h-0 flex-1 overflow-auto">{children}</main>
        </div>
      )}
    </div>
  );
}
