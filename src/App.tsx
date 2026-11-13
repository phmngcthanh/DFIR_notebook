import { lazy, Suspense, useCallback, useEffect, useState } from 'react';
import {
  Clock, Download, FileText, FolderOpen, GitGraph, Inbox, LayoutDashboard,
  Info, LockKeyhole, Network, NotebookPen, Plus, Route, ScrollText, Search, Server, ShieldAlert, SquareKanban, UserRound, Users,
} from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import type { ApiResponse, Case, ExpertIdentity, SearchHit, View } from '@/types';
import CaptureDialog from '@/components/CaptureDialog';
import CaseSearch from '@/components/CaseSearch';
import CaseSetup from '@/components/CaseSetup';
import LocalCaseSetup from '@/components/LocalCaseSetup';
import ExpertSetup from '@/components/ExpertSetup';
import CasePicker from '@/components/mobile/CasePicker';
import MobileShell from '@/components/mobile/MobileShell';
import { useIsAndroid } from '@/hooks/use-platform';
import { Toaster } from '@/components/ui/sonner';
import { branding } from '@/config/branding';
import {
  getObservedRevision, getServerState, getToken, invoke, isDesktop, logout, noteRevision,
  resetRevision, session, SESSION_EXPIRED_EVENT, setToken, type SessionPayload,
} from '@/lib/api';
import {
  configureDraftPersistence, draftScope, endDraftPersistence, flushDrafts, hydrateDrafts, pruneDrafts, setDraftValue,
} from '@/lib/drafts';
import './App.css';

const Dashboard = lazy(() => import('@/components/Dashboard'));
const CaptureInbox = lazy(() => import('@/components/CaptureInbox'));
const NetworkManager = lazy(() => import('@/components/NetworkManager'));
const AssetManager = lazy(() => import('@/components/AssetManager'));
const NetworkTopology = lazy(() => import('@/components/NetworkTopology'));
const InvestigationGraph = lazy(() => import('@/components/InvestigationGraph'));
const TimelineView = lazy(() => import('@/components/TimelineView'));
const EventLogPanel = lazy(() => import('@/components/EventLogPanel'));
const IocManager = lazy(() => import('@/components/IocManager'));
const NoteManager = lazy(() => import('@/components/NoteManager'));
const ActivityBoard = lazy(() => import('@/components/ActivityBoard'));
const ExportImport = lazy(() => import('@/components/ExportImport'));
const AboutPage = lazy(() => import('@/components/AboutPage'));

const NAV_ITEMS: { view: View; label: string; icon: React.ReactNode }[] = [
  { view: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={18} /> },
  { view: 'inbox', label: 'Capture inbox', icon: <Inbox size={18} /> },
  { view: 'networks', label: 'Networks', icon: <Network size={18} /> },
  { view: 'assets', label: 'Assets', icon: <Server size={18} /> },
  { view: 'topology', label: 'Topology', icon: <GitGraph size={18} /> },
  { view: 'investigation', label: 'Investigation', icon: <Route size={18} /> },
  { view: 'timeline', label: 'Timeline', icon: <Clock size={18} /> },
  { view: 'eventlogs', label: 'Event Logs', icon: <ScrollText size={18} /> },
  { view: 'iocs', label: 'IOCs', icon: <ShieldAlert size={18} /> },
  { view: 'notes', label: 'Notes', icon: <FileText size={18} /> },
  { view: 'activity', label: 'Activity Board', icon: <SquareKanban size={18} /> },
  { view: 'export', label: 'Case Transfer', icon: <Download size={18} /> },
  { view: 'about', label: 'About', icon: <Info size={18} /> },
];

/** How often each browser asks the server whether anyone else has written. */
const POLL_INTERVAL_MS = 5000;

function App() {
  const android = useIsAndroid();
  const [currentCase, setCurrentCase] = useState<Case | null>(null);
  const [currentExpert, setCurrentExpert] = useState<ExpertIdentity | null>(null);
  const [activeExperts, setActiveExperts] = useState<string[]>([]);
  const [currentView, setCurrentView] = useState<View>('dashboard');
  const [showExpertSetup, setShowExpertSetup] = useState(false);
  const [showCaseSetup, setShowCaseSetup] = useState(false);
  const [caseSetupMode, setCaseSetupMode] = useState<'new' | 'open'>('new');
  const [restoring, setRestoring] = useState(() => session.hasSessions && Boolean(getToken()));
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [showCapture, setShowCapture] = useState(false);
  const [showSearch, setShowSearch] = useState(false);
  /** Bumped to remount the open view, e.g. when a search result presets its filters. */
  const [viewKey, setViewKey] = useState(0);
  const [draftsReady, setDraftsReady] = useState(false);

  const endSession = useCallback(() => {
    setToken(null);
    resetRevision();
    setCurrentCase(null);
    setCurrentExpert(null);
    setActiveExperts([]);
    setCurrentView('dashboard');
    setShowExpertSetup(false);
    setShowCaseSetup(false);
  }, []);

  // Desktop and mobile hold one case in process state: ask the backend what is
  // open. The server shell instead restores a session from its bearer token, so
  // a page reload does not re-prompt for the case password.
  useEffect(() => {
    if (session.hasSessions && !getToken()) return;
    let cancelled = false;
    void (async () => {
      try {
        const [caseResponse, expertResponse] = await Promise.all([
          invoke<ApiResponse<Case | null>>('get_current_case_info'),
          invoke<ApiResponse<ExpertIdentity | null>>('get_current_expert'),
        ]);
        if (cancelled) return;
        const loadedCase = caseResponse.success ? caseResponse.data ?? null : null;
        const expert = expertResponse.success ? expertResponse.data ?? null : null;
        setCurrentCase(loadedCase);
        setCurrentExpert(expert);
        // Offline shells collect the expert name after the case file unlocks.
        if (isDesktop) setShowExpertSetup(Boolean(loadedCase && !expert));
      } catch {
        if (!cancelled && session.hasSessions) endSession();
      } finally {
        if (!cancelled) setRestoring(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [endSession]);

  useEffect(() => {
    if (!session.hasSessions) return;
    const handler = () => {
      endSession();
      toast.error('This session has expired. Unlock the case again');
    };
    window.addEventListener(SESSION_EXPIRED_EVENT, handler);
    return () => window.removeEventListener(SESSION_EXPIRED_EVENT, handler);
  }, [endSession]);

  // Everyone edits the same case file, so all a browser has to do to stay
  // current is notice that the server's revision moved and re-fetch.
  // `refreshTrigger` is the signal every feature component already listens to.
  useEffect(() => {
    if (!session.hasLiveCollaboration || !currentCase) return;
    let cancelled = false;
    const poll = async () => {
      try {
        const state = await getServerState();
        if (cancelled) return;
        setActiveExperts(state.activeExperts);
        // Only a revision *beyond* what this browser has already observed — via
        // its own writes' response headers or a prior poll — means a teammate
        // edited. Our own writes never trip this.
        const known = getObservedRevision();
        if (known >= 0 && state.revision > known) {
          setRefreshTrigger((value) => value + 1);
          toast.info('The case was updated by another expert');
        }
        noteRevision(state.revision);
      } catch {
        // A dropped poll is not worth interrupting the investigator over, and an
        // expired session already surfaces through SESSION_EXPIRED_EVENT.
      }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [currentCase]);

  // Server shell: unlock/create already seeded the observed revision in the api layer.
  const handleSession = (payload: SessionPayload) => {
    setCurrentCase(payload.case ?? null);
    setCurrentExpert(payload.expert);
    setCurrentView('dashboard');
    setRefreshTrigger((value) => value + 1);
  };

  // Offline shells: the native case dialog finished, so re-read what is open.
  const handleLocalCaseComplete = async () => {
    setShowCaseSetup(false);
    try {
      const [caseResponse, expertResponse] = await Promise.all([
        invoke<ApiResponse<Case | null>>('get_current_case_info'),
        invoke<ApiResponse<ExpertIdentity | null>>('get_current_expert'),
      ]);
      const loadedCase = caseResponse.success ? caseResponse.data ?? null : null;
      const expert = expertResponse.success ? expertResponse.data ?? null : null;
      setCurrentCase(loadedCase);
      setCurrentExpert(expert);
      setShowExpertSetup(Boolean(loadedCase && !expert));
    } catch (reason) {
      toast.error(String(reason));
    }
    setRefreshTrigger((value) => value + 1);
  };

  const openLocalCaseSetup = (mode: 'new' | 'open') => {
    setCaseSetupMode(mode);
    setShowCaseSetup(true);
    setShowExpertSetup(false);
  };

  const closeLocalCase = async () => {
    try {
      // Save pending drafts while the case is still open to receive them.
      await flushDrafts();
      const response = await invoke<ApiResponse<boolean>>('close_current_case');
      if (!response.success) throw new Error(response.error || 'Could not lock case');
      setCurrentCase(null);
      setCurrentExpert(null);
      setCurrentView('dashboard');
      setShowCaseSetup(false);
      setShowExpertSetup(false);
      toast.success('Case locked and closed');
    } catch (reason) {
      toast.error(String(reason));
    }
  };

  const reloadCase = useCallback(async () => {
    try {
      const response = await invoke<ApiResponse<Case | null>>('get_current_case_info');
      if (response.success) setCurrentCase(response.data ?? null);
    } catch (reason) {
      toast.error(String(reason));
    }
  }, []);

  const handleExpertComplete = (expert: ExpertIdentity) => {
    setCurrentExpert(expert);
    setShowExpertSetup(false);
    setRefreshTrigger((value) => value + 1);
  };

  const closeSession = async () => {
    try {
      await flushDrafts();
      await logout();
      toast.success('Session closed');
    } catch (reason) {
      toast.error(String(reason));
    } finally {
      endSession();
    }
  };

  const signedIn = Boolean(currentCase && currentExpert);
  const workspaceOpen = signedIn && !showExpertSetup && !showCaseSetup;
  const caseId = currentCase?.id ?? null;
  const expertName = currentExpert?.name ?? null;
  // Drafts belong to one case and one expert. Switching either, locking, or
  // ending the session forgets every other scope's drafts.
  const scope = caseId ? `${caseId}\u0001${expertName ?? ''}` : null;

  useEffect(() => {
    pruneDrafts(scope);
  }, [scope]);

  // Persisted drafts: restore them before the views mount, then keep saving
  // them (debounced) for this expert while the case is open.
  useEffect(() => {
    if (!signedIn || !scope) {
      setDraftsReady(false);
      return;
    }
    let cancelled = false;
    setDraftsReady(false);
    void (async () => {
      try {
        const response = await invoke<ApiResponse<Record<string, unknown>>>('load_case_drafts');
        if (!cancelled && response.success && response.data) hydrateDrafts(scope, response.data);
      } catch {
        // Drafts are a convenience; the case opens without them.
      }
      if (cancelled) return;
      configureDraftPersistence(scope, async (drafts) => {
        const response = await invoke<ApiResponse<number>>('save_case_drafts', { drafts });
        if (!response.success) throw new Error(response.error || 'Could not save drafts');
      });
      setDraftsReady(true);
    })();
    return () => {
      cancelled = true;
      void endDraftPersistence();
    };
  }, [signedIn, scope]);

  // Capture (Alt+C) and search (Ctrl/Cmd+K) work from every screen, even
  // while typing in a field. `code` keeps Alt+C working on layouts where
  // Option+C types a character.
  useEffect(() => {
    if (!workspaceOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.altKey && !event.ctrlKey && !event.metaKey && event.code === 'KeyC') {
        event.preventDefault();
        setShowSearch(false);
        setShowCapture(true);
      } else if ((event.ctrlKey || event.metaKey) && !event.altKey && event.code === 'KeyK') {
        event.preventDefault();
        setShowCapture(false);
        setShowSearch(true);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [workspaceOpen]);

  // Open a search result: preset the target screen's filters so the record is
  // in view, then remount that screen so it reads them.
  const openSearchResult = (hit: SearchHit) => {
    setShowSearch(false);
    if (!scope) return;
    const title = hit.title.replace(/\u2026$/, '');
    let view: View = 'dashboard';
    switch (hit.entity_type) {
      case 'asset':
        setDraftValue(scope, 'assets.search', title);
        setDraftValue(scope, 'assets.expandedAssetId', hit.entity_id);
        view = 'assets';
        break;
      case 'network':
        setDraftValue(scope, 'networks.section', 'zones');
        setDraftValue(scope, 'networks.search', title);
        view = 'networks';
        break;
      case 'site':
        setDraftValue(scope, 'networks.section', 'sites');
        setDraftValue(scope, 'networks.search', title);
        view = 'networks';
        break;
      case 'firewall':
        setDraftValue(scope, 'networks.section', 'firewalls');
        setDraftValue(scope, 'networks.search', title);
        setDraftValue(scope, 'networks.selectedFirewallId', hit.entity_id);
        view = 'networks';
        break;
      case 'ioc':
        setDraftValue(scope, 'iocs.search', title);
        view = 'iocs';
        break;
      case 'timeline_event':
        setDraftValue(scope, 'timeline.search', title);
        view = 'timeline';
        break;
      case 'note':
        setDraftValue(scope, 'notes.search', title);
        view = 'notes';
        break;
      case 'capture':
        setDraftValue(scope, 'inbox.search', '');
        setDraftValue(scope, 'inbox.focusId', hit.entity_id);
        view = 'inbox';
        break;
      case 'attack_edge':
        view = 'investigation';
        break;
    }
    setCurrentView(view);
    setViewKey((value) => value + 1);
  };

  const captured = () => {
    setRefreshTrigger((value) => value + 1);
    toast.success('Captured', {
      description: 'It is waiting in the Capture inbox.',
      action: { label: 'Open inbox', onClick: () => setCurrentView('inbox') },
    });
  };

  const overlays = workspaceOpen && (
    <draftScope.Provider value={scope ?? ''}>
      {showCapture && <CaptureDialog onClose={() => setShowCapture(false)} onCaptured={captured} />}
      {showSearch && <CaseSearch onClose={() => setShowSearch(false)} onOpen={openSearchResult} />}
    </draftScope.Provider>
  );

  // One route table for every shell. The chrome around it differs — a sidebar on
  // desktop and in the browser, a touch shell on Android — but which screen is
  // shown, and what it is given, never does.
  const viewContent = !draftsReady ? <WorkspaceLoading /> : (
    <draftScope.Provider value={scope ?? ''}>
      <Suspense key={viewKey} fallback={<WorkspaceLoading />}>
        {currentView === 'dashboard' && <Dashboard refreshTrigger={refreshTrigger} onCaseUpdated={() => void reloadCase()} />}
        {currentView === 'inbox' && <CaptureInbox refreshTrigger={refreshTrigger} onCapture={() => setShowCapture(true)} />}
        {currentView === 'networks' && <NetworkManager refreshTrigger={refreshTrigger} />}
        {currentView === 'assets' && currentExpert && <AssetManager refreshTrigger={refreshTrigger} expert={currentExpert} />}
        {currentView === 'topology' && <NetworkTopology refreshTrigger={refreshTrigger} />}
        {currentView === 'investigation' && <InvestigationGraph refreshTrigger={refreshTrigger} />}
        {currentView === 'timeline' && <TimelineView refreshTrigger={refreshTrigger} />}
        {currentView === 'eventlogs' && <EventLogPanel refreshTrigger={refreshTrigger} onChanged={() => setRefreshTrigger((value) => value + 1)} />}
        {currentView === 'iocs' && <IocManager refreshTrigger={refreshTrigger} />}
        {currentView === 'notes' && <NoteManager refreshTrigger={refreshTrigger} />}
        {currentView === 'activity' && <ActivityBoard refreshTrigger={refreshTrigger} />}
        {currentView === 'export' && <ExportImport refreshTrigger={refreshTrigger} onImport={() => setRefreshTrigger((value) => value + 1)} />}
      </Suspense>
    </draftScope.Provider>
  );

  // Android keeps its own chrome: app-private case storage instead of a file
  // dialog, and a touch shell instead of the sidebar.
  if (android) {
    return (
      <div className="touch-ui h-screen bg-gray-50">
        <Toaster position="top-right" />
        {!currentCase && <CasePicker onComplete={() => void handleLocalCaseComplete()} />}
        {currentCase && showExpertSetup && (
          <ExpertSetup onComplete={handleExpertComplete} onCancel={currentExpert ? () => setShowExpertSetup(false) : undefined} />
        )}
        {currentCase && currentExpert && !showExpertSetup && (
          <MobileShell
            navItems={NAV_ITEMS}
            currentView={currentView}
            onNavigate={setCurrentView}
            caseName={currentCase.name}
            expertName={currentExpert.name}
            scopeLabel={currentExpert.scope_label || 'All zones'}
            onExpertClick={() => setShowExpertSetup(true)}
            onLock={() => void closeLocalCase()}
          >
            {currentView === 'about' ? <Suspense fallback={<WorkspaceLoading />}><AboutPage /></Suspense> : viewContent}
          </MobileShell>
        )}
        {overlays}
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-gray-50">
      <Toaster position="top-right" />
      <aside className="flex w-60 flex-shrink-0 flex-col bg-slate-900 text-white">
        <div className="border-b border-slate-700 p-4">
          <h1 className="text-lg font-bold text-cyan-400">{branding.shortName}</h1>
          <p className="mt-1 text-xs text-slate-400">{branding.tagline}</p>
        </div>
        <div className="border-b border-slate-700 p-3">
          {currentCase ? (
            <div className="text-xs">
              <p className="truncate font-semibold text-cyan-300">{currentCase.name}</p>
              <p className="mt-1 text-slate-400">{currentCase.client_name || 'No client name'}</p>
              {currentExpert && (
                <button className="mt-3 flex w-full items-center gap-2 rounded bg-slate-800 px-2 py-1.5 text-left hover:bg-slate-700" onClick={() => setShowExpertSetup(true)}>
                  <UserRound size={14} className="text-cyan-400" />
                  <span className="min-w-0">
                    <span className="block truncate text-slate-200">{currentExpert.name}</span>
                    <span className="block truncate text-slate-500">{[currentExpert.team, currentExpert.scope_label].filter(Boolean).join(' · ') || 'All zones'}</span>
                  </span>
                </button>
              )}
              {activeExperts.length > 1 && (
                <p className="mt-2 flex items-start gap-1.5 text-slate-400" title={activeExperts.join(', ')}>
                  <Users size={13} className="mt-0.5 shrink-0 text-cyan-500" />
                  <span className="truncate">{activeExperts.length} experts working now</span>
                </p>
              )}
            </div>
          ) : <p className="text-xs text-slate-500">{session.hasSessions ? 'No case unlocked' : 'No case loaded'}</p>}
        </div>
        {workspaceOpen && (
          <div className="space-y-1 border-b border-slate-700 p-2">
            <button onClick={() => setShowCapture(true)} className="flex w-full items-center gap-3 rounded-md bg-cyan-900/40 px-3 py-2 text-sm text-cyan-100 hover:bg-cyan-800/60" title="Record something you just learned (Alt+C)">
              <NotebookPen size={18} />Capture<kbd className="ml-auto text-[10px] text-cyan-300">Alt+C</kbd>
            </button>
            <button onClick={() => setShowSearch(true)} className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-slate-300 hover:bg-slate-800" title="Search the whole case (Ctrl+K)">
              <Search size={18} />Search<kbd className="ml-auto text-[10px] text-slate-500">Ctrl+K</kbd>
            </button>
          </div>
        )}
        <nav className="flex-1 space-y-1 overflow-y-auto px-2 py-2">
          {NAV_ITEMS.map((item) => (
            <button key={item.view} onClick={() => (item.view === 'about' || signedIn) && setCurrentView(item.view)} disabled={item.view !== 'about' && !signedIn}
              className={`flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors ${currentView === item.view ? 'bg-cyan-600 text-white' : item.view === 'about' || signedIn ? 'text-slate-300 hover:bg-slate-800' : 'cursor-not-allowed text-slate-600'}`}>
              {item.icon}{item.label}
            </button>
          ))}
        </nav>
        {session.hasSessions ? (
          signedIn && (
            <div className="border-t border-slate-700 p-3">
              <Button size="sm" variant="outline" className="w-full border-amber-700 text-xs text-amber-300 hover:bg-amber-950/40" onClick={() => void closeSession()}>
                <LockKeyhole size={14} className="mr-1" />End Session
              </Button>
            </div>
          )
        ) : (
          <div className="space-y-2 border-t border-slate-700 p-3">
            {currentCase && (
              <Button size="sm" variant="outline" className="w-full border-amber-700 text-xs text-amber-300 hover:bg-amber-950/40" onClick={() => void closeLocalCase()}>
                <LockKeyhole size={14} className="mr-1" />Lock / Close Case
              </Button>
            )}
            <Button size="sm" variant="outline" className="w-full border-cyan-600 text-xs text-cyan-400 hover:bg-cyan-900/30" onClick={() => openLocalCaseSetup('new')}>
              <Plus size={14} className="mr-1" />New Case
            </Button>
            <Button size="sm" variant="outline" className="w-full border-slate-600 text-xs text-slate-300 hover:bg-slate-800" onClick={() => openLocalCaseSetup('open')}>
              <FolderOpen size={14} className="mr-1" />Open Case
            </Button>
          </div>
        )}
      </aside>

      <main className="flex-1 overflow-hidden">
        {restoring && <WorkspaceLoading />}
        {/* Server shell: the unlock screen IS the login. Offline shells show a
            welcome until the investigator picks a case file through a dialog. */}
        {session.hasSessions
          ? !restoring && !signedIn && currentView !== 'about' && <CaseSetup onSession={handleSession} />
          : !currentCase && !showCaseSetup && currentView !== 'about' && (
              <div className="flex h-full items-center justify-center"><div className="text-center">
                <GitGraph size={64} className="mx-auto mb-4 text-slate-300" />
                <h2 className="mb-2 text-2xl font-bold text-slate-700">Welcome to {branding.productName}</h2>
                <p className="mb-6 text-slate-500">Create a local encrypted case or open an existing one.</p>
                <div className="flex justify-center gap-3">
                  <Button onClick={() => openLocalCaseSetup('new')} className="bg-cyan-600 hover:bg-cyan-700"><Plus size={16} className="mr-2" />New Case</Button>
                  <Button onClick={() => openLocalCaseSetup('open')} variant="outline"><FolderOpen size={16} className="mr-2" />Open Case</Button>
                </div>
              </div></div>
            )}
        {!session.hasSessions && showCaseSetup && <LocalCaseSetup mode={caseSetupMode} onComplete={() => void handleLocalCaseComplete()} onCancel={() => setShowCaseSetup(false)} />}
        {currentView === 'about' && !showCaseSetup && <div className="h-full overflow-auto"><Suspense fallback={<WorkspaceLoading />}><AboutPage /></Suspense></div>}
        {currentCase && showExpertSetup && !showCaseSetup && currentView !== 'about' && (
          <ExpertSetup onComplete={handleExpertComplete} onCancel={currentExpert ? () => setShowExpertSetup(false) : undefined} />
        )}
        {signedIn && currentExpert && currentView !== 'about' && !showExpertSetup && !showCaseSetup && (
          <div className="h-full overflow-auto">{viewContent}</div>
        )}
      </main>
      {overlays}
    </div>
  );
}

function WorkspaceLoading() {
  return (
    <div className="flex h-full items-center justify-center" role="status" aria-live="polite">
      <div className="text-center text-sm text-slate-500">
        <div className="mx-auto mb-3 h-6 w-6 animate-spin rounded-full border-2 border-slate-300 border-t-cyan-600" />
        Loading workspace...
      </div>
    </div>
  );
}

export default App;
