import { lazy, Suspense, useCallback, useEffect, useState } from 'react';
import {
  Clock, Download, FileText, FolderOpen, GitGraph, LayoutDashboard,
  Info, LockKeyhole, Network, Plus, Route, Server, ShieldAlert, SquareKanban, UserRound, Users,
} from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import type { ApiResponse, Case, ExpertIdentity, View } from '@/types';
import CaseSetup from '@/components/CaseSetup';
import LocalCaseSetup from '@/components/LocalCaseSetup';
import ExpertSetup from '@/components/ExpertSetup';
import { Toaster } from '@/components/ui/sonner';
import { branding } from '@/config/branding';
import {
  getObservedRevision, getServerState, getToken, invoke, isDesktop, logout, noteRevision,
  resetRevision, session, SESSION_EXPIRED_EVENT, setToken, type SessionPayload,
} from '@/lib/api';
import './App.css';

const Dashboard = lazy(() => import('@/components/Dashboard'));
const NetworkManager = lazy(() => import('@/components/NetworkManager'));
const AssetManager = lazy(() => import('@/components/AssetManager'));
const NetworkTopology = lazy(() => import('@/components/NetworkTopology'));
const InvestigationGraph = lazy(() => import('@/components/InvestigationGraph'));
const TimelineView = lazy(() => import('@/components/TimelineView'));
const IocManager = lazy(() => import('@/components/IocManager'));
const NoteManager = lazy(() => import('@/components/NoteManager'));
const ActivityBoard = lazy(() => import('@/components/ActivityBoard'));
const ExportImport = lazy(() => import('@/components/ExportImport'));
const AboutPage = lazy(() => import('@/components/AboutPage'));

const NAV_ITEMS: { view: View; label: string; icon: React.ReactNode }[] = [
  { view: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={18} /> },
  { view: 'networks', label: 'Networks', icon: <Network size={18} /> },
  { view: 'assets', label: 'Assets', icon: <Server size={18} /> },
  { view: 'topology', label: 'Topology', icon: <GitGraph size={18} /> },
  { view: 'investigation', label: 'Investigation', icon: <Route size={18} /> },
  { view: 'timeline', label: 'Timeline', icon: <Clock size={18} /> },
  { view: 'iocs', label: 'IOCs', icon: <ShieldAlert size={18} /> },
  { view: 'notes', label: 'Notes', icon: <FileText size={18} /> },
  { view: 'activity', label: 'Activity Board', icon: <SquareKanban size={18} /> },
  { view: 'export', label: 'Case Transfer', icon: <Download size={18} /> },
  { view: 'about', label: 'About', icon: <Info size={18} /> },
];

/** How often each browser asks the server whether anyone else has written. */
const POLL_INTERVAL_MS = 5000;

function App() {
  const [currentCase, setCurrentCase] = useState<Case | null>(null);
  const [currentExpert, setCurrentExpert] = useState<ExpertIdentity | null>(null);
  const [activeExperts, setActiveExperts] = useState<string[]>([]);
  const [currentView, setCurrentView] = useState<View>('dashboard');
  const [showExpertSetup, setShowExpertSetup] = useState(false);
  const [showCaseSetup, setShowCaseSetup] = useState(false);
  const [caseSetupMode, setCaseSetupMode] = useState<'new' | 'open'>('new');
  const [restoring, setRestoring] = useState(() => session.hasSessions && Boolean(getToken()));
  const [refreshTrigger, setRefreshTrigger] = useState(0);

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
      await logout();
      toast.success('Session closed');
    } catch (reason) {
      toast.error(String(reason));
    } finally {
      endSession();
    }
  };

  const signedIn = Boolean(currentCase && currentExpert);

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
                    <span className="block truncate text-slate-500">{currentExpert.scope_label || 'All zones'}</span>
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
          <div className="h-full overflow-auto">
            <Suspense fallback={<WorkspaceLoading />}>
              {currentView === 'dashboard' && <Dashboard refreshTrigger={refreshTrigger} onCaseUpdated={() => void reloadCase()} />}
              {currentView === 'networks' && <NetworkManager refreshTrigger={refreshTrigger} />}
              {currentView === 'assets' && <AssetManager refreshTrigger={refreshTrigger} expert={currentExpert} />}
              {currentView === 'topology' && <NetworkTopology refreshTrigger={refreshTrigger} />}
              {currentView === 'investigation' && <InvestigationGraph refreshTrigger={refreshTrigger} />}
              {currentView === 'timeline' && <TimelineView refreshTrigger={refreshTrigger} />}
              {currentView === 'iocs' && <IocManager refreshTrigger={refreshTrigger} />}
              {currentView === 'notes' && <NoteManager refreshTrigger={refreshTrigger} />}
              {currentView === 'activity' && <ActivityBoard refreshTrigger={refreshTrigger} />}
              {currentView === 'export' && <ExportImport refreshTrigger={refreshTrigger} onImport={() => setRefreshTrigger((value) => value + 1)} />}
            </Suspense>
          </div>
        )}
      </main>
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
