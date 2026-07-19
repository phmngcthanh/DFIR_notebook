import { lazy, Suspense, useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  Clock, Download, FileText, FolderOpen, GitGraph, LayoutDashboard,
  Info, LockKeyhole, Network, Plus, Server, ShieldAlert, UserRound,
} from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import type { ApiResponse, Case, ExpertIdentity, View } from '@/types';
import CaseSetup from '@/components/CaseSetup';
import ExpertSetup from '@/components/ExpertSetup';
import { Toaster } from '@/components/ui/sonner';
import { branding } from '@/config/branding';
import './App.css';

const Dashboard = lazy(() => import('@/components/Dashboard'));
const NetworkManager = lazy(() => import('@/components/NetworkManager'));
const AssetManager = lazy(() => import('@/components/AssetManager'));
const NetworkTopology = lazy(() => import('@/components/NetworkTopology'));
const TimelineView = lazy(() => import('@/components/TimelineView'));
const IocManager = lazy(() => import('@/components/IocManager'));
const NoteManager = lazy(() => import('@/components/NoteManager'));
const ExportImport = lazy(() => import('@/components/ExportImport'));
const AboutPage = lazy(() => import('@/components/AboutPage'));

const NAV_ITEMS: { view: View; label: string; icon: React.ReactNode }[] = [
  { view: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={18} /> },
  { view: 'networks', label: 'Networks', icon: <Network size={18} /> },
  { view: 'assets', label: 'Assets', icon: <Server size={18} /> },
  { view: 'topology', label: 'Topology', icon: <GitGraph size={18} /> },
  { view: 'timeline', label: 'Timeline', icon: <Clock size={18} /> },
  { view: 'iocs', label: 'IOCs', icon: <ShieldAlert size={18} /> },
  { view: 'notes', label: 'Notes', icon: <FileText size={18} /> },
  { view: 'export', label: 'Expert Merge', icon: <Download size={18} /> },
  { view: 'about', label: 'About', icon: <Info size={18} /> },
];

function App() {
  const [currentCase, setCurrentCase] = useState<Case | null>(null);
  const [currentExpert, setCurrentExpert] = useState<ExpertIdentity | null>(null);
  const [currentView, setCurrentView] = useState<View>('dashboard');
  const [showCaseSetup, setShowCaseSetup] = useState(false);
  const [showExpertSetup, setShowExpertSetup] = useState(false);
  const [caseSetupMode, setCaseSetupMode] = useState<'new' | 'open'>('new');
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  const loadCase = useCallback(async () => {
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
    } catch {
      setCurrentCase(null);
      setCurrentExpert(null);
    }
  }, []);

  useEffect(() => {
    const task = window.setTimeout(() => void loadCase(), 0);
    return () => window.clearTimeout(task);
  }, [loadCase]);

  const handleCaseComplete = async () => {
    setShowCaseSetup(false);
    await loadCase();
    setRefreshTrigger((value) => value + 1);
  };

  const openCaseSetup = (mode: 'new' | 'open') => {
    setCaseSetupMode(mode);
    setShowCaseSetup(true);
    setShowExpertSetup(false);
  };

  const handleExpertComplete = (expert: ExpertIdentity) => {
    setCurrentExpert(expert);
    setShowExpertSetup(false);
    setRefreshTrigger((value) => value + 1);
  };

  const closeCase = async () => {
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
            </div>
          ) : <p className="text-xs text-slate-500">No case loaded</p>}
        </div>
        <nav className="flex-1 space-y-1 overflow-y-auto px-2 py-2">
          {NAV_ITEMS.map((item) => (
            <button key={item.view} onClick={() => (item.view === 'about' || (currentCase && currentExpert)) && setCurrentView(item.view)} disabled={item.view !== 'about' && (!currentCase || !currentExpert)}
              className={`flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors ${currentView === item.view ? 'bg-cyan-600 text-white' : item.view === 'about' || (currentCase && currentExpert) ? 'text-slate-300 hover:bg-slate-800' : 'cursor-not-allowed text-slate-600'}`}>
              {item.icon}{item.label}
            </button>
          ))}
        </nav>
        <div className="space-y-2 border-t border-slate-700 p-3">
          {currentCase && (
            <Button size="sm" variant="outline" className="w-full border-amber-700 text-xs text-amber-300 hover:bg-amber-950/40" onClick={() => void closeCase()}>
              <LockKeyhole size={14} className="mr-1" />Lock / Close Case
            </Button>
          )}
          <Button size="sm" variant="outline" className="w-full border-cyan-600 text-xs text-cyan-400 hover:bg-cyan-900/30" onClick={() => openCaseSetup('new')}>
            <Plus size={14} className="mr-1" />New Case
          </Button>
          <Button size="sm" variant="outline" className="w-full border-slate-600 text-xs text-slate-300 hover:bg-slate-800" onClick={() => openCaseSetup('open')}>
            <FolderOpen size={14} className="mr-1" />Open Case
          </Button>
        </div>
      </aside>

      <main className="flex-1 overflow-hidden">
        {!currentCase && !showCaseSetup && currentView !== 'about' && (
          <div className="flex h-full items-center justify-center"><div className="text-center">
            <GitGraph size={64} className="mx-auto mb-4 text-slate-300" />
            <h2 className="mb-2 text-2xl font-bold text-slate-700">Welcome to {branding.productName}</h2>
            <p className="mb-6 text-slate-500">Create a local SQLite case or open an existing one.</p>
            <div className="flex justify-center gap-3">
              <Button onClick={() => openCaseSetup('new')} className="bg-cyan-600 hover:bg-cyan-700"><Plus size={16} className="mr-2" />New Case</Button>
              <Button onClick={() => openCaseSetup('open')} variant="outline"><FolderOpen size={16} className="mr-2" />Open Case</Button>
            </div>
          </div></div>
        )}
        {showCaseSetup && <CaseSetup mode={caseSetupMode} onComplete={() => void handleCaseComplete()} onCancel={() => setShowCaseSetup(false)} />}
        {currentView === 'about' && !showCaseSetup && <div className="h-full overflow-auto"><Suspense fallback={<WorkspaceLoading />}><AboutPage /></Suspense></div>}
        {currentCase && showExpertSetup && !showCaseSetup && <ExpertSetup onComplete={handleExpertComplete} onCancel={currentExpert ? () => setShowExpertSetup(false) : undefined} />}
        {currentCase && currentExpert && currentView !== 'about' && !showCaseSetup && !showExpertSetup && (
          <div className="h-full overflow-auto">
            <Suspense fallback={<WorkspaceLoading />}>
              {currentView === 'dashboard' && <Dashboard refreshTrigger={refreshTrigger} onCaseUpdated={() => void loadCase()} />}
              {currentView === 'networks' && <NetworkManager refreshTrigger={refreshTrigger} />}
              {currentView === 'assets' && <AssetManager refreshTrigger={refreshTrigger} expert={currentExpert} />}
              {currentView === 'topology' && <NetworkTopology refreshTrigger={refreshTrigger} />}
              {currentView === 'timeline' && <TimelineView refreshTrigger={refreshTrigger} />}
              {currentView === 'iocs' && <IocManager refreshTrigger={refreshTrigger} />}
              {currentView === 'notes' && <NoteManager refreshTrigger={refreshTrigger} />}
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
