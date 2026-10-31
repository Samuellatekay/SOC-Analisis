import React from 'react';
import { ShieldAlert, Activity, Database, Sparkles, PlusCircle } from 'lucide-react';

interface HeaderProps {
  onOpenSimulator: () => void;
  activeCasesCount: number;
}

export const Header: React.FC<HeaderProps> = ({ onOpenSimulator, activeCasesCount }) => {
  return (
    <header className="h-16 border-b border-slate-800 bg-[#0B0F19]/90 backdrop-blur sticky top-0 z-30 px-6 flex items-center justify-between">
      {/* Brand & Title */}
      <div className="flex items-center space-x-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 border border-cyan-400/30">
          <ShieldAlert className="w-6 h-6 text-white" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-1.5">
              SOC Analisis Engine
              <span className="text-[10px] font-mono font-medium px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/30">
                AHP-FFT-PCC
              </span>
            </h1>
          </div>
          <p className="text-xs text-slate-400">
            Intelligent Priority Awareness & Dynamic Risk Triage (Guo et al. 2026)
          </p>
        </div>
      </div>

      {/* Center Engine Status Indicators */}
      <div className="hidden lg:flex items-center space-x-6 text-xs">
        <div className="flex items-center space-x-2 bg-slate-900/80 px-3 py-1.5 rounded-lg border border-slate-800">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span className="text-slate-300 font-medium">Fast Path Ingress:</span>
          <span className="text-emerald-400 font-mono">0.82ms</span>
        </div>

        <div className="flex items-center space-x-2 bg-slate-900/80 px-3 py-1.5 rounded-lg border border-slate-800">
          <Database className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-slate-300 font-medium">Graph Snapshot:</span>
          <span className="text-cyan-400 font-mono">G* Validated</span>
        </div>

        <div className="flex items-center space-x-2 bg-slate-900/80 px-3 py-1.5 rounded-lg border border-slate-800">
          <Activity className="w-3.5 h-3.5 text-amber-400" />
          <span className="text-slate-300 font-medium">Active Cases:</span>
          <span className="text-amber-400 font-mono font-bold">{activeCasesCount}</span>
        </div>
      </div>

      {/* Action Buttons */}
      <div className="flex items-center space-x-3">
        <button
          onClick={onOpenSimulator}
          className="flex items-center space-x-2 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-md shadow-cyan-600/20 border border-cyan-400/40 transition-all cursor-pointer"
        >
          <Sparkles className="w-4 h-4 text-cyan-200" />
          <span>Simulasi Alert</span>
        </button>
      </div>
    </header>
  );
};
