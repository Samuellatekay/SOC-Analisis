import React from 'react';
import { LayoutDashboard, AlertOctagon, Briefcase, Network, Cpu } from 'lucide-react';

export type NavTab = 'dashboard' | 'alerts' | 'cases' | 'topology';

interface SidebarProps {
  currentTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  unreadHighAlerts?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onTabChange, unreadHighAlerts = 0 }) => {
  const navItems = [
    { id: 'dashboard', label: 'Overview Dashboard', icon: LayoutDashboard },
    { id: 'alerts', label: 'Alert Triage & Priority', icon: AlertOctagon, badge: unreadHighAlerts },
    { id: 'cases', label: 'Case Management', icon: Briefcase },
    { id: 'topology', label: 'Knowledge Graph', icon: Network },
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-[#0B0F19] p-4 flex flex-col justify-between shrink-0">
      <div className="space-y-6">
        <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider px-3">
          Triage Navigation
        </div>

        <nav className="space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onTabChange(item.id as NavTab)}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-blue-600/15 text-cyan-400 border border-cyan-500/30 shadow-sm shadow-cyan-500/10'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge && item.badge > 0 ? (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-500/20 text-red-400 border border-red-500/30">
                    {item.badge}
                  </span>
                ) : null}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Engine Blueprint Card at Bottom */}
      <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-xs space-y-2">
        <div className="flex items-center space-x-2 text-cyan-400 font-semibold text-[11px]">
          <Cpu className="w-3.5 h-3.5" />
          <span>Paper Methodology</span>
        </div>
        <p className="text-[11px] text-slate-400 leading-relaxed">
          Conservative Risk-gated FFT-PCC filtering + BERT Multi-Agent fusion + AHP Dynamic Scoring ($CR=0.041$).
        </p>
        <div className="pt-1 border-t border-slate-800/80 text-[10px] text-slate-500 flex justify-between">
          <span>Target NRR: 72.0%</span>
          <span>Recall: 94.0%</span>
        </div>
      </div>
    </aside>
  );
};
