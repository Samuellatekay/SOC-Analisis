import React from 'react';
import { AnalyticsOverview } from '../../types';
import { Filter, Zap, Clock, ShieldCheck, TrendingDown, ArrowUpRight, BarChart2 } from 'lucide-react';

interface DashboardViewProps {
  analytics: AnalyticsOverview | null;
  onNavigateToAlerts: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({ analytics, onNavigateToAlerts }) => {
  if (!analytics) {
    return <div className="p-8 text-center text-slate-400">Loading analytics...</div>;
  }

  const {
    total_alerts,
    filtered_noise_count,
    retained_alerts_count,
    noise_reduction_rate,
    active_cases_count,
    branch_distribution,
    risk_distribution,
    benchmark_comparison,
    improvements,
  } = analytics;

  return (
    <div className="space-y-6">
      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Ingress */}
        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Total Raw Ingress</span>
            <Zap className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">{total_alerts}</div>
          <p className="text-[11px] text-slate-400">
            Stream processed via Redis durable broker
          </p>
        </div>

        {/* Noise Reduction Rate */}
        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Noise Reduction Rate (NRR)</span>
            <Filter className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-cyan-400">{noise_reduction_rate}%</span>
            <span className="text-xs text-emerald-400 flex items-center font-medium">
              <TrendingDown className="w-3 h-3 mr-0.5" /> -37% load
            </span>
          </div>
          <p className="text-[11px] text-slate-400">
            {filtered_noise_count} periodic & benign alerts filtered
          </p>
        </div>

        {/* Retained True Alerts */}
        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Retained Priority Queue</span>
            <ShieldCheck className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">{retained_alerts_count}</div>
          <p className="text-[11px] text-slate-400">
            High: {risk_distribution.high_risk} | Med: {risk_distribution.medium_risk} | Low: {risk_distribution.low_risk}
          </p>
        </div>

        {/* MTTR Response Speed */}
        <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Mean Response Time (MTTR)</span>
            <Clock className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-emerald-400">6.5 min</span>
            <span className="text-xs text-slate-400 font-mono">(vs 12.0m Splunk)</span>
          </div>
          <p className="text-[11px] text-emerald-400 font-medium">
            +103% throughput (240 alerts/hour)
          </p>
        </div>
      </div>

      {/* Hierarchical Noise Reduction Flow Diagram (Figure 5 from paper) */}
      <div className="bg-slate-900/60 p-5 rounded-xl border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-white flex items-center gap-2">
              <BarChart2 className="w-4 h-4 text-cyan-400" />
              Hierarchical Workload & Noise Reduction Funnel (Guo et al. Fig. 5)
            </h2>
            <p className="text-xs text-slate-400">
              Two-stage architecture: High-speed FFT-PCC pre-filtering (82%) + Multi-Agent evidence reasoning (18%)
            </p>
          </div>
          <button
            onClick={onNavigateToAlerts}
            className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium"
          >
            Inspect Retained Alerts <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
          {/* Stage 1: Ingress */}
          <div className="bg-slate-950/70 p-4 rounded-xl border border-slate-800 space-y-3 relative overflow-hidden">
            <div className="absolute top-0 left-0 w-1 h-full bg-blue-500"></div>
            <div className="flex justify-between items-center text-xs font-semibold text-slate-300">
              <span>Alert Stream (100%)</span>
              <span className="font-mono text-blue-400">{total_alerts} Total</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Ingress via multi-source adapters. Structured triplet construction:
              <br />
              <code className="text-cyan-300 font-mono text-[10px]">$g(a_i) = (src_i, dst_i, type_i)$</code>
            </p>
            <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
              <div className="bg-blue-500 h-full w-full"></div>
            </div>
          </div>

          {/* Stage 2: FFT-PCC & Risk Gate */}
          <div className="bg-slate-950/70 p-4 rounded-xl border border-slate-800 space-y-3 relative overflow-hidden">
            <div className="absolute top-0 left-0 w-1 h-full bg-cyan-500"></div>
            <div className="flex justify-between items-center text-xs font-semibold text-slate-300">
              <span>FFT-PCC Periodic Filter (82%)</span>
              <span className="font-mono text-cyan-400">{branch_distribution.filtered_noise_pct}% Noise Dropped</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Detects periodic operational noise (&rho;<sub>g</sub> &ge; 3.0, r<sub>g</sub> &gt; 0.85). Protected by Conservative Risk Gate.
            </p>
            <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
              <div className="bg-cyan-500 h-full" style={{ width: `${branch_distribution.filtered_noise_pct}%` }}></div>
            </div>
          </div>

          {/* Stage 3: Multi-Agent & Retained */}
          <div className="bg-slate-950/70 p-4 rounded-xl border border-slate-800 space-y-3 relative overflow-hidden">
            <div className="absolute top-0 left-0 w-1 h-full bg-amber-500"></div>
            <div className="flex justify-between items-center text-xs font-semibold text-slate-300">
              <span>Multi-Agent & Scoring (18%)</span>
              <span className="font-mono text-amber-400">{retained_alerts_count} Triaged</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              BERT semantic classification (6.3%) + 6 plugins + AHP dynamic risk scoring ($CR=0.041$).
            </p>
            <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
              <div className="bg-amber-500 h-full" style={{ width: `${(retained_alerts_count / (total_alerts || 1)) * 100}%` }}></div>
            </div>
          </div>
        </div>
      </div>

      {/* Comparison with Commercial & Open-Source Platforms (Table 14) */}
      <div className="bg-slate-900/60 p-5 rounded-xl border border-slate-800 space-y-4">
        <div>
          <h2 className="text-sm font-bold text-white">
            End-to-End SOC Platform Evaluation (Guo et al. 2026 Table 14)
          </h2>
          <p className="text-xs text-slate-400">
            Controlled 30-day replay evaluation with 10 SOC analysts under 10,000 alerts/sec workload
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-950/80 text-slate-400 font-mono uppercase text-[10px]">
              <tr>
                <th className="py-2.5 px-3">System / Platform</th>
                <th className="py-2.5 px-3">Mean Response Time</th>
                <th className="py-2.5 px-3">Alert Throughput</th>
                <th className="py-2.5 px-3">Cognitive Load (NASA-TLX)</th>
                <th className="py-2.5 px-3">High-Risk Recall</th>
                <th className="py-2.5 px-3">Architecture Note</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {benchmark_comparison.map((row, idx) => {
                const isOurs = row.system.includes("Ours");
                return (
                  <tr key={idx} className={isOurs ? 'bg-cyan-500/10 font-medium text-white' : 'hover:bg-slate-800/30'}>
                    <td className="py-3 px-3 flex items-center gap-2">
                      {isOurs && <span className="w-2 h-2 rounded-full bg-cyan-400"></span>}
                      {row.system}
                    </td>
                    <td className="py-3 px-3 font-mono">{row.mttr_min} min</td>
                    <td className="py-3 px-3 font-mono text-cyan-300">{row.throughput_h} alerts/h</td>
                    <td className="py-3 px-3 font-mono">{row.nasa_tlx}</td>
                    <td className="py-3 px-3 font-mono text-emerald-400">{(row.high_risk_recall * 100).toFixed(0)}%</td>
                    <td className="py-3 px-3 text-[11px] text-slate-400">
                      {isOurs ? 'Risk-gated noise reduction + AHP dynamic scoring' : 'Baseline without FFT-PCC filtering'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
