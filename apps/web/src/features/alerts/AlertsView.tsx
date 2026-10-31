import React, { useState } from 'react';
import { EnrichedAlert, RiskLevel, SeverityLevel } from '../../types';
import { AHPScoreRadar } from '../../components/AHPScoreRadar';
import { TimeSeriesChart } from '../../components/TimeSeriesChart';
import {
  ShieldAlert,
  Search,
  Filter,
  Eye,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ChevronRight,
  ExternalLink,
  PlusCircle,
  X,
  FileText,
} from 'lucide-react';

interface AlertsViewProps {
  alerts: EnrichedAlert[];
  onSelectAlert: (alert: EnrichedAlert) => void;
  selectedAlert: EnrichedAlert | null;
  onCloseDrawer: () => void;
  onCreateCaseFromAlert: (alert: EnrichedAlert) => void;
  filterRisk: RiskLevel | 'all';
  onFilterRiskChange: (level: RiskLevel | 'all') => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  showNoise: boolean;
  onToggleNoise: (val: boolean) => void;
}

export const AlertsView: React.FC<AlertsViewProps> = ({
  alerts,
  onSelectAlert,
  selectedAlert,
  onCloseDrawer,
  onCreateCaseFromAlert,
  filterRisk,
  onFilterRiskChange,
  searchQuery,
  onSearchChange,
  showNoise,
  onToggleNoise,
}) => {
  const [activeTab, setActiveTab] = useState<'ahp' | 'multi_agent' | 'rag' | 'series'>('ahp');

  return (
    <div className="space-y-4">
      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900/60 p-3 rounded-xl border border-slate-800">
        <div className="flex items-center space-x-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="Search IP, Event ID, Attack Type..."
              className="bg-slate-950 border border-slate-800 text-xs rounded-lg pl-8 pr-3 py-1.5 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-64"
            />
          </div>

          {/* Risk Level Pills */}
          <div className="flex items-center space-x-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
            {(['all', 'high', 'medium', 'low'] as const).map((lvl) => (
              <button
                key={lvl}
                onClick={() => onFilterRiskChange(lvl)}
                className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all ${
                  filterRisk === lvl
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {lvl.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        {/* Toggle Show Noise */}
        <label className="flex items-center space-x-2 text-xs text-slate-400 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={showNoise}
            onChange={(e) => onToggleNoise(e.target.checked)}
            className="rounded bg-slate-950 border-slate-700 text-cyan-500 focus:ring-0"
          />
          <span>Include Filtered Periodic Noise</span>
        </label>
      </div>

      {/* Main Alert List Table */}
      <div className="bg-slate-900/60 rounded-xl border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-950/80 text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Risk Level</th>
                <th className="py-2.5 px-3">Alert Type / Signature</th>
                <th className="py-2.5 px-3">Source & Destination</th>
                <th className="py-2.5 px-3">Triage Route</th>
                <th className="py-2.5 px-3">Risk Score</th>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    No alerts match the selected criteria.
                  </td>
                </tr>
              ) : (
                alerts.map((a) => {
                  const isHigh = a.risk_level === 'high';
                  const isMed = a.risk_level === 'medium';
                  const isNoise = a.filtered_as_noise;

                  return (
                    <tr
                      key={a.event_id}
                      onClick={() => onSelectAlert(a)}
                      className={`hover:bg-slate-800/40 cursor-pointer transition-colors ${
                        selectedAlert?.event_id === a.event_id ? 'bg-cyan-500/10' : ''
                      }`}
                    >
                      {/* Priority Badge */}
                      <td className="py-3 px-3">
                        {isNoise ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
                            FILTERED NOISE
                          </span>
                        ) : isHigh ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/20 text-red-400 border border-red-500/40">
                            HIGH RISK
                          </span>
                        ) : isMed ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-amber-500/20 text-amber-400 border border-amber-500/40">
                            MEDIUM
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                            LOW RISK
                          </span>
                        )}
                      </td>

                      {/* Alert Type */}
                      <td className="py-3 px-3">
                        <div className="font-semibold text-white">{a.alert_type}</div>
                        <div className="text-[10px] text-slate-400 font-mono truncate max-w-xs">
                          {a.source} | ID: {a.event_id.slice(0, 8)}
                        </div>
                      </td>

                      {/* Source & Dst */}
                      <td className="py-3 px-3 font-mono text-[11px]">
                        <div className="text-slate-200">{a.src_ip}</div>
                        <div className="text-slate-400 flex items-center gap-1 text-[10px]">
                          <span>→</span> {a.dst_ip}:{a.dst_port || 80} ({a.protocol})
                        </div>
                      </td>

                      {/* Triage Route */}
                      <td className="py-3 px-3">
                        {a.risk_gate?.has_high_risk_evidence ? (
                          <span className="text-[10px] text-red-300 bg-red-950/60 border border-red-800/60 px-1.5 py-0.5 rounded flex items-center gap-1 w-fit">
                            <ShieldAlert className="w-3 h-3 text-red-400" />
                            Risk-Gate Retained
                          </span>
                        ) : isNoise ? (
                          <span className="text-[10px] text-slate-400 bg-slate-950 px-1.5 py-0.5 rounded">
                            FFT-PCC Filter
                          </span>
                        ) : (
                          <span className="text-[10px] text-cyan-300 bg-cyan-950/60 border border-cyan-800/60 px-1.5 py-0.5 rounded">
                            Multi-Agent Fusion
                          </span>
                        )}
                      </td>

                      {/* Risk Score */}
                      <td className="py-3 px-3 font-mono font-bold">
                        <span className={isHigh ? 'text-red-400 text-sm' : isMed ? 'text-amber-400' : 'text-slate-400'}>
                          {a.risk_score.toFixed(1)}
                        </span>
                      </td>

                      {/* Timestamp */}
                      <td className="py-3 px-3 text-slate-400 font-mono text-[10px]">
                        {new Date(a.event_time).toLocaleTimeString()}
                      </td>

                      {/* Actions */}
                      <td className="py-3 px-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectAlert(a);
                          }}
                          className="p-1 rounded hover:bg-slate-700 text-slate-400 hover:text-white"
                        >
                          <ChevronRight className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Slide-over Detail Drawer */}
      {selectedAlert && (
        <div className="fixed inset-y-0 right-0 w-full max-w-2xl bg-[#0F172A] border-l border-slate-800 shadow-2xl z-50 flex flex-col">
          {/* Drawer Header */}
          <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/80">
            <div className="space-y-1">
              <div className="flex items-center space-x-2">
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                  selectedAlert.risk_level === 'high' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                  selectedAlert.risk_level === 'medium' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40' :
                  'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                }`}>
                  {selectedAlert.risk_level.toUpperCase()} ({selectedAlert.risk_score.toFixed(1)})
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  {selectedAlert.event_id}
                </span>
              </div>
              <h3 className="text-sm font-bold text-white">{selectedAlert.alert_type}</h3>
            </div>

            <div className="flex items-center space-x-2">
              <button
                onClick={() => onCreateCaseFromAlert(selectedAlert)}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow"
              >
                <PlusCircle className="w-3.5 h-3.5" />
                <span>Create Case</span>
              </button>
              <button
                onClick={onCloseDrawer}
                className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
          </div>

          {/* Drawer Tabs */}
          <div className="flex border-b border-slate-800 bg-slate-950 px-4 text-xs">
            <button
              onClick={() => setActiveTab('ahp')}
              className={`py-2.5 px-3 border-b-2 font-medium transition-all ${
                activeTab === 'ahp' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              AHP 17-Indicators
            </button>
            <button
              onClick={() => setActiveTab('multi_agent')}
              className={`py-2.5 px-3 border-b-2 font-medium transition-all ${
                activeTab === 'multi_agent' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Multi-Agent & Risk Gate
            </button>
            <button
              onClick={() => setActiveTab('rag')}
              className={`py-2.5 px-3 border-b-2 font-medium transition-all ${
                activeTab === 'rag' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              RAG & Mitigations
            </button>
            <button
              onClick={() => setActiveTab('series')}
              className={`py-2.5 px-3 border-b-2 font-medium transition-all ${
                activeTab === 'series' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              FFT Triplet Time-Series
            </button>
          </div>

          {/* Drawer Content */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {/* TAB 1: AHP RISK SCORING */}
            {activeTab === 'ahp' && (
              <div className="space-y-4">
                {selectedAlert.ahp_scoring ? (
                  <>
                    <AHPScoreRadar
                      criteria={selectedAlert.ahp_scoring.criteria_breakdown}
                      finalScore={selectedAlert.ahp_scoring.final_risk_score}
                    />

                    <div className="bg-slate-900/60 p-3 rounded-xl border border-slate-800 text-xs space-y-2">
                      <div className="text-[11px] font-semibold text-slate-400 font-mono">
                        FORMULA CALCULATION NOTES (Guo et al. Eq. 8-10):
                      </div>
                      <p className="text-slate-300 font-mono text-[11px] bg-slate-950 p-2 rounded">
                        {selectedAlert.ahp_scoring.formula_notes}
                      </p>
                    </div>

                    {/* 17 Sub-indicators Table */}
                    <div className="space-y-2">
                      <h4 className="text-xs font-bold text-slate-300">
                        17 Sub-Indicators Normalized Values (v<sub>ij</sub>) &amp; Weighted Contributions
                      </h4>
                      <div className="space-y-3">
                        {selectedAlert.ahp_scoring.criteria_breakdown.map((crit, cIdx) => (
                          <div key={cIdx} className="bg-slate-950 p-2.5 rounded-lg border border-slate-800/80 space-y-1.5">
                            <div className="flex justify-between text-xs font-semibold text-cyan-400">
                              <span>{crit.criterion_name}</span>
                              <span className="font-mono text-slate-400">
                                Weight: {crit.criterion_weight} | Score: {crit.score.toFixed(3)}
                              </span>
                            </div>
                            <div className="space-y-1">
                              {crit.sub_indicators.map((sub, sIdx) => (
                                <div key={sIdx} className="flex justify-between items-center text-[11px] text-slate-300 py-0.5 border-t border-slate-900">
                                  <span>{sub.name} <span className="text-slate-500 font-mono text-[10px]">({String(sub.raw_value)})</span></span>
                                  <div className="flex items-center space-x-2 font-mono">
                                    <span className="text-slate-400">v={sub.normalized_value}</span>
                                    <span className="text-emerald-400 font-bold">+{sub.weighted_score.toFixed(3)}</span>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="p-8 text-center text-slate-400">
                    This alert was filtered as periodic noise before entering AHP scoring.
                  </div>
                )}
              </div>
            )}

            {/* TAB 2: MULTI-AGENT & RISK GATE */}
            {activeTab === 'multi_agent' && (
              <div className="space-y-4 text-xs">
                {/* Risk Gate Status */}
                <div className={`p-3 rounded-xl border ${
                  selectedAlert.risk_gate?.has_high_risk_evidence
                    ? 'bg-red-950/30 border-red-800/60'
                    : 'bg-slate-900/60 border-slate-800'
                }`}>
                  <div className="flex items-center space-x-2 font-bold mb-2">
                    <ShieldAlert className={`w-4 h-4 ${
                      selectedAlert.risk_gate?.has_high_risk_evidence ? 'text-red-400' : 'text-slate-400'
                    }`} />
                    <span className={selectedAlert.risk_gate?.has_high_risk_evidence ? 'text-red-300' : 'text-slate-300'}>
                      Conservative Risk Gate (Algorithm 1)
                    </span>
                  </div>
                  <div className="space-y-1 text-slate-300">
                    {selectedAlert.risk_gate?.reasons.map((r, i) => (
                      <div key={i} className="flex items-start gap-1.5">
                        <CheckCircle2 className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                        <span>{r}</span>
                      </div>
                    ))}
                    {!selectedAlert.risk_gate?.has_high_risk_evidence && (
                      <span className="text-slate-400">No high-risk override triggers found.</span>
                    )}
                  </div>
                </div>

                {/* Multi-Agent Branches */}
                {selectedAlert.multi_agent && (
                  <div className="space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="font-semibold text-white">Agent Evidence Orchestration Outputs</span>
                      <span className="font-mono text-cyan-400 font-bold">
                        S<sub>TA</sub> = {selectedAlert.multi_agent.sta_score.toFixed(2)} ({selectedAlert.multi_agent.decision})
                      </span>
                    </div>

                    {selectedAlert.multi_agent.branch_outputs.map((branch, idx) => (
                      <div key={idx} className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1.5">
                        <div className="flex justify-between items-center">
                          <span className="font-bold text-cyan-300 uppercase text-[10px] tracking-wider">
                            {branch.branch.replace('_', ' ')} Agent
                          </span>
                          <span className="font-mono text-slate-400">
                            Confidence: {(branch.confidence * 100).toFixed(0)}% | Dec: {branch.decision}
                          </span>
                        </div>
                        <pre className="text-[10px] font-mono text-slate-400 bg-slate-900 p-2 rounded overflow-x-auto">
                          {JSON.stringify(branch.evidence_details, null, 2)}
                        </pre>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* TAB 3: RAG & MITIGATIONS */}
            {activeTab === 'rag' && (
              <div className="space-y-4 text-xs">
                {/* ATT&CK Banner */}
                <div className="bg-slate-950 p-3 rounded-xl border border-blue-500/30 flex justify-between items-center">
                  <div>
                    <span className="text-[10px] font-mono uppercase text-blue-400">MITRE ATT&CK Mapping</span>
                    <div className="font-bold text-white text-sm">
                      {selectedAlert.mitre_attack_id}: {selectedAlert.mitre_attack_name}
                    </div>
                  </div>
                  <ExternalLink className="w-4 h-4 text-slate-400" />
                </div>

                {/* Analyst Hypothesis */}
                <div className="bg-slate-900/60 p-3 rounded-xl border border-slate-800 space-y-2">
                  <h4 className="font-bold text-white flex items-center gap-1.5">
                    <FileText className="w-4 h-4 text-cyan-400" />
                    AI / RAG Reasoning & Hypothesis
                  </h4>
                  <p className="text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-lg border border-slate-800/80">
                    {selectedAlert.rag_explanation || "No explanation generated."}
                  </p>
                </div>

                {/* Recommended Mitigation Playbooks */}
                <div className="space-y-2">
                  <h4 className="font-bold text-white">Recommended Triage & Containment Steps</h4>
                  <div className="space-y-2">
                    {selectedAlert.recommended_actions.map((act, idx) => (
                      <div key={idx} className="flex items-start space-x-2 bg-slate-950 p-2.5 rounded-lg border border-slate-800">
                        <span className="w-4 h-4 rounded-full bg-cyan-500/20 text-cyan-400 font-mono text-[10px] flex items-center justify-center shrink-0 mt-0.5">
                          {idx + 1}
                        </span>
                        <span className="text-slate-300">{act}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* TAB 4: TIME-SERIES */}
            {activeTab === 'series' && (
              <div className="space-y-4 text-xs">
                <TimeSeriesChart
                  data={[12, 10, 8, 25, 10, 11, 24, 9, 10, 26, 12, 11, 25, 10]}
                  isPeriodic={selectedAlert.fft_result?.is_periodic_candidate}
                  periodHours={selectedAlert.fft_result?.candidate_period_hours}
                />
                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 space-y-1.5">
                  <div className="font-bold text-white">FFT Periodicity Analysis Details</div>
                  <p className="text-slate-400 text-[11px] font-mono leading-relaxed">
                    {selectedAlert.fft_result?.details || "No periodic spectrum detected."}
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
