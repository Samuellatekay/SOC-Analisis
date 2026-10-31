import React, { useState } from 'react';
import { X, Sparkles, Send, ShieldAlert, Cpu } from 'lucide-react';

interface SimulatorModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSimulate: (payload: { raw_alert: any; context?: any }) => Promise<void>;
}

export const SimulatorModal: React.FC<SimulatorModalProps> = ({ isOpen, onClose, onSimulate }) => {
  if (!isOpen) return null;

  const [loading, setLoading] = useState(false);

  const presets = [
    {
      id: 'periodic_brute_force',
      title: '1. Periodic SSH Brute-Force (Risk-Gated)',
      desc: 'Periodic pulses every 24h attacking Core Database with known exploit. Verifies Conservative Risk Gate prevents noise drop!',
      raw: {
        source: 'Wazuh HIDS',
        src_ip: '203.0.113.45',
        dst_ip: '192.168.10.10',
        dst_port: 22,
        protocol: 'TCP',
        alert_type: 'SSH Brute-force Attempt',
        severity: 'high',
        raw_message: 'Failed password burst for root count 465 from 203.0.113.45',
      },
      context: {
        ioc_match: true,
        asset_business_value: 'core',
        attack_surface_exposure: 'internet',
        cve_id: 'CVE-2024-6387',
        vulnerability_exploitability: 'public_exploit',
        external_threat_posture: 'industry campaign',
        internal_security_status: 'network-wide anomaly',
      },
    },
    {
      id: 'ransomware_impact',
      title: '2. Ransomware Host Encryption (Critical)',
      desc: 'LockBit 3.0 vssadmin shadow copy deletion on Domain Controller. Evaluates High AHP score (90+) and priority triage.',
      raw: {
        source: 'CrowdStrike Falcon',
        src_ip: '10.0.1.15',
        dst_ip: '10.0.1.5',
        dst_port: 445,
        protocol: 'TCP',
        alert_type: 'Ransomware Data Encryption Activity',
        severity: 'critical',
        raw_message: 'Mass shadow copy deletion via vssadmin and file extension rename',
      },
      context: {
        ioc_match: true,
        asset_business_value: 'core',
        data_sensitivity: 'top secret',
        attack_stage: 'impact',
        stage_policy_weight: 1.0,
        apt_group: 'LockBit 3.0',
        vulnerability_exploitability: 'public_exploit',
        path_reachability: 'direct',
        protection_bypass: 'evasion',
        homogeneous_count: 6,
        kill_chain_progression: true,
      },
    },
    {
      id: 'periodic_noise',
      title: '3. Routine Monitoring Probe (Noise Reduction)',
      desc: 'Routine 2-hour monitoring agent health probe on test server. Verifies FFT-PCC filters as periodic operational noise.',
      raw: {
        source: 'Suricata NIDS',
        src_ip: '10.0.5.20',
        dst_ip: '10.0.1.200',
        dst_port: 10050,
        protocol: 'TCP',
        alert_type: 'Zabbix Health Check Probe',
        severity: 'low',
        raw_message: 'Routine agent heartbeat keepalive TCP connection established',
      },
      context: {
        ioc_match: false,
        asset_business_value: 'test',
        attack_surface_exposure: 'isolated',
        vulnerability_exploitability: 'none',
      },
    },
  ];

  const handleRunPreset = async (preset: typeof presets[0]) => {
    setLoading(true);
    try {
      await onSimulate({ raw_alert: preset.raw, context: preset.context });
      onClose();
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="w-full max-w-xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col">
        {/* Modal Header */}
        <div className="p-4 border-b border-slate-800 flex justify-between items-center bg-slate-950/80">
          <div className="flex items-center space-x-2">
            <Sparkles className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-bold text-white">Live Alert Pipeline Simulator</h3>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 space-y-4">
          <p className="text-xs text-slate-400">
            Select a representative scenario from Guo et al. (2026) to test real-time ingress, FFT-PCC filtering,
            Conservative Risk Gating, Multi-Agent fusion, and AHP scoring:
          </p>

          <div className="space-y-3">
            {presets.map((preset) => (
              <div
                key={preset.id}
                className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 hover:border-cyan-500/50 transition-all flex justify-between items-center group"
              >
                <div className="space-y-1 max-w-md">
                  <div className="text-xs font-bold text-white group-hover:text-cyan-300 transition-colors">
                    {preset.title}
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">{preset.desc}</p>
                </div>
                <button
                  disabled={loading}
                  onClick={() => handleRunPreset(preset)}
                  className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold shrink-0 flex items-center gap-1.5 shadow"
                >
                  <Send className="w-3 h-3" />
                  <span>Run</span>
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-3 border-t border-slate-800 bg-slate-950/60 text-right">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-white"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
};
