import React, { useState } from 'react';
import { X, Sparkles, Send, FileCode, CheckCircle2 } from 'lucide-react';
import { socApi } from '../../services/api';

interface SimulatorModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSimulate: (payload: { raw_alert: any; context?: any }) => Promise<void>;
  onAlertsUpdated?: () => Promise<void>;
}

export const SimulatorModal: React.FC<SimulatorModalProps> = ({
  isOpen,
  onClose,
  onSimulate,
  onAlertsUpdated,
}) => {
  if (!isOpen) return null;

  const [activeTab, setActiveTab] = useState<'presets' | 'wazuh'>('presets');
  const [loading, setLoading] = useState(false);
  const [wazuhError, setWazuhError] = useState<string | null>(null);

  // Sample Wazuh Log default text
  const defaultWazuhLog = JSON.stringify(
    {
      timestamp: "2026-10-31T05:12:30.123+0000",
      rule: {
        level: 10,
        description: "sshd: Attempt to login using a non-existent user (SSH Brute Force)",
        id: "5710",
        mitre: {
          id: ["T1110.001"],
          tactic: ["Credential Access"],
          technique: ["Password Guessing"]
        }
      },
      agent: {
        id: "001",
        name: "srv-prod-db01",
        ip: "192.168.10.10"
      },
      data: {
        srcip: "203.0.113.45",
        dstip: "192.168.10.10",
        dstport: "22",
        protocol: "TCP"
      },
      full_log: "Oct 31 05:12:30 srv-prod-db01 sshd[4045]: Failed password for invalid user root from 203.0.113.45 port 54822 ssh2",
      id: "1730351550.91024"
    },
    null,
    2
  );

  const [wazuhInput, setWazuhInput] = useState(defaultWazuhLog);

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

  const handleIngestWazuh = async () => {
    setWazuhError(null);
    setLoading(true);
    try {
      const parsed = JSON.parse(wazuhInput);
      await socApi.ingestWazuh(parsed);
      if (onAlertsUpdated) {
        await onAlertsUpdated();
      }
      onClose();
    } catch (err: any) {
      setWazuhError(err.message || "Failed to parse or ingest Wazuh JSON.");
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
            <h3 className="text-sm font-bold text-white">Ingest &amp; Simulasi Alert</h3>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Tabs */}
        <div className="flex border-b border-slate-800 bg-slate-950 text-xs px-4">
          <button
            onClick={() => setActiveTab('presets')}
            className={`py-2.5 px-4 font-semibold transition-all border-b-2 ${
              activeTab === 'presets'
                ? 'border-cyan-500 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            Skenario Preset Paper
          </button>
          <button
            onClick={() => setActiveTab('wazuh')}
            className={`py-2.5 px-4 font-semibold transition-all border-b-2 flex items-center gap-1.5 ${
              activeTab === 'wazuh'
                ? 'border-cyan-500 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-white'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>Kirim Log Wazuh (JSON)</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 space-y-4 max-h-[70vh] overflow-y-auto">
          {activeTab === 'presets' ? (
            <>
              <p className="text-xs text-slate-400">
                Pilih skenario representatif untuk menguji pipeline FFT-PCC, Conservative Risk Gate,
                Multi-Agent evidence fusion, dan scoring AHP secara langsung:
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
                      className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold shrink-0 flex items-center gap-1.5 shadow cursor-pointer"
                    >
                      <Send className="w-3 h-3" />
                      <span>Run</span>
                    </button>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-xs font-semibold text-slate-300">
                  Paste JSON Alert Wazuh (<code className="text-cyan-400">alerts.json</code>):
                </span>
                <span className="text-[10px] font-mono text-slate-500">
                  POST /api/v1/alerts/ingest/wazuh
                </span>
              </div>

              <textarea
                rows={12}
                value={wazuhInput}
                onChange={(e) => setWazuhInput(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
                placeholder="Paste Wazuh alert JSON here..."
              />

              {wazuhError && (
                <div className="p-2.5 rounded-lg bg-red-950/60 border border-red-800 text-red-300 text-xs">
                  {wazuhError}
                </div>
              )}

              <div className="flex justify-between items-center pt-2">
                <span className="text-[11px] text-slate-400">
                  Format otomatis dinormalkan ke skema internal &amp; dihitung skor AHP.
                </span>
                <button
                  disabled={loading}
                  onClick={handleIngestWazuh}
                  className="px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-bold flex items-center gap-2 shadow-lg shadow-cyan-600/20 cursor-pointer"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>Proses Log Wazuh</span>
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-3 border-t border-slate-800 bg-slate-950/60 text-right">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-white"
          >
            Tutup
          </button>
        </div>
      </div>
    </div>
  );
};
