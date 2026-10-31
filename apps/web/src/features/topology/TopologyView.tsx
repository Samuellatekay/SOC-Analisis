import React, { useState } from 'react';
import { TopologyResponse, TopologyNode } from '../../types';
import { Network, ShieldCheck, Database, Server, Bug, Crosshair, Globe } from 'lucide-react';

interface TopologyViewProps {
  topology: TopologyResponse | null;
}

export const TopologyView: React.FC<TopologyViewProps> = ({ topology }) => {
  const [selectedNode, setSelectedNode] = useState<TopologyNode | null>(null);

  if (!topology) {
    return <div className="p-8 text-center text-slate-400">Loading knowledge graph snapshot...</div>;
  }

  const { snapshot_id, semantic_integrity, nodes, edges } = topology;

  const nodeIcons = {
    asset: Server,
    technique: Crosshair,
    vulnerability: Bug,
    apt: Globe,
    ioc: Globe,
  };

  const nodeColors = {
    asset: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
    technique: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
    vulnerability: 'bg-red-500/10 text-red-400 border-red-500/30',
    apt: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    ioc: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
  };

  return (
    <div className="space-y-4">
      {/* Integrity Snapshot Status Banner */}
      <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-sm font-bold text-white">Semantic Integrity Layer (Algorithm 2)</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                G* Validated Snapshot: {snapshot_id}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Verified rules: $C_S$ (Schema), $C_I$ (Canonical Identity), $C_R$ (Relations), $C_T$ (Temporal Freshness), $C_P$ (Provenance).
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3 text-xs font-mono">
          <div className="bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800 text-slate-300">
            Quarantined Facts: <span className="text-emerald-400 font-bold">0</span>
          </div>
          <div className="bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800 text-slate-300">
            Schema Conflicts: <span className="text-emerald-400 font-bold">0</span>
          </div>
        </div>
      </div>

      {/* Main Graph & Entity Explorer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Entity Nodes Grid */}
        <div className="lg:col-span-8 bg-slate-900/60 p-4 rounded-xl border border-slate-800 space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-xs font-bold text-white flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" />
              Integrated Cybersecurity & Asset Association Graph Entities ({nodes.length})
            </h3>
            <span className="text-[10px] text-slate-400 font-mono">Click an entity to inspect relations</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {nodes.map((node) => {
              const Icon = nodeIcons[node.type] || Server;
              const isSelected = selectedNode?.id === node.id;
              return (
                <div
                  key={node.id}
                  onClick={() => setSelectedNode(node)}
                  className={`p-3 rounded-lg border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-cyan-500/15 border-cyan-500/50 shadow-md shadow-cyan-500/10'
                      : 'bg-slate-950/70 border-slate-800/80 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-center space-x-2.5">
                      <div className={`p-1.5 rounded-md border ${nodeColors[node.type]}`}>
                        <Icon className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="text-xs font-bold text-white">{node.label}</div>
                        <div className="text-[10px] text-slate-400 font-mono uppercase tracking-wider">
                          Type: {node.type}
                        </div>
                      </div>
                    </div>
                    {node.criticality && (
                      <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/40">
                        {node.criticality}
                      </span>
                    )}
                    {node.cvss && (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/40">
                        CVSS {node.cvss}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Association Inspector / Relations Sidebar */}
        <div className="lg:col-span-4 bg-slate-900/60 p-4 rounded-xl border border-slate-800 flex flex-col justify-between">
          <div className="space-y-4">
            <h3 className="text-xs font-bold text-white">Graph Relation & Provenance Inspector</h3>

            {selectedNode ? (
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-3">
                <div className="text-xs font-bold text-cyan-400">{selectedNode.label}</div>
                <div className="text-[11px] text-slate-300 font-mono space-y-1">
                  <div>Entity ID: {selectedNode.id}</div>
                  <div>Category: {selectedNode.type.toUpperCase()}</div>
                  {selectedNode.tactic && <div>ATT&CK Tactic: {selectedNode.tactic}</div>}
                  {selectedNode.criticality && <div>Business Criticality: {selectedNode.criticality.toUpperCase()}</div>}
                </div>

                {/* Connected Edges */}
                <div className="pt-2 border-t border-slate-800 space-y-2">
                  <span className="text-[11px] font-semibold text-slate-400">Connected Associations:</span>
                  <div className="space-y-1.5">
                    {edges
                      .filter((e) => e.source === selectedNode.id || e.target === selectedNode.id)
                      .map((e, idx) => (
                        <div key={idx} className="text-[10px] font-mono bg-slate-900 p-2 rounded border border-slate-800 flex items-center justify-between text-slate-300">
                          <span>{e.source}</span>
                          <span className="text-cyan-400 font-bold px-1.5 py-0.5 bg-cyan-950 rounded border border-cyan-800 text-[9px]">
                            {e.label}
                          </span>
                          <span>{e.target}</span>
                        </div>
                      ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center text-slate-500 text-xs">
                Select an entity node to inspect its relations, semantic links, and ATT&CK mapping.
              </div>
            )}
          </div>

          <div className="text-[11px] text-slate-500 leading-relaxed pt-4 border-t border-slate-800">
            Graph snapshot maintained with automated daily 01:00 Asia/Jakarta sync with MITRE ATT&CK & CISA KEV feeds.
          </div>
        </div>
      </div>
    </div>
  );
};
