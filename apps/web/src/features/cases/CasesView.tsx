import React, { useState } from 'react';
import { Case, CaseStatus, SeverityLevel } from '../../types';
import {
  Briefcase,
  Clock,
  User,
  Tag,
  CheckCircle2,
  AlertCircle,
  Plus,
  Send,
  History,
  FileText,
} from 'lucide-react';

interface CasesViewProps {
  cases: Case[];
  onUpdateStatus: (caseId: string, status: CaseStatus, comment?: string) => Promise<void>;
  onAddNote: (caseId: string, author: string, content: string) => Promise<void>;
}

export const CasesView: React.FC<CasesViewProps> = ({ cases, onUpdateStatus, onAddNote }) => {
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(cases[0]?.case_id || null);
  const [newNoteContent, setNewNoteContent] = useState('');
  const [authorName, setAuthorName] = useState('Senior Analyst');

  const selectedCase = cases.find((c) => c.case_id === selectedCaseId) || cases[0];

  const handleStatusChange = async (newStatus: CaseStatus) => {
    if (!selectedCase) return;
    await onUpdateStatus(selectedCase.case_id, newStatus, `Analyst changed state to ${newStatus.toUpperCase()}`);
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCase || !newNoteContent.trim()) return;
    await onAddNote(selectedCase.case_id, authorName, newNoteContent.trim());
    setNewNoteContent('');
  };

  const statusColors: Record<CaseStatus, string> = {
    new: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
    triage: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
    investigating: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    resolved: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    closed: 'bg-slate-800 text-slate-400 border-slate-700',
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 h-[calc(100vh-140px)]">
      {/* Left List of Cases */}
      <div className="lg:col-span-5 flex flex-col bg-slate-900/60 rounded-xl border border-slate-800 overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex justify-between items-center bg-slate-950/60">
          <div className="flex items-center space-x-2">
            <Briefcase className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-white">Security Incident Cases</h2>
          </div>
          <span className="text-xs font-mono text-slate-400">{cases.length} Total</span>
        </div>

        <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60 p-2 space-y-1">
          {cases.map((c) => {
            const isSelected = selectedCase?.case_id === c.case_id;
            return (
              <div
                key={c.case_id}
                onClick={() => setSelectedCaseId(c.case_id)}
                className={`p-3 rounded-lg cursor-pointer transition-all ${
                  isSelected
                    ? 'bg-cyan-500/10 border border-cyan-500/30'
                    : 'hover:bg-slate-800/40 border border-transparent'
                }`}
              >
                <div className="flex justify-between items-start mb-1">
                  <span className="text-[10px] font-mono text-cyan-400">{c.case_id}</span>
                  <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border ${statusColors[c.status]}`}>
                    {c.status}
                  </span>
                </div>
                <h4 className="text-xs font-semibold text-white mb-1.5 line-clamp-1">{c.title}</h4>
                <div className="flex items-center justify-between text-[11px] text-slate-400">
                  <span className="flex items-center gap-1">
                    <User className="w-3 h-3 text-slate-500" />
                    {c.assigned_to}
                  </span>
                  <span className="font-mono text-[10px] text-slate-500">
                    {c.linked_alert_ids.length} alerts linked
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Right Detail Pane */}
      <div className="lg:col-span-7 flex flex-col bg-slate-900/60 rounded-xl border border-slate-800 overflow-hidden">
        {selectedCase ? (
          <div className="flex-1 flex flex-col h-full overflow-hidden">
            {/* Top Bar with Status Controls */}
            <div className="p-4 border-b border-slate-800 bg-slate-950/80 space-y-3">
              <div className="flex justify-between items-start">
                <div>
                  <div className="flex items-center space-x-2 mb-1">
                    <span className="text-xs font-mono text-cyan-400">{selectedCase.case_id}</span>
                    <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border ${statusColors[selectedCase.status]}`}>
                      {selectedCase.status}
                    </span>
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/30">
                      {selectedCase.priority.toUpperCase()} PRIORITY
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-white">{selectedCase.title}</h3>
                </div>

                {/* Workflow Status Transition Selector */}
                <div className="flex items-center space-x-2">
                  <span className="text-xs text-slate-400">State:</span>
                  <select
                    value={selectedCase.status}
                    onChange={(e) => handleStatusChange(e.target.value as CaseStatus)}
                    className="bg-slate-900 border border-slate-700 text-xs text-white rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="new">NEW</option>
                    <option value="triage">TRIAGE</option>
                    <option value="investigating">INVESTIGATING</option>
                    <option value="resolved">RESOLVED</option>
                    <option value="closed">CLOSED</option>
                  </select>
                </div>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                {selectedCase.description}
              </p>

              {/* Tags & Linked Alerts */}
              <div className="flex flex-wrap gap-2 pt-1 text-xs">
                {selectedCase.tags.map((tag, i) => (
                  <span key={i} className="flex items-center gap-1 bg-slate-800 px-2 py-0.5 rounded text-[10px] text-slate-300">
                    <Tag className="w-2.5 h-2.5 text-cyan-400" />
                    {tag}
                  </span>
                ))}
              </div>
            </div>

            {/* Scrollable Center: Notes & Audit Trail */}
            <div className="flex-1 overflow-y-auto p-4 space-y-5">
              {/* Linked Alerts List */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                  <FileText className="w-3.5 h-3.5 text-blue-400" />
                  Linked Alert Telemetry ({selectedCase.linked_alert_ids.length})
                </h4>
                <div className="flex flex-wrap gap-2">
                  {selectedCase.linked_alert_ids.map((aid) => (
                    <span key={aid} className="font-mono text-[11px] bg-slate-950 px-2.5 py-1 rounded border border-slate-800 text-cyan-300">
                      ID: {aid.slice(0, 8)}...
                    </span>
                  ))}
                </div>
              </div>

              {/* Investigation Notes Thread */}
              <div className="space-y-3">
                <h4 className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                  <FileText className="w-3.5 h-3.5 text-cyan-400" />
                  Analyst Triage & Investigation Notes
                </h4>
                <div className="space-y-2">
                  {selectedCase.notes.length === 0 ? (
                    <div className="text-xs text-slate-500 italic">No notes added yet.</div>
                  ) : (
                    selectedCase.notes.map((note) => (
                      <div key={note.note_id} className="bg-slate-950 p-3 rounded-lg border border-slate-800/80 space-y-1">
                        <div className="flex justify-between items-center text-[10px] text-slate-400">
                          <span className="font-semibold text-cyan-400">{note.author}</span>
                          <span className="font-mono">{new Date(note.created_at).toLocaleString()}</span>
                        </div>
                        <p className="text-xs text-slate-200 leading-relaxed">{note.content}</p>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Audit Trail */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                  <History className="w-3.5 h-3.5 text-purple-400" />
                  Audit & Provenance History
                </h4>
                <div className="space-y-1.5">
                  {selectedCase.audit_trail.map((entry, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-[11px] text-slate-400 bg-slate-950/40 p-2 rounded">
                      <span className="font-mono text-[10px] text-slate-500 shrink-0">
                        {new Date(entry.timestamp).toLocaleTimeString()}
                      </span>
                      <span className="font-semibold text-slate-300">{entry.actor}:</span>
                      <span className="text-slate-400">{entry.detail}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Note Input Box at Bottom */}
            <form onSubmit={handleAddNote} className="p-3 border-t border-slate-800 bg-slate-950 flex items-center gap-2">
              <input
                type="text"
                value={newNoteContent}
                onChange={(e) => setNewNoteContent(e.target.value)}
                placeholder="Add analyst note or containment instruction..."
                className="flex-1 bg-slate-900 border border-slate-700 text-xs rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
              <button
                type="submit"
                className="px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-1.5"
              >
                <Send className="w-3.5 h-3.5" />
                <span>Post</span>
              </button>
            </form>
          </div>
        ) : (
          <div className="p-12 text-center text-slate-500">Select a case to inspect details.</div>
        )}
      </div>
    </div>
  );
};
