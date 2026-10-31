export type RiskLevel = 'low' | 'medium' | 'high';
export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical';
export type CaseStatus = 'new' | 'triage' | 'investigating' | 'resolved' | 'closed';

export interface SubIndicatorValue {
  name: string;
  raw_value: any;
  normalized_value: number;
  weight: number;
  weighted_score: number;
}

export interface CriterionScore {
  criterion_name: string;
  criterion_weight: number;
  score: number;
  sub_indicators: SubIndicatorValue[];
}

export interface AHPScoringResult {
  base_risk_score: number;
  ext_environment_multiplier: number;
  int_environment_multiplier: number;
  final_risk_score: number;
  risk_level: RiskLevel;
  criteria_breakdown: CriterionScore[];
  scoring_version: string;
  formula_notes: string;
}

export interface AgentEvidenceOutput {
  branch: string;
  decision: number;
  confidence: number;
  weight: number;
  evidence_details: Record<string, any>;
}

export interface MultiAgentFusionResult {
  sta_score: number;
  decision: 'RETAIN' | 'FILTER' | 'MANUAL_REVIEW';
  branch_outputs: AgentEvidenceOutput[];
  risk_gate_activated: boolean;
  explanation: string;
}

export interface FFTAnalysisResult {
  dominant_peak_ratio: number;
  candidate_period_hours: number;
  is_periodic_candidate: boolean;
  details: string;
}

export interface PCCAnalysisResult {
  mean_pairwise_correlation: number;
  is_stable_periodic: boolean;
  details: string;
}

export interface RiskGateEvaluation {
  has_high_risk_evidence: boolean;
  ioc_matched: boolean;
  exploitable_vuln: boolean;
  high_criticality_asset: boolean;
  kill_chain_advancement: boolean;
  reasons: string[];
}

export interface EnrichedAlert {
  event_id: string;
  source_event_id?: string;
  tenant_id: string;
  source: string;
  received_at: string;
  event_time: string;
  src_ip: string;
  dst_ip: string;
  dst_port?: number;
  protocol: string;
  alert_type: string;
  severity: SeverityLevel;
  raw_message: string;
  triplet_key: string;
  
  fft_result?: FFTAnalysisResult;
  pcc_result?: PCCAnalysisResult;
  risk_gate?: RiskGateEvaluation;
  multi_agent?: MultiAgentFusionResult;
  filtered_as_noise: boolean;
  
  ahp_scoring?: AHPScoringResult;
  risk_score: number;
  risk_level: RiskLevel;
  
  rag_explanation?: string;
  mitre_attack_id?: string;
  mitre_attack_name?: string;
  recommended_actions: string[];
  
  processing_status: string;
  analysis_status: string;
  linked_case_id?: string;
}

export interface CaseNote {
  note_id: string;
  author: string;
  content: string;
  created_at: string;
}

export interface CaseAuditEntry {
  timestamp: string;
  actor: string;
  action: string;
  detail: string;
}

export interface Case {
  case_id: string;
  title: string;
  description: string;
  status: CaseStatus;
  severity: SeverityLevel;
  priority: RiskLevel;
  assigned_to: string;
  created_at: string;
  updated_at: string;
  linked_alert_ids: string[];
  tags: string[];
  notes: CaseNote[];
  audit_trail: CaseAuditEntry[];
}

export interface AnalyticsOverview {
  total_alerts: number;
  filtered_noise_count: number;
  retained_alerts_count: number;
  noise_reduction_rate: number;
  active_cases_count: number;
  branch_distribution: {
    fft_pcc_branch_pct: number;
    multi_agent_branch_pct: number;
    bert_reasoning_pct: number;
    filtered_noise_pct: number;
  };
  risk_distribution: {
    high_risk: number;
    medium_risk: number;
    low_risk: number;
    total_retained: number;
  };
  benchmark_comparison: Array<{
    system: string;
    mttr_min: number;
    throughput_h: number;
    nasa_tlx: number;
    high_risk_recall: number;
  }>;
  improvements: {
    mttr_reduction_pct: number;
    throughput_boost_pct: number;
    analyst_cognitive_load_reduction_pct: number;
    high_risk_recall: number;
  };
}

export interface TopologyNode {
  id: string;
  label: string;
  type: 'asset' | 'technique' | 'vulnerability' | 'apt' | 'ioc';
  criticality?: string;
  tactic?: string;
  cvss?: number;
  val: number;
}

export interface TopologyEdge {
  source: string;
  target: string;
  label: string;
}

export interface TopologyResponse {
  snapshot_id: string;
  status: string;
  semantic_integrity: Record<string, any>;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}
