"""
Data contracts and Pydantic models for SOC Analisis Engine.
Based on Guo et al. (2026) "Intelligent priority awareness method for alert data in SOC threat response".
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(str, Enum):
    LOW = "low"          # 0 <= R < 60
    MEDIUM = "medium"    # 60 <= R < 80
    HIGH = "high"        # 80 <= R <= 100


class ProcessingStatus(str, Enum):
    RECEIVED = "received"
    NORMALIZED = "normalized"
    PERIODIC_FILTERED = "periodic_filtered"
    AGENT_ORCHESTRATED = "agent_orchestrated"
    SCORED = "scored"
    INDEXED = "indexed"


class AnalysisStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class CaseStatus(str, Enum):
    NEW = "new"
    TRIAGE = "triage"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


# --- Alert Input & Normalization Models ---

class RawAlertInput(BaseModel):
    timestamp: Optional[datetime] = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "Wazuh"
    source_event_id: Optional[str] = None
    tenant_id: str = "tenant-default"
    src_ip: str
    dst_ip: str
    dst_port: Optional[int] = 80
    protocol: str = "TCP"
    alert_type: str
    severity: SeverityLevel = SeverityLevel.MEDIUM
    raw_message: str = ""
    asset_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AlertTriplet(BaseModel):
    triplet_key: str  # Format: "src_ip->dst_ip:alert_type"
    src_ip: str
    dst_ip: str
    alert_type: str
    hourly_counts: List[float] = Field(default_factory=list)


# --- Noise Reduction Models (Section 4) ---

class FFTAnalysisResult(BaseModel):
    dominant_peak_ratio: float
    candidate_period_hours: float
    is_periodic_candidate: bool
    details: str = ""


class PCCAnalysisResult(BaseModel):
    mean_pairwise_correlation: float
    is_stable_periodic: bool
    details: str = ""


class RiskGateEvaluation(BaseModel):
    has_high_risk_evidence: bool
    ioc_matched: bool = False
    exploitable_vuln: bool = False
    high_criticality_asset: bool = False
    kill_chain_advancement: bool = False
    reasons: List[str] = Field(default_factory=list)


class AgentEvidenceOutput(BaseModel):
    branch: str  # "knowledge_retrieval", "association_query", "bert_reasoning"
    decision: float  # 1.0 = true alert, 0.0 = false positive
    confidence: float  # 0.0 to 1.0
    weight: float
    evidence_details: Dict[str, Any] = Field(default_factory=dict)


class MultiAgentFusionResult(BaseModel):
    sta_score: float  # S_TA true-alert score
    decision: str  # "RETAIN", "FILTER", "MANUAL_REVIEW"
    branch_outputs: List[AgentEvidenceOutput] = Field(default_factory=list)
    risk_gate_activated: bool = False
    explanation: str = ""


# --- AHP Risk Scoring Models (Section 5.3 & Tables 4, 5) ---

class SubIndicatorValue(BaseModel):
    name: str
    raw_value: Any
    normalized_value: float  # v_ij in [0, 1]
    weight: float  # w_ij
    weighted_score: float  # w_ij * v_ij


class CriterionScore(BaseModel):
    criterion_name: str
    criterion_weight: float  # W_i
    score: float  # C_i = sum(w_ij * v_ij)
    sub_indicators: List[SubIndicatorValue] = Field(default_factory=list)


class AHPScoringResult(BaseModel):
    base_risk_score: float  # R_b = 100 * sum(W_i * C_i)
    ext_environment_multiplier: float = 1.0  # E_ext
    int_environment_multiplier: float = 1.0  # E_int
    final_risk_score: float  # R = min(100, R_b * E_ext * E_int)
    risk_level: RiskLevel
    criteria_breakdown: List[CriterionScore] = Field(default_factory=list)
    scoring_version: str = "AHP-2026-v1.0"
    formula_notes: str = ""


# --- Semantic Integrity Models (Algorithm 2) ---

class SemanticIntegrityReport(BaseModel):
    passed: bool
    canonical_id: str
    entity_types_valid: bool = True
    relations_valid: bool = True
    freshness_valid: bool = True
    no_conflict: bool = True
    quarantined: bool = False
    violations: List[str] = Field(default_factory=list)


# --- Enriched Alert Model ---

class EnrichedAlert(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_event_id: Optional[str] = None
    tenant_id: str = "tenant-default"
    source: str
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Core fields
    src_ip: str
    dst_ip: str
    dst_port: Optional[int] = 80
    protocol: str = "TCP"
    alert_type: str
    severity: SeverityLevel
    raw_message: str
    triplet_key: str
    
    # Noise Reduction & Triage Path
    fft_result: Optional[FFTAnalysisResult] = None
    pcc_result: Optional[PCCAnalysisResult] = None
    risk_gate: Optional[RiskGateEvaluation] = None
    multi_agent: Optional[MultiAgentFusionResult] = None
    filtered_as_noise: bool = False
    
    # Knowledge & Semantic Integrity
    semantic_report: Optional[SemanticIntegrityReport] = None
    graph_snapshot_id: Optional[str] = "G-SNAP-202610-001"
    
    # AHP Scoring
    ahp_scoring: Optional[AHPScoringResult] = None
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.LOW
    
    # AI RAG & Explanation
    rag_explanation: Optional[str] = None
    mitre_attack_id: Optional[str] = None
    mitre_attack_name: Optional[str] = None
    recommended_actions: List[str] = Field(default_factory=list)
    
    # Processing states
    processing_status: ProcessingStatus = ProcessingStatus.RECEIVED
    analysis_status: AnalysisStatus = AnalysisStatus.PENDING
    linked_case_id: Optional[str] = None


# --- Case Management Models ---

class CaseNote(BaseModel):
    note_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    author: str
    content: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CaseAuditEntry(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str
    action: str
    detail: str


class Case(BaseModel):
    case_id: str = Field(default_factory=lambda: f"CASE-{uuid.uuid4().hex[:8].upper()}")
    title: str
    description: str
    status: CaseStatus = CaseStatus.NEW
    severity: SeverityLevel = SeverityLevel.MEDIUM
    priority: RiskLevel = RiskLevel.MEDIUM
    assigned_to: Optional[str] = "Unassigned"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    linked_alert_ids: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    notes: List[CaseNote] = Field(default_factory=list)
    audit_trail: List[CaseAuditEntry] = Field(default_factory=list)
