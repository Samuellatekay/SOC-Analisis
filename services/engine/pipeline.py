"""
End-to-End SOC Priority Awareness & Analysis Pipeline.
Coordinates Ingress Normalization -> FFT-PCC Periodic Detection -> Conservative Risk Gate
-> Multi-Agent Evidence Orchestration -> Semantic Integrity -> AHP Risk Scoring -> Async RAG.
"""

from typing import Dict, Any, Optional

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))

from packages.contracts.models import (
    RawAlertInput,
    EnrichedAlert,
    ProcessingStatus,
    AnalysisStatus,
    RiskLevel,
    SeverityLevel,
)
from services.engine.normalizer import AlertNormalizer
from services.engine.fft_pcc import FFTPCCDetector
from services.engine.risk_gate import ConservativeRiskGate
from services.engine.multi_agent import MasterAgentOrchestrator
from services.engine.semantic_integrity import SemanticIntegrityEngine
from services.engine.ahp_scorer import AHPRiskEngine
from services.rag_worker.explainer import RAGExplainer


class SOCAnalisisEngine:
    def __init__(self):
        self.normalizer = AlertNormalizer()
        self.fft_pcc = FFTPCCDetector()
        self.risk_gate = ConservativeRiskGate()
        self.multi_agent = MasterAgentOrchestrator()
        self.semantic_engine = SemanticIntegrityEngine()
        self.ahp_scorer = AHPRiskEngine()
        self.rag_explainer = RAGExplainer()

    def process_alert(
        self,
        raw_alert: RawAlertInput,
        context: Optional[Dict[str, Any]] = None,
    ) -> EnrichedAlert:
        ctx = context or {}

        # 1. Normalization & Triplet Construction
        norm_dict = self.normalizer.normalize(raw_alert)
        triplet_key = norm_dict["triplet_key"]
        triplet = self.normalizer.get_triplet(triplet_key)
        hourly_series = triplet.hourly_counts if triplet else [1.0]

        # 2. Risk Gate Evaluation (Early context inspection)
        risk_gate_eval = self.risk_gate.evaluate(norm_dict, ctx)

        # 3. FFT-PCC Periodic Noise Analysis
        fft_res = self.fft_pcc.analyze_fft(hourly_series)
        pcc_res = None
        is_periodic_noise = False

        if fft_res.is_periodic_candidate:
            pcc_res = self.fft_pcc.analyze_pcc(hourly_series, fft_res.candidate_period_hours)
            if pcc_res.is_stable_periodic:
                # Candidate for periodic noise
                if not risk_gate_eval.has_high_risk_evidence:
                    # Low-risk periodic noise filtered!
                    is_periodic_noise = True

        # 4. Multi-Agent Evidence Orchestration
        # Run if not filtered as periodic noise OR if risk-gated high risk periodic
        multi_agent_res = None
        filtered_as_noise = False

        if is_periodic_noise:
            filtered_as_noise = True
            proc_status = ProcessingStatus.PERIODIC_FILTERED
        else:
            multi_agent_res = self.multi_agent.orchestrate(norm_dict, ctx, risk_gate_eval)
            if multi_agent_res.decision == "FILTER":
                filtered_as_noise = True
                proc_status = ProcessingStatus.PERIODIC_FILTERED
            else:
                proc_status = ProcessingStatus.AGENT_ORCHESTRATED

        # 5. Semantic Integrity Verification
        semantic_report = self.semantic_engine.verify_alert_context(norm_dict["event_id"], ctx)

        # 6. AHP Dynamic Risk Scoring (for retained/uncertain alerts)
        ahp_res = None
        final_risk = 15.0
        risk_level = RiskLevel.LOW

        if not filtered_as_noise:
            # Only admitted if semantic integrity passes
            if semantic_report.passed:
                ahp_res = self.ahp_scorer.calculate_risk(norm_dict, ctx)
                final_risk = ahp_res.final_risk_score
                risk_level = ahp_res.risk_level
                proc_status = ProcessingStatus.SCORED
            else:
                final_risk = 30.0
                risk_level = RiskLevel.LOW
                proc_status = ProcessingStatus.NORMALIZED

        # 7. RAG & ATT&CK Context
        rag_data = {}
        if not filtered_as_noise and ahp_res:
            rag_data = self.rag_explainer.generate_explanation(
                norm_dict,
                ahp_res.model_dump(),
                ctx,
            )

        # Construct final enriched alert
        enriched = EnrichedAlert(
            event_id=norm_dict["event_id"],
            source_event_id=norm_dict["source_event_id"],
            tenant_id=norm_dict["tenant_id"],
            source=norm_dict["source"],
            received_at=norm_dict["received_at"],
            event_time=norm_dict["event_time"],
            src_ip=norm_dict["src_ip"],
            dst_ip=norm_dict["dst_ip"],
            dst_port=norm_dict["dst_port"],
            protocol=norm_dict["protocol"],
            alert_type=norm_dict["alert_type"],
            severity=norm_dict["severity"],
            raw_message=norm_dict["raw_message"],
            triplet_key=triplet_key,
            fft_result=fft_res,
            pcc_result=pcc_res,
            risk_gate=risk_gate_eval,
            multi_agent=multi_agent_res,
            filtered_as_noise=filtered_as_noise,
            semantic_report=semantic_report,
            graph_snapshot_id="G-SNAP-202610-001",
            ahp_scoring=ahp_res,
            risk_score=final_risk,
            risk_level=risk_level,
            rag_explanation=rag_data.get("rag_explanation"),
            mitre_attack_id=rag_data.get("mitre_attack_id"),
            mitre_attack_name=rag_data.get("mitre_attack_name"),
            recommended_actions=rag_data.get("recommended_actions", []),
            processing_status=proc_status,
            analysis_status=AnalysisStatus.COMPLETED if rag_data else AnalysisStatus.SKIPPED,
        )

        return enriched

    def process_alert_sync(
        self,
        raw_alert: RawAlertInput,
        context: Optional[Dict[str, Any]] = None,
    ) -> EnrichedAlert:
        """Alias for process_alert."""
        return self.process_alert(raw_alert, context)
