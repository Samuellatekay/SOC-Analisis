"""
BERT-assisted Multi-Agent Evidence Orchestration & Conservative Evidence Fusion.
Based on Section 4.3, Table 1, and Equation (7) from Guo et al. (2026).
"""

from typing import Dict, Any, List
import re

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))

from packages.contracts.models import (
    AgentEvidenceOutput,
    MultiAgentFusionResult,
    RiskGateEvaluation,
)


class KnowledgeRetrievalAgent:
    """Queries local security rules for attack-pattern verification."""
    def __init__(self):
        self.rules = {
            "ssh_brute_force": {
                "rule_name": "SSH Brute-force Threshold",
                "min_attempts": 10,
                "indicators": ["port 22", "failed login", "auth failure"],
                "default_confidence": 0.88,
            },
            "port_scan": {
                "rule_name": "Recon Port Scan",
                "min_ports": 15,
                "indicators": ["syn flood", "rapid ports", "rst response"],
                "default_confidence": 0.82,
            },
            "web_attack": {
                "rule_name": "OWASP Injection Patterns",
                "indicators": ["select", "union", "<script>", "../", "etc/passwd"],
                "default_confidence": 0.90,
            },
            "malware_communication": {
                "rule_name": "C2 Beaconing Pattern",
                "indicators": ["dga", "raw ip connection", "suspicious port", "dns tunneling"],
                "default_confidence": 0.92,
            },
        }

    def evaluate(self, alert_data: Dict[str, Any]) -> AgentEvidenceOutput:
        alert_type = str(alert_data.get("alert_type", "")).lower().replace(" ", "_")
        matched_rule = None
        for key, r in self.rules.items():
            if key in alert_type:
                matched_rule = r
                break

        msg = str(alert_data.get("raw_message", "")).lower()
        if matched_rule:
            matched_indicators = [ind for ind in matched_rule["indicators"] if ind in msg]
            confidence = matched_rule["default_confidence"]
            # If msg explicitly matches rule indicators -> high confidence true alert
            is_true = 1.0 if (len(matched_indicators) > 0 or "failed" in msg or "attack" in msg) else 0.7
            return AgentEvidenceOutput(
                branch="knowledge_retrieval",
                decision=is_true,
                confidence=confidence,
                weight=0.35,
                evidence_details={
                    "rule": matched_rule["rule_name"],
                    "matched_indicators": matched_indicators,
                },
            )

        return AgentEvidenceOutput(
            branch="knowledge_retrieval",
            decision=0.5,
            confidence=0.5,
            weight=0.35,
            evidence_details={"rule": "Generic Default Rule", "matched_indicators": []},
        )


class AssociationQueryAgent:
    """
    Coordinates 6 plugins:
    1. IOC Matching Plugin
    2. IP Reputation Query Plugin
    3. NetFlow Behavior Plugin
    4. Whois Query Plugin
    5. Asset Query Plugin
    6. Vulnerability Correlation Plugin
    """
    def __init__(self):
        # Known blacklists / reputation simulator
        self.known_bad_asns = {"AS4134", "AS14061", "AS9009"}
        self.known_bad_subnets = ["203.0.113.", "198.51.100."]

    def evaluate(self, alert_data: Dict[str, Any], context: Dict[str, Any]) -> AgentEvidenceOutput:
        src_ip = alert_data.get("src_ip", "")
        dst_ip = alert_data.get("dst_ip", "")
        plugins_run = {}

        # 1. IOC Matching Plugin
        ioc_hit = context.get("ioc_match", False) or any(src_ip.startswith(s) for s in self.known_bad_subnets)
        plugins_run["ioc_matching"] = {"matched": ioc_hit, "source": "OpenCTI CTI Cache"}

        # 2. IP Reputation Plugin
        asn = context.get("src_asn", "AS13335")
        bad_rep = asn in self.known_bad_asns or ioc_hit
        plugins_run["ip_reputation"] = {
            "asn": asn,
            "reputation_score": 0.15 if bad_rep else 0.85,
            "threat_flag": bad_rep,
        }

        # 3. NetFlow Behavior Plugin
        flow_anomaly = context.get("flow_anomaly", False) or "anomaly" in str(alert_data.get("raw_message", "")).lower()
        plugins_run["netflow_behavior"] = {
            "abnormal_volume": flow_anomaly,
            "session_count": context.get("session_count", 465 if "brute" in str(alert_data.get("alert_type", "")).lower() else 12),
        }

        # 4. Asset Query Plugin (GLPI)
        asset_crit = context.get("asset_business_value", "support")
        plugins_run["asset_query"] = {
            "target_ip": dst_ip,
            "criticality": asset_crit,
            "dept": context.get("asset_dept", "Finance/DataCenter"),
        }

        # 5. Vulnerability Correlation Plugin
        vuln_cve = context.get("cve_id", "CVE-2024-38077" if "remote" in str(alert_data.get("alert_type", "")).lower() else None)
        plugins_run["vulnerability_correlation"] = {
            "associated_cve": vuln_cve,
            "has_exploit": context.get("vulnerability_exploitability", "none") == "public_exploit",
        }

        # Synthesize association output
        positives = sum(1 for p in [ioc_hit, bad_rep, flow_anomaly, vuln_cve is not None] if p)
        decision = 1.0 if positives >= 2 else (0.7 if positives == 1 else 0.1)
        confidence = 0.90 if ioc_hit else (0.80 if positives >= 1 else 0.70)

        return AgentEvidenceOutput(
            branch="association_query",
            decision=decision,
            confidence=confidence,
            weight=0.35,
            evidence_details={"plugins": plugins_run},
        )


class BERTReasoningAgent:
    """
    BERT-assisted Semantic Reasoning Agent.
    Evaluates text structure of alert message and entity context.
    """
    def __init__(self):
        self.noise_keywords = ["probe", "keepalive", "heartbeat", "scheduled_task", "routine", "health_check"]
        self.malicious_keywords = ["brute_force", "exploit", "cve-", "unauthorized", "backdoor", "c2", "injection", "root"]

    def evaluate(self, alert_data: Dict[str, Any]) -> AgentEvidenceOutput:
        raw_text = (
            f"[CLS] Type: {alert_data.get('alert_type', '')} | "
            f"Src: {alert_data.get('src_ip', '')}:{alert_data.get('dst_port', 80)} -> "
            f"Dst: {alert_data.get('dst_ip', '')} | "
            f"Msg: {alert_data.get('raw_message', '')} [SEP]"
        ).lower()

        # Semantic classification inference emulation (aligned with paper Table 12 & Fig 7/10)
        noise_hits = sum(1 for w in self.noise_keywords if w in raw_text)
        malicious_hits = sum(1 for w in self.malicious_keywords if w in raw_text)

        if malicious_hits > 0:
            prob_true_alert = min(0.98, 0.75 + (malicious_hits * 0.1))
            confidence = 0.92
        elif noise_hits > 0:
            prob_true_alert = max(0.04, 0.25 - (noise_hits * 0.1))
            confidence = 0.88
        else:
            prob_true_alert = 0.50
            confidence = 0.75

        return AgentEvidenceOutput(
            branch="bert_reasoning",
            decision=round(prob_true_alert, 3),
            confidence=confidence,
            weight=0.30,
            evidence_details={
                "input_sequence": raw_text[:120] + "...",
                "semantic_features": {
                    "malicious_hits": malicious_hits,
                    "noise_hits": noise_hits,
                },
            },
        )


class MasterAgentOrchestrator:
    """
    Deterministic Master Agent & Conservative Evidence Fusion.
    Implements Eq (7): S_TA = sum_j (omega_j * c_j * y_j) + eta * G
    """
    def __init__(self):
        self.knowledge_agent = KnowledgeRetrievalAgent()
        self.query_agent = AssociationQueryAgent()
        self.bert_agent = BERTReasoningAgent()

    def orchestrate(
        self,
        alert_data: Dict[str, Any],
        context: Dict[str, Any],
        risk_gate: RiskGateEvaluation,
    ) -> MultiAgentFusionResult:
        # Run 3 auxiliary agents
        y_k = self.knowledge_agent.evaluate(alert_data)
        y_q = self.query_agent.evaluate(alert_data, context)
        y_b = self.bert_agent.evaluate(alert_data)

        branches = [y_k, y_q, y_b]

        # Calculate S_TA (Eq 7)
        weighted_sum = sum(b.weight * b.confidence * b.decision for b in branches)
        total_weight = sum(b.weight * b.confidence for b in branches)
        
        base_sta = weighted_sum / total_weight if total_weight > 0 else 0.5

        # G is binary risk gate signal
        G = 1.0 if risk_gate.has_high_risk_evidence else 0.0
        eta = 0.20  # Risk gate boost parameter
        
        final_sta = min(1.0, base_sta + (eta * G))

        # Paper Decision Thresholds:
        # S_TA >= 0.60 -> Retain True Alert
        # S_TA <= 0.30 -> Filter False Positive
        # Else -> Manual Review
        # Override: If risk gate has confirmed high-risk evidence, ALWAYS retain!
        if risk_gate.has_high_risk_evidence:
            decision = "RETAIN"
            explanation = "Risk-gated high risk evidence present. Force retain true alert regardless of other branches."
        elif final_sta >= 0.60:
            decision = "RETAIN"
            explanation = f"True Alert score S_TA={final_sta:.2f} >= 0.60. Retained for AHP risk scoring."
        elif final_sta <= 0.30:
            decision = "FILTER"
            explanation = f"True Alert score S_TA={final_sta:.2f} <= 0.30. Classified as false positive noise."
        else:
            decision = "MANUAL_REVIEW"
            explanation = f"True Alert score S_TA={final_sta:.2f} in uncertain region (0.30, 0.60). Escalated to analyst triage."

        return MultiAgentFusionResult(
            sta_score=round(final_sta, 3),
            decision=decision,
            branch_outputs=branches,
            risk_gate_activated=risk_gate.has_high_risk_evidence,
            explanation=explanation,
        )
