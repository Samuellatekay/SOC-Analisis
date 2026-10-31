"""
AHP Dynamic Risk Scoring Engine.
Directly implements Section 5.3, Equations (8), (9), (10), and Tables 4 & 5
from Guo et al. (2026) "Intelligent priority awareness method for alert data in SOC threat response".
"""

import math
from typing import Dict, Any, List, Tuple
import numpy as np

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))

from packages.contracts.models import (
    AHPScoringResult,
    CriterionScore,
    SubIndicatorValue,
    RiskLevel,
)


class AHPRiskEngine:
    """
    Analytic Hierarchy Process (AHP) Dynamic Risk Scorer.
    Consistency Ratio: CR = 0.041 < 0.10.
    """
    def __init__(self):
        # Criterion weights W_i (Table 5)
        self.W = {
            "target_criticality": 0.16,
            "attack_stage_hazard": 0.31,
            "threat_intelligence_match": 0.18,
            "attack_feasibility": 0.22,
            "attack_persistence": 0.07,
            "environmental_situation": 0.06,
        }

        # Sub-indicator weights w_ij (Table 4)
        self.w = {
            "target_criticality": {
                "asset_business_value": 0.40,
                "data_sensitivity": 0.30,
                "attack_surface_exposure": 0.30,
            },
            "attack_stage_hazard": {
                "phase_hazard_coeff": 0.70,
                "stage_policy_weight": 0.30,
            },
            "threat_intelligence_match": {
                "ioc_confidence": 0.30,
                "vulnerability_existence": 0.20,
                "apt_association": 0.40,
                "intelligence_freshness": 0.10,
            },
            "attack_feasibility": {
                "vulnerability_exploitability": 0.50,
                "path_reachability": 0.30,
                "protection_bypass": 0.20,
            },
            "attack_persistence": {
                "homogeneous_correlation": 0.40,
                "kill_chain_progression": 0.40,
                "lateral_movement_potential": 0.20,
            },
            "environmental_situation": {
                "external_threat_posture": 0.60,
                "internal_security_status": 0.40,
            },
        }

        # Stage mapping for ATT&CK Kill-chain
        self.stage_map = {
            "reconnaissance": 0.2,
            "resource_development": 0.3,
            "initial_access": 0.5,
            "execution": 0.7,
            "persistence": 0.75,
            "privilege_escalation": 0.8,
            "defense_evasion": 0.8,
            "credential_access": 0.85,
            "discovery": 0.6,
            "lateral_movement": 0.85,
            "collection": 0.7,
            "command_and_control": 0.9,
            "exfiltration": 0.95,
            "impact": 1.0,
        }

    def normalize_target_criticality(self, context: Dict[str, Any]) -> List[SubIndicatorValue]:
        # 1. Asset business value: Core=1.0, support=0.6, test=0.2
        val_raw = str(context.get("asset_business_value", "support")).lower()
        if "core" in val_raw:
            v_val = 1.0
        elif "support" in val_raw:
            v_val = 0.6
        else:
            v_val = 0.2

        # 2. Data sensitivity: Top secret=1.0, confidential=0.75, internal=0.5, public=0.25
        sens_raw = str(context.get("data_sensitivity", "internal")).lower()
        if "top" in sens_raw or "secret" in sens_raw:
            v_sens = 1.0
        elif "confidential" in sens_raw:
            v_sens = 0.75
        elif "internal" in sens_raw:
            v_sens = 0.5
        else:
            v_sens = 0.25

        # 3. Attack surface exposure: Internet=1.0, DMZ=0.8, internal=0.6, isolated=0.2
        exp_raw = str(context.get("attack_surface_exposure", "internal")).lower()
        if "internet" in exp_raw:
            v_exp = 1.0
        elif "dmz" in exp_raw:
            v_exp = 0.8
        elif "internal" in exp_raw:
            v_exp = 0.6
        else:
            v_exp = 0.2

        weights = self.w["target_criticality"]
        return [
            SubIndicatorValue(
                name="Asset Business Value",
                raw_value=val_raw,
                normalized_value=v_val,
                weight=weights["asset_business_value"],
                weighted_score=weights["asset_business_value"] * v_val,
            ),
            SubIndicatorValue(
                name="Data Sensitivity",
                raw_value=sens_raw,
                normalized_value=v_sens,
                weight=weights["data_sensitivity"],
                weighted_score=weights["data_sensitivity"] * v_sens,
            ),
            SubIndicatorValue(
                name="Attack Surface Exposure",
                raw_value=exp_raw,
                normalized_value=v_exp,
                weight=weights["attack_surface_exposure"],
                weighted_score=weights["attack_surface_exposure"] * v_exp,
            ),
        ]

    def normalize_attack_stage(self, context: Dict[str, Any], alert_type: str) -> List[SubIndicatorValue]:
        # Phase hazard coefficient: ATT&CK/kill-chain phase mapped to [0,1]
        phase_raw = str(context.get("attack_stage", "")).lower()
        if not phase_raw:
            for k in self.stage_map:
                if k in alert_type.lower():
                    phase_raw = k
                    break
        v_phase = self.stage_map.get(phase_raw, 0.5)

        # Stage policy weight: Dynamic policy coefficient clipped to [0,1]
        v_policy = float(np.clip(context.get("stage_policy_weight", 0.60), 0.0, 1.0))

        weights = self.w["attack_stage_hazard"]
        return [
            SubIndicatorValue(
                name="Phase Hazard Coefficient",
                raw_value=phase_raw or "generic_attempt",
                normalized_value=round(v_phase, 3),
                weight=weights["phase_hazard_coeff"],
                weighted_score=round(weights["phase_hazard_coeff"] * v_phase, 4),
            ),
            SubIndicatorValue(
                name="Stage Policy Weight",
                raw_value=v_policy,
                normalized_value=round(v_policy, 3),
                weight=weights["stage_policy_weight"],
                weighted_score=round(weights["stage_policy_weight"] * v_policy, 4),
            ),
        ]

    def normalize_threat_intel(self, context: Dict[str, Any]) -> List[SubIndicatorValue]:
        # IOC confidence [0, 1]
        v_ioc = float(np.clip(context.get("ioc_confidence", 0.85 if context.get("ioc_match") else 0.1), 0.0, 1.0))
        
        # Vulnerability existence: Existing CVE=1.0, possible=0.5, none=0
        vuln_raw = str(context.get("vulnerability_existence", "none")).lower()
        if context.get("cve_id") or "existing" in vuln_raw or vuln_raw == "1.0":
            v_vuln = 1.0
        elif "possible" in vuln_raw or vuln_raw == "0.5":
            v_vuln = 0.5
        else:
            v_vuln = 0.0

        # APT association: APT-linked technique weighted by threat level [0, 1]
        apt_raw = context.get("apt_group", None)
        v_apt = 0.90 if apt_raw else float(context.get("apt_weight", 0.0))

        # Intelligence freshness: exponential decay e^(-lambda * days)
        age_days = float(context.get("intelligence_age_days", 1.0))
        v_fresh = float(math.exp(-0.05 * age_days))  # fresh ~ 1.0, 30 days ~ 0.22

        weights = self.w["threat_intelligence_match"]
        return [
            SubIndicatorValue(
                name="IOC Matching Confidence",
                raw_value=v_ioc,
                normalized_value=round(v_ioc, 3),
                weight=weights["ioc_confidence"],
                weighted_score=round(weights["ioc_confidence"] * v_ioc, 4),
            ),
            SubIndicatorValue(
                name="Vulnerability Existence",
                raw_value=vuln_raw,
                normalized_value=v_vuln,
                weight=weights["vulnerability_existence"],
                weighted_score=round(weights["vulnerability_existence"] * v_vuln, 4),
            ),
            SubIndicatorValue(
                name="APT Association",
                raw_value=apt_raw or "None",
                normalized_value=round(v_apt, 3),
                weight=weights["apt_association"],
                weighted_score=round(weights["apt_association"] * v_apt, 4),
            ),
            SubIndicatorValue(
                name="Intelligence Freshness",
                raw_value=f"{age_days:.1f} days",
                normalized_value=round(v_fresh, 3),
                weight=weights["intelligence_freshness"],
                weighted_score=round(weights["intelligence_freshness"] * v_fresh, 4),
            ),
        ]

    def normalize_attack_feasibility(self, context: Dict[str, Any]) -> List[SubIndicatorValue]:
        # Vulnerability exploitability: Public exploit=1.0, vulnerability only=0.7, none=0.3
        exploit_raw = str(context.get("vulnerability_exploitability", "none")).lower()
        if "public" in exploit_raw or exploit_raw == "1.0":
            v_exploit = 1.0
        elif "vuln" in exploit_raw or exploit_raw == "0.7":
            v_exploit = 0.7
        else:
            v_exploit = 0.3

        # Path reachability: Direct=1.0, hop=0.8, isolated=0.1
        reach_raw = str(context.get("path_reachability", "direct")).lower()
        if "direct" in reach_raw:
            v_reach = 1.0
        elif "hop" in reach_raw:
            v_reach = 0.8
        else:
            v_reach = 0.1

        # Protection bypass: Evasion evidence=1.0, none=0.8
        evasion_raw = str(context.get("protection_bypass", "none")).lower()
        v_bypass = 1.0 if ("evasion" in evasion_raw or evasion_raw == "1.0") else 0.8

        weights = self.w["attack_feasibility"]
        return [
            SubIndicatorValue(
                name="Vulnerability Exploitability",
                raw_value=exploit_raw,
                normalized_value=v_exploit,
                weight=weights["vulnerability_exploitability"],
                weighted_score=round(weights["vulnerability_exploitability"] * v_exploit, 4),
            ),
            SubIndicatorValue(
                name="Path Reachability",
                raw_value=reach_raw,
                normalized_value=v_reach,
                weight=weights["path_reachability"],
                weighted_score=round(weights["path_reachability"] * v_reach, 4),
            ),
            SubIndicatorValue(
                name="Protection Bypass",
                raw_value=evasion_raw,
                normalized_value=v_bypass,
                weight=weights["protection_bypass"],
                weighted_score=round(weights["protection_bypass"] * v_bypass, 4),
            ),
        ]

    def normalize_attack_persistence(self, context: Dict[str, Any]) -> List[SubIndicatorValue]:
        # Homogeneous alert correlation: 0.5 + 0.1 * count, capped at 1.0
        count = int(context.get("homogeneous_count", 1))
        v_corr = min(1.0, 0.5 + (0.1 * count))

        # Kill-chain progression evidence: Progression evidence=1.0, none=0.5
        prog_raw = context.get("kill_chain_progression", False)
        v_prog = 1.0 if prog_raw else 0.5

        # Lateral movement potential: Jump server/key segment=1.0, endpoint=0.7
        lat_raw = str(context.get("lateral_movement_potential", "endpoint")).lower()
        v_lat = 1.0 if ("jump" in lat_raw or "server" in lat_raw or "key" in lat_raw) else 0.7

        weights = self.w["attack_persistence"]
        return [
            SubIndicatorValue(
                name="Homogeneous Alert Correlation",
                raw_value=count,
                normalized_value=round(v_corr, 3),
                weight=weights["homogeneous_correlation"],
                weighted_score=round(weights["homogeneous_correlation"] * v_corr, 4),
            ),
            SubIndicatorValue(
                name="Kill-chain Progression Evidence",
                raw_value="Evidence present" if prog_raw else "None",
                normalized_value=v_prog,
                weight=weights["kill_chain_progression"],
                weighted_score=round(weights["kill_chain_progression"] * v_prog, 4),
            ),
            SubIndicatorValue(
                name="Lateral Movement Potential",
                raw_value=lat_raw,
                normalized_value=v_lat,
                weight=weights["lateral_movement_potential"],
                weighted_score=round(weights["lateral_movement_potential"] * v_lat, 4),
            ),
        ]

    def normalize_environmental_situation(self, context: Dict[str, Any]) -> Tuple[List[SubIndicatorValue], float, float]:
        # Multipliers from Paper Table 4:
        # External: Industry campaign = 1.2, normal = 1.0
        ext_raw = str(context.get("external_threat_posture", "normal")).lower()
        e_ext = 1.2 if "campaign" in ext_raw else 1.0

        # Internal: Network-wide anomaly = 1.1, normal = 1.0
        int_raw = str(context.get("internal_security_status", "normal")).lower()
        e_int = 1.1 if "anomaly" in int_raw else 1.0

        # Sub-indicator normalized representation
        v_ext_sub = 1.0 if e_ext > 1.0 else 0.5
        v_int_sub = 1.0 if e_int > 1.0 else 0.5

        weights = self.w["environmental_situation"]
        subs = [
            SubIndicatorValue(
                name="External Threat Posture",
                raw_value=ext_raw,
                normalized_value=v_ext_sub,
                weight=weights["external_threat_posture"],
                weighted_score=round(weights["external_threat_posture"] * v_ext_sub, 4),
            ),
            SubIndicatorValue(
                name="Internal Security Status",
                raw_value=int_raw,
                normalized_value=v_int_sub,
                weight=weights["internal_security_status"],
                weighted_score=round(weights["internal_security_status"] * v_int_sub, 4),
            ),
        ]
        return subs, e_ext, e_int

    def calculate_risk(
        self,
        alert_data: Dict[str, Any],
        context: Dict[str, Any],
    ) -> AHPScoringResult:
        """
        Executes Equations (8), (9), (10):
        C_i = sum_j (w_ij * v_ij)
        R_b = 100 * sum_i (W_i * C_i)
        R = min(100, R_b * E_ext * E_int)
        """
        alert_type = str(alert_data.get("alert_type", ""))

        # 1. Target Criticality
        tc_subs = self.normalize_target_criticality(context)
        c_tc = sum(s.weighted_score for s in tc_subs)

        # 2. Attack-Stage Hazard
        as_subs = self.normalize_attack_stage(context, alert_type)
        c_as = sum(s.weighted_score for s in as_subs)

        # 3. Threat Intelligence Match
        ti_subs = self.normalize_threat_intel(context)
        c_ti = sum(s.weighted_score for s in ti_subs)

        # 4. Attack Feasibility
        af_subs = self.normalize_attack_feasibility(context)
        c_af = sum(s.weighted_score for s in af_subs)

        # 5. Attack Persistence
        ap_subs = self.normalize_attack_persistence(context)
        c_ap = sum(s.weighted_score for s in ap_subs)

        # 6. Environmental Situation
        env_subs, e_ext, e_int = self.normalize_environmental_situation(context)
        c_env = sum(s.weighted_score for s in env_subs)

        criteria_list = [
            CriterionScore(
                criterion_name="Attack Target Criticality",
                criterion_weight=self.W["target_criticality"],
                score=round(c_tc, 4),
                sub_indicators=tc_subs,
            ),
            CriterionScore(
                criterion_name="Attack-Stage Hazard",
                criterion_weight=self.W["attack_stage_hazard"],
                score=round(c_as, 4),
                sub_indicators=as_subs,
            ),
            CriterionScore(
                criterion_name="Threat Intelligence Match",
                criterion_weight=self.W["threat_intelligence_match"],
                score=round(c_ti, 4),
                sub_indicators=ti_subs,
            ),
            CriterionScore(
                criterion_name="Attack Feasibility",
                criterion_weight=self.W["attack_feasibility"],
                score=round(c_af, 4),
                sub_indicators=af_subs,
            ),
            CriterionScore(
                criterion_name="Attack Persistence",
                criterion_weight=self.W["attack_persistence"],
                score=round(c_ap, 4),
                sub_indicators=ap_subs,
            ),
            CriterionScore(
                criterion_name="Environmental Situation",
                criterion_weight=self.W["environmental_situation"],
                score=round(c_env, 4),
                sub_indicators=env_subs,
            ),
        ]

        # Eq (9): R_b = 100 * sum_i (W_i * C_i)
        r_base = 100.0 * sum(c.criterion_weight * c.score for c in criteria_list)

        # Eq (10): R = min(100, R_b * E_ext * E_int)
        r_final = min(100.0, r_base * e_ext * e_int)

        # Priority Level:
        # High Risk: 80 <= R <= 100
        # Medium Risk: 60 <= R < 80
        # Low Risk: 0 <= R < 60
        if r_final >= 80.0:
            level = RiskLevel.HIGH
        elif r_final >= 60.0:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        notes = (
            f"AHP Consistency Ratio CR=0.041 < 0.10. "
            f"Base Score R_b={r_base:.2f}, Multipliers: Ext={e_ext}, Int={e_int}. "
            f"Final Risk={r_final:.2f} ({level.value.upper()})."
        )

        return AHPScoringResult(
            base_risk_score=round(r_base, 2),
            ext_environment_multiplier=e_ext,
            int_environment_multiplier=e_int,
            final_risk_score=round(r_final, 2),
            risk_level=level,
            criteria_breakdown=criteria_list,
            scoring_version="AHP-2026-v1.0",
            formula_notes=notes,
        )
