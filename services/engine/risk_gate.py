"""
Conservative Risk Gate.
Ensures that periodic but genuinely high-risk alerts are NEVER dropped as noise.
Based on Algorithm 1 (Steps 8 & 9) from Guo et al. (2026).
"""

from typing import Dict, Any, List

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))

from packages.contracts.models import RiskGateEvaluation


class ConservativeRiskGate:
    def __init__(self):
        # Known high-criticality keywords & stages
        self.high_risk_attack_stages = {
            "privilege_escalation",
            "lateral_movement",
            "command_and_control",
            "exfiltration",
            "impact",
            "credential_access",
            "ransomware",
        }

    def evaluate(self, alert_data: Dict[str, Any], context: Dict[str, Any]) -> RiskGateEvaluation:
        """
        Evaluates whether an alert contains high-risk evidence:
        1. Confirmed IOC in threat intelligence
        2. Known active exploit for vulnerability
        3. Core or DMZ asset criticality
        4. Advanced kill-chain attack stage
        5. APT association
        """
        reasons: List[str] = []
        ioc_matched = False
        exploitable_vuln = False
        high_criticality_asset = False
        kill_chain_advancement = False

        # 1. Threat Intelligence IOC Check
        ti_ioc = context.get("ioc_match", False)
        if ti_ioc or alert_data.get("metadata", {}).get("is_known_malicious_ip", False):
            ioc_matched = True
            reasons.append("Threat Intelligence: Confirmed malicious IOC match found.")

        # 2. Vulnerability Exploitability
        vuln_status = context.get("vulnerability_exploitability", "none")
        if vuln_status in ["public_exploit", "critical_cve", 1.0]:
            exploitable_vuln = True
            reasons.append(f"Vulnerability: Active or public exploit available ({vuln_status}).")

        # 3. Asset Criticality (Business value core or exposed surface DMZ/Internet)
        asset_val = context.get("asset_business_value", "support")
        attack_surface = context.get("attack_surface_exposure", "internal")
        if asset_val in ["core", 1.0] or attack_surface in ["internet", 1.0]:
            high_criticality_asset = True
            reasons.append(f"Asset: High criticality target detected (Value: {asset_val}, Exposure: {attack_surface}).")

        # 4. Kill-chain advancement / High-risk attack type
        alert_type = str(alert_data.get("alert_type", "")).lower().replace(" ", "_").replace("-", "_")
        for stage in self.high_risk_attack_stages:
            if stage in alert_type:
                kill_chain_advancement = True
                reasons.append(f"Attack Stage: Threat type reflects critical kill-chain phase ({stage}).")
                break

        # 5. APT Association
        apt_group = context.get("apt_group", None)
        if apt_group:
            ioc_matched = True
            reasons.append(f"Threat Intelligence: High confidence association with APT group '{apt_group}'.")

        has_high_risk = (
            ioc_matched
            or exploitable_vuln
            or high_criticality_asset
            or kill_chain_advancement
        )

        return RiskGateEvaluation(
            has_high_risk_evidence=has_high_risk,
            ioc_matched=ioc_matched,
            exploitable_vuln=exploitable_vuln,
            high_criticality_asset=high_criticality_asset,
            kill_chain_advancement=kill_chain_advancement,
            reasons=reasons,
        )
