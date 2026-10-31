"""
Unit tests for AHP Dynamic Risk Scoring Engine.
Tests Equations (8), (9), (10) and Table 4 & 5 weights from Guo et al. (2026).
"""

import unittest
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from services.engine.ahp_scorer import AHPRiskEngine
from packages.contracts.models import RiskLevel


class TestAHPScorer(unittest.TestCase):
    def test_ahp_consistency_and_weights(self):
        engine = AHPRiskEngine()
        
        # Check that criterion weights sum to 1.0
        total_w = sum(engine.W.values())
        self.assertLess(abs(total_w - 1.0), 1e-4)

        # Check each sub-indicator weight sum to 1.0
        for crit, sub_weights in engine.w.items():
            self.assertLess(abs(sum(sub_weights.values()) - 1.0), 1e-4)

    def test_high_risk_attack_scenario(self):
        """Ransomware / Command and Control targeting Core server with known exploit."""
        engine = AHPRiskEngine()

        alert_data = {
            "alert_type": "Ransomware Data Encryption",
            "src_ip": "198.51.100.55",
            "dst_ip": "10.0.1.5",
        }
        context = {
            "asset_business_value": "core",           # v = 1.0
            "data_sensitivity": "top secret",          # v = 1.0
            "attack_surface_exposure": "internet",     # v = 1.0
            "attack_stage": "impact",                  # v = 1.0
            "stage_policy_weight": 1.0,                # v = 1.0
            "ioc_match": True,                         # v ~ 0.85
            "vulnerability_existence": "existing",     # v = 1.0
            "apt_group": "APT29",                      # v = 0.90
            "intelligence_age_days": 1.0,              # v ~ 0.95
            "vulnerability_exploitability": "public_exploit", # v = 1.0
            "path_reachability": "direct",             # v = 1.0
            "protection_bypass": "evasion",            # v = 1.0
            "homogeneous_count": 5,                    # v = 1.0
            "kill_chain_progression": True,            # v = 1.0
            "lateral_movement_potential": "jump server", # v = 1.0
            "external_threat_posture": "industry campaign", # E_ext = 1.2
            "internal_security_status": "network-wide anomaly", # E_int = 1.1
        }

        result = engine.calculate_risk(alert_data, context)
        self.assertEqual(result.risk_level, RiskLevel.HIGH)
        self.assertGreaterEqual(result.final_risk_score, 80.0)
        self.assertEqual(result.ext_environment_multiplier, 1.2)
        self.assertEqual(result.int_environment_multiplier, 1.1)

    def test_low_risk_benign_scenario(self):
        """Routine scan on isolated test machine with no vulnerability or IOC."""
        engine = AHPRiskEngine()

        alert_data = {
            "alert_type": "Ping Sweep Discovery",
            "src_ip": "192.168.1.100",
            "dst_ip": "192.168.1.200",
        }
        context = {
            "asset_business_value": "test",            # v = 0.2
            "data_sensitivity": "public",              # v = 0.25
            "attack_surface_exposure": "isolated",     # v = 0.2
            "attack_stage": "reconnaissance",          # v = 0.2
            "stage_policy_weight": 0.2,
            "ioc_match": False,                        # v ~ 0.1
            "vulnerability_existence": "none",         # v = 0.0
            "apt_group": None,                         # v = 0.0
            "intelligence_age_days": 60.0,             # v ~ 0.05
            "vulnerability_exploitability": "none",    # v = 0.3
            "path_reachability": "isolated",           # v = 0.1
            "protection_bypass": "none",               # v = 0.8
            "homogeneous_count": 1,                    # v = 0.6
            "kill_chain_progression": False,           # v = 0.5
            "lateral_movement_potential": "endpoint",  # v = 0.7
            "external_threat_posture": "normal",       # E_ext = 1.0
            "internal_security_status": "normal",      # E_int = 1.0
        }

        result = engine.calculate_risk(alert_data, context)
        self.assertEqual(result.risk_level, RiskLevel.LOW)
        self.assertLess(result.final_risk_score, 60.0)


if __name__ == "__main__":
    unittest.main()
