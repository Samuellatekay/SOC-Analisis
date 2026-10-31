"""
Unit tests for Conservative Risk Gate.
Verifies that periodic alerts bearing high-risk evidence are never erroneously filtered.
"""

import unittest
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from services.engine.pipeline import SOCAnalisisEngine
from packages.contracts.models import RawAlertInput, SeverityLevel


class TestRiskGate(unittest.TestCase):
    def test_conservative_risk_gate_protects_periodic_high_risk(self):
        """
        Scenario: A periodic brute force happens periodically every 24h,
        normally FFT-PCC would flag it as noise, BUT it has a confirmed IOC match or exploit.
        The Conservative Risk Gate MUST retain it!
        """
        engine = SOCAnalisisEngine()

        # Pre-seed 72-hour periodic pattern into normalizer store
        triplet_key = engine.normalizer.construct_triplet_key("203.0.113.45", "192.168.10.10", "ssh_brute_force")
        
        # 24h periodic pattern: pulse every 24 hours
        periodic_counts = [25.0 if (h % 24 == 0) else 1.0 for h in range(72)]
        engine.normalizer.set_triplet_history(
            triplet_key,
            periodic_counts,
            src_ip="203.0.113.45",
            dst_ip="192.168.10.10",
            alert_type="ssh_brute_force",
        )

        alert_input = RawAlertInput(
            src_ip="203.0.113.45",
            dst_ip="192.168.10.10",
            dst_port=22,
            protocol="TCP",
            alert_type="ssh_brute_force",
            severity=SeverityLevel.HIGH,
            raw_message="SSH login failure burst from known malicious IP",
        )

        # Context with confirmed IOC match, core asset, and industry campaign
        context = {
            "ioc_match": True,
            "asset_business_value": "core",
            "attack_surface_exposure": "internet",
            "cve_id": "CVE-2024-6387",
            "vulnerability_exploitability": "public_exploit",
            "external_threat_posture": "industry campaign",  # 1.2
            "internal_security_status": "network-wide anomaly", # 1.1
        }

        result = engine.process_alert_sync(alert_input, context)

        # Assert that despite periodicity, it was NOT filtered!
        self.assertTrue(result.fft_result.is_periodic_candidate)
        self.assertTrue(result.risk_gate.has_high_risk_evidence)
        self.assertFalse(result.filtered_as_noise)
        self.assertGreaterEqual(result.risk_score, 80.0)


if __name__ == "__main__":
    unittest.main()
