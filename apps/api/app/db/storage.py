"""
In-memory and transactional repository for SOC alerts, cases, and knowledge graph.
Pre-seeds realistic SOC scenarios from Guo et al. (2026).
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
import uuid

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[4]))

from packages.contracts.models import (
    EnrichedAlert,
    Case,
    CaseStatus,
    CaseNote,
    CaseAuditEntry,
    SeverityLevel,
    RiskLevel,
    RawAlertInput,
)
from services.engine.pipeline import SOCAnalisisEngine


class SOCStorage:
    def __init__(self):
        self.engine = SOCAnalisisEngine()
        self.alerts: Dict[str, EnrichedAlert] = {}
        self.cases: Dict[str, Case] = {}
        self.graph_nodes: List[Dict[str, Any]] = []
        self.graph_edges: List[Dict[str, Any]] = []
        
        # Initialize default seed data
        self.seed_initial_data()

    def seed_initial_data(self):
        """Seeds realistic alerts representing scenarios from paper evaluation."""
        now = datetime.now(timezone.utc)

        # 1. SCENARIO A: High-Risk Periodic SSH Brute Force Protected by Conservative Risk Gate
        # Triplet: 203.0.113.45 -> 192.168.10.10:ssh_brute_force
        triplet_key = self.engine.normalizer.construct_triplet_key(
            "203.0.113.45", "192.168.10.10", "SSH Brute-force Attempt"
        )
        periodic_counts = [25.0 if (h % 24 == 0) else 1.0 for h in range(72)]
        self.engine.normalizer.set_triplet_history(
            triplet_key,
            periodic_counts,
            src_ip="203.0.113.45",
            dst_ip="192.168.10.10",
            alert_type="SSH Brute-force Attempt",
        )

        alert_1 = self.engine.process_alert(
            RawAlertInput(
                timestamp=now - timedelta(minutes=15),
                source="Wazuh HIDS",
                source_event_id="WAZ-882194",
                src_ip="203.0.113.45",
                dst_ip="192.168.10.10",
                dst_port=22,
                protocol="TCP",
                alert_type="SSH Brute-force Attempt",
                severity=SeverityLevel.HIGH,
                raw_message="sshd[4045]: Failed password for root from 203.0.113.45 port 54822 ssh2 (count: 465)",
            ),
            context={
                "ioc_match": True,
                "asset_business_value": "core",
                "attack_surface_exposure": "internet",
                "cve_id": "CVE-2024-6387",
                "vulnerability_exploitability": "public_exploit",
                "external_threat_posture": "industry campaign",
                "internal_security_status": "network-wide anomaly",
                "homogeneous_count": 4,
                "kill_chain_progression": True,
                "lateral_movement_potential": "jump server",
            },
        )
        self.alerts[alert_1.event_id] = alert_1

        # 2. SCENARIO B: Critical Ransomware Impact on Primary Domain Controller
        alert_2 = self.engine.process_alert(
            RawAlertInput(
                timestamp=now - timedelta(minutes=42),
                source="CrowdStrike Falcon",
                source_event_id="CS-E90214",
                src_ip="10.0.1.15",
                dst_ip="10.0.1.5",
                dst_port=445,
                protocol="TCP",
                alert_type="Ransomware Data Encryption Activity",
                severity=SeverityLevel.CRITICAL,
                raw_message="Process vssadmin.exe attempted shadowcopy deletion followed by mass file rename .locked",
            ),
            context={
                "ioc_match": True,
                "asset_business_value": "core",
                "data_sensitivity": "top secret",
                "attack_surface_exposure": "internal",
                "attack_stage": "impact",
                "stage_policy_weight": 1.0,
                "vulnerability_existence": "existing",
                "apt_group": "LockBit 3.0",
                "vulnerability_exploitability": "public_exploit",
                "path_reachability": "direct",
                "protection_bypass": "evasion",
                "homogeneous_count": 6,
                "kill_chain_progression": True,
                "lateral_movement_potential": "key segment",
                "external_threat_posture": "industry campaign",
                "internal_security_status": "network-wide anomaly",
            },
        )
        self.alerts[alert_2.event_id] = alert_2

        # 3. SCENARIO C: Periodic Operational Noise Filtered by FFT-PCC (72% Noise Reduction branch)
        triplet_noise = self.engine.normalizer.construct_triplet_key(
            "10.0.5.20", "10.0.1.200", "Zabbix Health Check Probe"
        )
        noise_series = [15.0 if (h % 2 == 0) else 14.0 for h in range(72)]
        self.engine.normalizer.set_triplet_history(
            triplet_noise,
            noise_series,
            src_ip="10.0.5.20",
            dst_ip="10.0.1.200",
            alert_type="Zabbix Health Check Probe",
        )

        alert_3 = self.engine.process_alert(
            RawAlertInput(
                timestamp=now - timedelta(hours=2),
                source="Suricata NIDS",
                source_event_id="SUR-102941",
                src_ip="10.0.5.20",
                dst_ip="10.0.1.200",
                dst_port=10050,
                protocol="TCP",
                alert_type="Zabbix Health Check Probe",
                severity=SeverityLevel.LOW,
                raw_message="ET INFO Routine internal monitoring probe connection established",
            ),
            context={
                "ioc_match": False,
                "asset_business_value": "test",
                "attack_surface_exposure": "isolated",
                "vulnerability_exploitability": "none",
            },
        )
        self.alerts[alert_3.event_id] = alert_3

        # 4. SCENARIO D: OWASP SQL Injection Web Attack on DMZ Web Application
        alert_4 = self.engine.process_alert(
            RawAlertInput(
                timestamp=now - timedelta(hours=3),
                source="Cloudflare WAF",
                source_event_id="CF-9921045",
                src_ip="198.51.100.88",
                dst_ip="172.16.0.10",
                dst_port=443,
                protocol="TCP",
                alert_type="SQL Injection Authentication Bypass",
                severity=SeverityLevel.HIGH,
                raw_message="POST /api/login HTTP/1.1 payload ' UNION SELECT NULL, username, password FROM users--",
            ),
            context={
                "ioc_match": False,
                "asset_business_value": "core",
                "data_sensitivity": "confidential",
                "attack_surface_exposure": "dmz",
                "attack_stage": "initial_access",
                "stage_policy_weight": 0.8,
                "vulnerability_existence": "existing",
                "cve_id": "CVE-2023-46604",
                "vulnerability_exploitability": "public_exploit",
                "path_reachability": "direct",
                "protection_bypass": "evasion",
                "homogeneous_count": 3,
                "kill_chain_progression": False,
                "lateral_movement_potential": "endpoint",
            },
        )
        self.alerts[alert_4.event_id] = alert_4

        # 5. SCENARIO E: C2 Beaconing / Malware Communication
        alert_5 = self.engine.process_alert(
            RawAlertInput(
                timestamp=now - timedelta(hours=5),
                source="Microsoft Sentinel",
                source_event_id="SEN-55102",
                src_ip="10.0.3.44",
                dst_ip="185.220.101.5",
                dst_port=8443,
                protocol="TCP",
                alert_type="Suspected Cobalt Strike DNS/HTTPS Beaconing",
                severity=SeverityLevel.CRITICAL,
                raw_message="Periodic TLS connection with high entropy jitter matching Cobalt Strike malleable C2 profile",
            ),
            context={
                "ioc_match": True,
                "asset_business_value": "support",
                "data_sensitivity": "internal",
                "attack_surface_exposure": "internal",
                "attack_stage": "command_and_control",
                "stage_policy_weight": 0.9,
                "apt_group": "APT28",
                "vulnerability_exploitability": "none",
                "path_reachability": "hop",
                "protection_bypass": "evasion",
                "homogeneous_count": 8,
                "kill_chain_progression": True,
                "lateral_movement_potential": "jump server",
            },
        )
        self.alerts[alert_5.event_id] = alert_5

        # Seed initial Case linked to alert_1 and alert_2
        case_1 = Case(
            case_id="CASE-202610-001",
            title="Coordinated Credential Access & Lateral Progression on DC",
            description="High-priority incident linking perimeter SSH brute-force to ransomware staging on Domain Controller 10.0.1.5.",
            status=CaseStatus.INVESTIGATING,
            severity=SeverityLevel.CRITICAL,
            priority=RiskLevel.HIGH,
            assigned_to="Senior Analyst (SOC Tier 3)",
            linked_alert_ids=[alert_1.event_id, alert_2.event_id],
            tags=["Ransomware", "Brute-force", "LockBit", "Critical-DC"],
            notes=[
                CaseNote(
                    author="Senior Analyst",
                    content="Firewall drop rule deployed for source 203.0.113.45. EDR isolation token sent to DC 10.0.1.5.",
                ),
            ],
            audit_trail=[
                CaseAuditEntry(
                    actor="System Automation",
                    action="CASE_CREATED",
                    detail=f"Auto-promoted from High-Risk alerts {alert_1.event_id[:8]} and {alert_2.event_id[:8]}.",
                ),
                CaseAuditEntry(
                    actor="Senior Analyst",
                    action="STATUS_CHANGE",
                    detail="Status transitioned from Triage to Investigating.",
                ),
            ],
        )
        self.cases[case_1.case_id] = case_1
        alert_1.linked_case_id = case_1.case_id
        alert_2.linked_case_id = case_1.case_id

        # Seed comprehensive Knowledge Graph topology for visual viewer
        self.graph_nodes = [
            # 1. Assets
            {"id": "A-DC01", "label": "Domain Controller (10.0.1.5)", "type": "asset", "criticality": "core", "val": 25},
            {"id": "A-WEB01", "label": "DMZ Web Server (172.16.0.10)", "type": "asset", "criticality": "core", "val": 20},
            {"id": "A-DB01", "label": "Finance Database (192.168.10.10)", "type": "asset", "criticality": "core", "val": 22},
            {"id": "A-K8S01", "label": "K8s Ingress Gateway (172.16.0.2)", "type": "asset", "criticality": "core", "val": 20},
            {"id": "A-WS104", "label": "Finance Workstation (10.0.2.45)", "type": "asset", "criticality": "support", "val": 16},
            {"id": "A-FW01", "label": "Edge Firewall (10.0.0.1)", "type": "asset", "criticality": "core", "val": 24},

            # 2. MITRE ATT&CK Techniques
            {"id": "T1110", "label": "T1110.001 Password Guessing", "type": "technique", "tactic": "Credential Access", "val": 18},
            {"id": "T1486", "label": "T1486 Data Encrypted for Impact", "type": "technique", "tactic": "Impact", "val": 22},
            {"id": "T1190", "label": "T1190 Exploit Public App", "type": "technique", "tactic": "Initial Access", "val": 18},
            {"id": "T1071", "label": "T1071 C2 Web Protocols", "type": "technique", "tactic": "Command & Control", "val": 19},
            {"id": "T1059", "label": "T1059.001 PowerShell Scripting", "type": "technique", "tactic": "Execution", "val": 17},
            {"id": "T1021", "label": "T1021.002 SMB Admin Shares", "type": "technique", "tactic": "Lateral Movement", "val": 20},
            {"id": "T1046", "label": "T1046 Network Service Scan", "type": "technique", "tactic": "Discovery", "val": 16},

            # 3. Known Vulnerabilities (CVE)
            {"id": "CVE-2024-6387", "label": "CVE-2024-6387 (regreSSHion)", "type": "vulnerability", "cvss": 9.8, "val": 18},
            {"id": "CVE-2023-46604", "label": "CVE-2023-46604 (ActiveMQ RCE)", "type": "vulnerability", "cvss": 9.8, "val": 17},
            {"id": "CVE-2024-38077", "label": "CVE-2024-38077 (MadLicense RCE)", "type": "vulnerability", "cvss": 9.8, "val": 19},
            {"id": "CVE-2024-21413", "label": "CVE-2024-21413 (Outlook Moniker)", "type": "vulnerability", "cvss": 9.8, "val": 16},

            # 4. Threat Actors (APT)
            {"id": "APT28", "label": "APT28 (Fancy Bear)", "type": "apt", "origin": "State-sponsored", "val": 21},
            {"id": "LockBit", "label": "LockBit 3.0 Syndicate", "type": "apt", "origin": "Ransomware-as-a-Service", "val": 22},
            {"id": "Lazarus", "label": "Lazarus Group (Hidden Cobra)", "type": "apt", "origin": "Nation-State Cybercrime", "val": 21},

            # 5. Indicators of Compromise (IOC)
            {"id": "IOC-1", "label": "203.0.113.45 (C2 IP)", "type": "ioc", "ioc_type": "IPv4", "val": 14},
            {"id": "IOC-2", "label": "185.220.101.5 (Tor Exit)", "type": "ioc", "ioc_type": "IPv4", "val": 14},
            {"id": "IOC-3", "label": "evil-c2-update.xyz (DGA Domain)", "type": "ioc", "ioc_type": "Domain", "val": 15},
            {"id": "IOC-4", "label": "7b8e19c0a... (LockBit Payload)", "type": "ioc", "ioc_type": "SHA256", "val": 15},
        ]

        self.graph_edges = [
            # Asset - Vulnerability
            {"source": "A-DB01", "target": "CVE-2024-6387", "label": "VULNERABLE_TO"},
            {"source": "A-WEB01", "target": "CVE-2023-46604", "label": "VULNERABLE_TO"},
            {"source": "A-DC01", "target": "CVE-2024-38077", "label": "VULNERABLE_TO"},
            {"source": "A-WS104", "target": "CVE-2024-21413", "label": "VULNERABLE_TO"},

            # Threat Actors - Techniques
            {"source": "LockBit", "target": "T1486", "label": "USES_TECHNIQUE"},
            {"source": "LockBit", "target": "T1059", "label": "USES_TECHNIQUE"},
            {"source": "LockBit", "target": "T1021", "label": "USES_TECHNIQUE"},
            {"source": "APT28", "target": "T1071", "label": "USES_TECHNIQUE"},
            {"source": "APT28", "target": "T1190", "label": "USES_TECHNIQUE"},
            {"source": "Lazarus", "target": "T1110", "label": "USES_TECHNIQUE"},
            {"source": "Lazarus", "target": "T1046", "label": "USES_TECHNIQUE"},

            # Threat Actors - IOCs
            {"source": "IOC-1", "target": "LockBit", "label": "INFRASTRUCTURE_OF"},
            {"source": "IOC-2", "target": "APT28", "label": "ROUTED_THROUGH"},
            {"source": "IOC-3", "target": "APT28", "label": "DOMAIN_OWNED_BY"},
            {"source": "IOC-4", "target": "LockBit", "label": "PAYLOAD_OF"},

            # Attacks - Target Assets
            {"source": "IOC-1", "target": "A-DB01", "label": "ATTACKED"},
            {"source": "T1110", "target": "A-DB01", "label": "TARGETED"},
            {"source": "T1190", "target": "A-WEB01", "label": "EXPLOITED"},
            {"source": "T1486", "target": "A-DC01", "label": "IMPACTED"},
            {"source": "T1021", "target": "A-DC01", "label": "LATERAL_PROGRESSION"},
            {"source": "T1059", "target": "A-WS104", "label": "EXECUTED_ON"},
            {"source": "A-FW01", "target": "A-K8S01", "label": "ROUTES_TRAFFIC"},
            {"source": "A-K8S01", "target": "A-WEB01", "label": "LOAD_BALANCES"},
        ]


# Global singleton instance
storage = SOCStorage()
