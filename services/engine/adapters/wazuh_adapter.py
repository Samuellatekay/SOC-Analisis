"""
Wazuh Log Ingestion Adapter.
Parses native Wazuh alert records (from /var/ossec/logs/alerts/alerts.json or Wazuh Integration webhook)
into canonical RawAlertInput and context for the SOC Analisis Engine pipeline.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional
import re

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[4]))

from packages.contracts.models import RawAlertInput, SeverityLevel


class WazuhAdapter:
    @staticmethod
    def map_wazuh_level_to_severity(level: int) -> SeverityLevel:
        """
        Maps Wazuh alert rule level (0-16) to standardized SOC severity:
        - 12-16: Critical
        - 8-11:  High
        - 4-7:   Medium
        - 0-3:   Low
        """
        if level >= 12:
            return SeverityLevel.CRITICAL
        elif level >= 8:
            return SeverityLevel.HIGH
        elif level >= 4:
            return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

    def parse_alert(self, wazuh_payload: Dict[str, Any]) -> Tuple[RawAlertInput, Dict[str, Any]]:
        """
        Parses a native Wazuh alert JSON dict.
        Returns (RawAlertInput, context_dict).
        """
        # 1. Timestamp extraction
        ts_raw = wazuh_payload.get("timestamp")
        parsed_ts = datetime.now(timezone.utc)
        if ts_raw:
            try:
                # Handle formats like 2026-10-31T05:12:30.123+0000 or ISO format
                clean_ts = ts_raw.replace("+0000", "+00:00")
                parsed_ts = datetime.fromisoformat(clean_ts)
            except Exception:
                pass

        # 2. Rule & Severity
        rule = wazuh_payload.get("rule", {})
        rule_level = int(rule.get("level", 5))
        severity = self.map_wazuh_level_to_severity(rule_level)
        rule_desc = rule.get("description", "Wazuh Security Alert")
        rule_id = str(rule.get("id", "0000"))

        # 3. Agent Info
        agent = wazuh_payload.get("agent", {})
        agent_name = agent.get("name", "wazuh-agent")
        agent_ip = agent.get("ip", "127.0.0.1")

        # 4. Network Data Extraction (srcip, dstip, dstport, protocol)
        data = wazuh_payload.get("data", {})
        src_ip = (
            data.get("srcip")
            or data.get("src_ip")
            or wazuh_payload.get("srcip")
            or "0.0.0.0"
        )
        dst_ip = (
            data.get("dstip")
            or data.get("dst_ip")
            or agent_ip
            or "127.0.0.1"
        )

        # In case IP was inside full_log
        full_log = wazuh_payload.get("full_log", "")
        if src_ip == "0.0.0.0" and full_log:
            ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", full_log)
            if ip_matches:
                src_ip = ip_matches[0]

        try:
            dst_port = int(data.get("dstport") or data.get("dst_port") or 80)
        except (ValueError, TypeError):
            dst_port = 80

        protocol = (data.get("protocol") or data.get("proto") or "TCP").upper()

        # 5. Extract MITRE ATT&CK info from Wazuh rule
        mitre = rule.get("mitre", {})
        mitre_ids = mitre.get("id", [])
        mitre_tactics = mitre.get("tactic", [])
        primary_tactic = mitre_tactics[0] if mitre_tactics else ""
        primary_technique_id = mitre_ids[0] if mitre_ids else ""

        # Map MITRE tactic to attack_stage for AHP
        tactic_clean = primary_tactic.lower().replace(" ", "_")

        raw_alert = RawAlertInput(
            timestamp=parsed_ts,
            source=f"Wazuh ({agent_name})",
            source_event_id=str(wazuh_payload.get("id", f"WAZ-{rule_id}-{parsed_ts.timestamp()}")),
            tenant_id="tenant-default",
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            alert_type=rule_desc,
            severity=severity,
            raw_message=full_log or rule_desc,
            metadata={
                "wazuh_rule_id": rule_id,
                "wazuh_rule_level": rule_level,
                "wazuh_agent_id": agent.get("id"),
                "wazuh_agent_name": agent_name,
                "mitre_technique_id": primary_technique_id,
            },
        )

        # Context for AHP & Risk Gate
        context = {
            "attack_stage": tactic_clean or "reconnaissance",
            "ioc_match": rule_level >= 10,
            "asset_business_value": "core" if "srv" in agent_name.lower() or "dc" in agent_name.lower() else "support",
            "attack_surface_exposure": "internal" if dst_ip.startswith("10.") or dst_ip.startswith("192.168.") else "internet",
            "vulnerability_exploitability": "public_exploit" if rule_level >= 12 else "none",
        }

        return raw_alert, context
