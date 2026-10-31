"""
Ingress & Schema Normalizer.
Converts heterogeneous SIEM/EDR logs into normalized alerts and triplet time-series.
"""

from datetime import datetime, timezone
import hashlib
from typing import Dict, List, Optional
import uuid

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[2]))

from packages.contracts.models import RawAlertInput, SeverityLevel, AlertTriplet


class AlertNormalizer:
    def __init__(self):
        # In-memory storage for hourly time-series per triplet
        # Key: triplet_key, Value: dict containing counts per hour
        self.triplet_store: Dict[str, AlertTriplet] = {}

    @staticmethod
    def construct_triplet_key(src_ip: str, dst_ip: str, alert_type: str) -> str:
        """
        Paper formula Eq (2): g(a_i) = (src_i, dst_i, type_i)
        """
        clean_src = src_ip.strip()
        clean_dst = dst_ip.strip()
        clean_type = alert_type.strip().lower().replace(" ", "_")
        return f"{clean_src}->{clean_dst}:{clean_type}"

    def normalize(self, raw: RawAlertInput) -> Dict:
        """
        Maps raw input fields to canonical schema, assigns unique event_id,
        and aggregates into triplet time series.
        """
        event_id = str(uuid.uuid4())
        triplet_key = self.construct_triplet_key(raw.src_ip, raw.dst_ip, raw.alert_type)
        
        event_time = raw.timestamp if raw.timestamp else datetime.now(timezone.utc)
        received_at = datetime.now(timezone.utc)

        # Update triplet hourly bucket
        self.record_triplet_event(triplet_key, raw.src_ip, raw.dst_ip, raw.alert_type)

        return {
            "event_id": event_id,
            "source_event_id": raw.source_event_id or f"SRC-{hashlib.md5(f'{event_id}'.encode()).hexdigest()[:8]}",
            "tenant_id": raw.tenant_id,
            "source": raw.source,
            "received_at": received_at,
            "event_time": event_time,
            "src_ip": raw.src_ip,
            "dst_ip": raw.dst_ip,
            "dst_port": raw.dst_port or 80,
            "protocol": raw.protocol.upper(),
            "alert_type": raw.alert_type,
            "severity": raw.severity,
            "raw_message": raw.raw_message or f"Security alert {raw.alert_type} detected from {raw.src_ip}",
            "triplet_key": triplet_key,
            "metadata": raw.metadata,
        }

    def record_triplet_event(self, triplet_key: str, src_ip: str, dst_ip: str, alert_type: str):
        if triplet_key not in self.triplet_store:
            # Initialize with default hourly series (e.g. 7-day 168 hours or 24 hours history)
            self.triplet_store[triplet_key] = AlertTriplet(
                triplet_key=triplet_key,
                src_ip=src_ip,
                dst_ip=dst_ip,
                alert_type=alert_type,
                hourly_counts=[0.0] * 72,
            )
        
        # Increment the latest hour count
        self.triplet_store[triplet_key].hourly_counts[-1] += 1.0

    def set_triplet_history(self, triplet_key: str, counts: List[float], src_ip: str = "", dst_ip: str = "", alert_type: str = ""):
        """
        Seed or update explicit historical hourly series for FFT analysis.
        """
        self.triplet_store[triplet_key] = AlertTriplet(
            triplet_key=triplet_key,
            src_ip=src_ip or "0.0.0.0",
            dst_ip=dst_ip or "0.0.0.0",
            alert_type=alert_type or "unknown",
            hourly_counts=counts,
        )

    def get_triplet(self, triplet_key: str) -> Optional[AlertTriplet]:
        return self.triplet_store.get(triplet_key)
