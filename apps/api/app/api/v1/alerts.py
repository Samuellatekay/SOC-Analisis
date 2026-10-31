"""
Alerts REST API Endpoints.
Provides querying, filtering, detailed scoring breakdown, and ingestion simulation.
"""

from typing import List, Optional, Union, Dict, Any
from fastapi import APIRouter, HTTPException, Query, Body
from pydantic import BaseModel

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[4]))

from packages.contracts.models import EnrichedAlert, RawAlertInput, RiskLevel, SeverityLevel
from apps.api.app.db.storage import storage
from services.engine.adapters.wazuh_adapter import WazuhAdapter

router = APIRouter()
wazuh_adapter = WazuhAdapter()


class AlertSimulationRequest(BaseModel):
    raw_alert: RawAlertInput
    context: Optional[dict] = None


@router.get("", response_model=List[EnrichedAlert])
def list_alerts(
    risk_level: Optional[RiskLevel] = None,
    severity: Optional[SeverityLevel] = None,
    source: Optional[str] = None,
    search: Optional[str] = None,
    include_noise: bool = False,
    limit: int = 50,
    offset: int = 0,
):
    """
    List alerts with flexible filters, sorted by risk_score descending.
    """
    alerts = list(storage.alerts.values())

    # Filter out noise unless requested
    if not include_noise:
        alerts = [a for a in alerts if not a.filtered_as_noise]

    if risk_level:
        alerts = [a for a in alerts if a.risk_level == risk_level]

    if severity:
        alerts = [a for a in alerts if a.severity == severity]

    if source:
        alerts = [a for a in alerts if source.lower() in a.source.lower()]

    if search:
        s = search.lower()
        alerts = [
            a for a in alerts
            if (s in a.src_ip or s in a.dst_ip or s in a.alert_type.lower() or s in a.event_id)
        ]

    # Sort: highest risk score first, then newest
    alerts.sort(key=lambda x: (x.risk_score, x.event_time), reverse=True)

    return alerts[offset : offset + limit]


@router.get("/{event_id}", response_model=EnrichedAlert)
def get_alert_detail(event_id: str):
    """
    Get full alert detail, including AHP 17 sub-indicator breakdown,
    FFT-PCC status, Multi-Agent evidence outputs, and RAG explanation.
    """
    alert = storage.alerts.get(event_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert with ID {event_id} not found.")
    return alert


@router.post("/simulate", response_model=EnrichedAlert)
def simulate_ingest_alert(payload: AlertSimulationRequest):
    """
    Simulates live ingestion of an alert through the complete pipeline:
    Normalization -> FFT-PCC -> Risk Gate -> Multi-Agent -> Semantic Integrity -> AHP Scoring -> RAG.
    """
    enriched = storage.engine.process_alert(payload.raw_alert, payload.context or {})
    storage.alerts[enriched.event_id] = enriched
    return enriched


@router.post("/ingest/wazuh", response_model=List[EnrichedAlert])
def ingest_wazuh_alerts(payload: Union[Dict[str, Any], List[Dict[str, Any]]] = Body(...)):
    """
    Direct ingestion webhook for Wazuh Manager alerts (/var/ossec/logs/alerts/alerts.json).
    Accepts a single alert object or a batch list of alerts.
    """
    raw_items = payload if isinstance(payload, list) else [payload]
    results: List[EnrichedAlert] = []

    for item in raw_items:
        raw_alert, context = wazuh_adapter.parse_alert(item)
        enriched = storage.engine.process_alert(raw_alert, context)
        storage.alerts[enriched.event_id] = enriched
        results.append(enriched)

    return results
