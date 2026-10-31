"""
Case & Incident Management REST API Endpoints.
Workflow: New -> Triage -> Investigating -> Resolved -> Closed.
"""

from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[4]))

from packages.contracts.models import (
    Case,
    CaseStatus,
    CaseNote,
    CaseAuditEntry,
    SeverityLevel,
    RiskLevel,
)
from apps.api.app.db.storage import storage

router = APIRouter()


class CreateCaseRequest(BaseModel):
    title: str
    description: str
    severity: SeverityLevel = SeverityLevel.MEDIUM
    priority: RiskLevel = RiskLevel.MEDIUM
    assigned_to: Optional[str] = "Unassigned"
    linked_alert_ids: List[str] = []
    tags: List[str] = []


class UpdateStatusRequest(BaseModel):
    status: CaseStatus
    actor: str = "SOC Analyst"
    comment: Optional[str] = None


class AddNoteRequest(BaseModel):
    author: str
    content: str


class LinkAlertRequest(BaseModel):
    alert_id: str
    actor: str = "SOC Analyst"


@router.get("", response_model=List[Case])
def list_cases(
    status: Optional[CaseStatus] = None,
    priority: Optional[RiskLevel] = None,
):
    cases = list(storage.cases.values())
    if status:
        cases = [c for c in cases if c.status == status]
    if priority:
        cases = [c for c in cases if c.priority == priority]
    cases.sort(key=lambda c: c.updated_at, reverse=True)
    return cases


@router.post("", response_model=Case)
def create_case(payload: CreateCaseRequest):
    case = Case(
        title=payload.title,
        description=payload.description,
        status=CaseStatus.NEW,
        severity=payload.severity,
        priority=payload.priority,
        assigned_to=payload.assigned_to or "Unassigned",
        linked_alert_ids=payload.linked_alert_ids,
        tags=payload.tags,
        audit_trail=[
            CaseAuditEntry(
                actor=payload.assigned_to or "SOC Analyst",
                action="CASE_CREATED",
                detail=f"Case initialized with {len(payload.linked_alert_ids)} linked alerts.",
            )
        ],
    )
    storage.cases[case.case_id] = case

    # Link back to alerts
    for aid in payload.linked_alert_ids:
        if aid in storage.alerts:
            storage.alerts[aid].linked_case_id = case.case_id

    return case


@router.get("/{case_id}", response_model=Case)
def get_case(case_id: str):
    case = storage.cases.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")
    return case


@router.patch("/{case_id}/status", response_model=Case)
def update_case_status(case_id: str, payload: UpdateStatusRequest):
    case = storage.cases.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")

    old_status = case.status
    case.status = payload.status
    case.updated_at = datetime.now(timezone.utc)

    msg = f"Status changed from {old_status.value.upper()} to {payload.status.value.upper()}."
    if payload.comment:
        msg += f" Note: {payload.comment}"

    case.audit_trail.append(
        CaseAuditEntry(
            actor=payload.actor,
            action="STATUS_CHANGE",
            detail=msg,
        )
    )
    return case


@router.post("/{case_id}/notes", response_model=Case)
def add_case_note(case_id: str, payload: AddNoteRequest):
    case = storage.cases.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")

    note = CaseNote(author=payload.author, content=payload.content)
    case.notes.append(note)
    case.updated_at = datetime.now(timezone.utc)

    case.audit_trail.append(
        CaseAuditEntry(
            actor=payload.author,
            action="NOTE_ADDED",
            detail=f"Added note: {payload.content[:50]}...",
        )
    )
    return case


@router.post("/{case_id}/link", response_model=Case)
def link_alert_to_case(case_id: str, payload: LinkAlertRequest):
    case = storage.cases.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")

    if payload.alert_id not in case.linked_alert_ids:
        case.linked_alert_ids.append(payload.alert_id)
        if payload.alert_id in storage.alerts:
            storage.alerts[payload.alert_id].linked_case_id = case.case_id

        case.audit_trail.append(
            CaseAuditEntry(
                actor=payload.actor,
                action="ALERT_LINKED",
                detail=f"Linked alert {payload.alert_id}.",
            )
        )

    return case
