from typing import Literal

from pydantic import Field

from app.core.constants import IncidentStatus, SecurityCategory, Severity
from app.schemas.asset import AssetBrief
from app.schemas.common import DT, ORMModel, RequestModel
from app.schemas.incident_sla import IncidentSLAOut
from app.schemas.security_alert import AlertBrief
from app.schemas.user import UserBrief


class IncidentCreate(RequestModel):
    title: str = Field(min_length=3, max_length=255)
    description: str | None = None
    category: SecurityCategory | None = Field(None, description="Defaults to the category of the linked alerts")
    severity: Severity | None = Field(None, description="Defaults to the highest severity of the linked alerts")
    alert_ids: list[int] = Field(default_factory=list, description="Alerts to link to the new incident")
    correlation_id: int | None = Field(None, description="Link every alert of this correlation group")
    asset_id: int | None = Field(None, description="Primary affected asset (defaults to the alerts' asset)")
    is_sensitive: bool = False
    assigned_to_id: int | None = Field(None, description="Assign immediately (requires incident:assign)")
    allow_duplicate: bool = Field(
        False, description="Create even if an open incident for the same asset+category exists (links it as related)"
    )


class IncidentUpdate(RequestModel):
    title: str | None = Field(None, min_length=3, max_length=255)
    description: str | None = None
    category: SecurityCategory | None = None
    severity: Severity | None = None
    is_sensitive: bool | None = None


class IncidentStatusUpdate(RequestModel):
    status: Literal["investigating", "containment"]
    comment: str | None = Field(None, max_length=1000)


class IncidentAssign(RequestModel):
    assigned_to_id: int
    comment: str | None = Field(None, max_length=1000)


class IncidentResolve(RequestModel):
    resolution_summary: str = Field(min_length=3, max_length=500)
    resolution_details: str = Field(min_length=10)
    root_cause: str | None = None


class ClosureRequest(RequestModel):
    comment: str | None = Field(None, max_length=1000)


class ClosureDecision(RequestModel):
    comment: str | None = Field(None, max_length=1000, description="Required when rejecting")


class IncidentLinkAlerts(RequestModel):
    alert_ids: list[int] = Field(min_length=1)


class IncidentRelationCreate(RequestModel):
    related_incident_id: int
    relation_type: Literal["related", "possible_duplicate", "follow_up"] = "related"
    reason: str | None = Field(None, max_length=500)


class NoteCreate(RequestModel):
    content: str = Field(min_length=1, max_length=10000)


class IncidentOut(ORMModel):
    id: int
    reference: str | None = None
    title: str
    description: str | None = None
    category: SecurityCategory
    severity: Severity
    status: IncidentStatus
    is_sensitive: bool
    asset: AssetBrief | None = None
    correlation_id: int | None = None
    assigned_to: UserBrief | None = None
    created_by_id: int | None = None
    resolution_summary: str | None = None
    resolution_details: str | None = None
    root_cause: str | None = None
    resolved_at: DT | None = None
    closed_at: DT | None = None
    closure_requested_by_id: int | None = None
    closure_requested_at: DT | None = None
    closure_approved_by_id: int | None = None
    closure_note: str | None = None
    sla: IncidentSLAOut | None = None
    created_at: DT
    updated_at: DT


class IncidentDetail(IncidentOut):
    alerts: list[AlertBrief] = []


class IncidentHistoryOut(ORMModel):
    id: int
    incident_id: int
    user_id: int | None = None
    action: str
    old_value: str | None = None
    new_value: str | None = None
    comment: str | None = None
    timestamp: DT


class IncidentAssignmentOut(ORMModel):
    id: int
    incident_id: int
    assigned_to_id: int
    assigned_by_id: int | None = None
    assigned_at: DT
    unassigned_at: DT | None = None
    is_active: bool


class IncidentRelationOut(ORMModel):
    id: int
    incident_id: int
    related_incident_id: int
    relation_type: str
    reason: str | None = None
    created_at: DT


class SearchResultItem(ORMModel):
    entity_type: Literal["incident", "alert"]
    id: int
    reference: str | None = None
    title: str
    severity: str
    status: str
    category: str
    asset_id: int | None = None
    assigned_to_id: int | None = None
    created_at: DT
