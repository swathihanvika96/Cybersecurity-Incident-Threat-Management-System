from pydantic import Field, computed_field, model_validator

from app.core.constants import EscalationStatus, Severity, SLAStatus
from app.schemas.common import DT, ORMModel, RequestModel
from app.utils.date_utils import attach_utc, utcnow


class SLAPolicyUpdate(RequestModel):
    ack_minutes: int = Field(gt=0, le=525600)
    investigation_minutes: int = Field(gt=0, le=525600)
    resolution_minutes: int = Field(gt=0, le=525600)

    @model_validator(mode="after")
    def _ordered(self):
        if not (self.ack_minutes <= self.investigation_minutes <= self.resolution_minutes):
            raise ValueError("Expected ack_minutes <= investigation_minutes <= resolution_minutes")
        return self


class SLAPolicyOut(ORMModel):
    severity: Severity
    ack_minutes: int
    investigation_minutes: int
    resolution_minutes: int
    updated_at: DT


class EscalateRequest(RequestModel):
    reason: str = Field(min_length=3, max_length=500)


class IncidentSLAOut(ORMModel):
    incident_id: int
    severity: Severity
    ack_deadline: DT
    investigation_deadline: DT
    resolution_deadline: DT
    acknowledged_at: DT | None = None
    investigation_started_at: DT | None = None
    resolved_at: DT | None = None
    response_time_minutes: float | None = Field(None, description="Actual response (acknowledgment) time")
    resolution_time_minutes: float | None = Field(None, description="Actual resolution time")
    ack_breached: bool
    investigation_breached: bool
    resolution_breached: bool
    sla_status: SLAStatus
    escalation_status: EscalationStatus
    escalation_level: int
    escalated_at: DT | None = None
    escalation_reason: str | None = None

    @computed_field(description="Minutes until the resolution deadline (negative = overdue); null once resolved")
    @property
    def minutes_to_resolution_deadline(self) -> float | None:
        if self.resolved_at is not None:
            return None
        return round((self.resolution_deadline - attach_utc(utcnow())).total_seconds() / 60, 1)


class SLAIncidentItem(ORMModel):
    incident_id: int
    incident_reference: str | None = None
    incident_title: str
    incident_status: str
    severity: Severity
    assigned_to_id: int | None = None
    at_risk_phases: list[str] = Field(description="Phases (acknowledgment/investigation/resolution) concerned")
    sla: IncidentSLAOut


class SLAEvaluationResult(ORMModel):
    evaluated: int
    newly_breached: int
    escalated: int


class SLAHistoryOut(ORMModel):
    id: int
    incident_id: int
    event: str
    details: str | None = None
    timestamp: DT
