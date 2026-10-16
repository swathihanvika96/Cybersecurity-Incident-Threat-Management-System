from pydantic import Field

from app.core.constants import AlertStatus, SecurityCategory, Severity
from app.schemas.asset import AssetBrief
from app.schemas.common import DT, DTIn, ORMModel, RequestModel
from app.schemas.user import UserBrief


class AlertCreate(RequestModel):
    title: str = Field(min_length=3, max_length=255)
    description: str | None = None
    source: str = Field(min_length=2, max_length=100, description="Detection source, e.g. SIEM, EDR, IDS")
    category: SecurityCategory
    severity: Severity
    asset_id: int = Field(description="Affected asset")
    detected_at: DTIn | None = Field(None, description="When the alert was raised (defaults to now, UTC)")
    assigned_to_id: int | None = None


class AlertUpdate(RequestModel):
    title: str | None = Field(None, min_length=3, max_length=255)
    description: str | None = None
    source: str | None = Field(None, min_length=2, max_length=100)
    category: SecurityCategory | None = None
    severity: Severity | None = None


class AlertStatusUpdate(RequestModel):
    status: AlertStatus
    comment: str | None = Field(None, max_length=500)


class AlertAssign(RequestModel):
    assigned_to_id: int | None = Field(description="Analyst user id (null un-assigns)")


class AlertBrief(ORMModel):
    id: int
    reference: str | None = None
    title: str
    severity: Severity
    status: AlertStatus
    detected_at: DT


class AlertOut(ORMModel):
    id: int
    reference: str | None = None
    title: str
    description: str | None = None
    source: str
    category: SecurityCategory
    severity: Severity
    status: AlertStatus
    asset: AssetBrief
    assigned_to: UserBrief | None = None
    detected_at: DT
    is_duplicate: bool
    duplicate_of_id: int | None = None
    occurrence_count: int
    correlation_id: int | None = None
    created_at: DT
    updated_at: DT
