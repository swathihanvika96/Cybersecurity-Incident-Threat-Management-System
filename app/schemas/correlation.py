from pydantic import Field, computed_field

from app.core.constants import CorrelationRule, SecurityCategory
from app.schemas.common import DT, ORMModel, RequestModel
from app.schemas.security_alert import AlertBrief


class CorrelationCreate(RequestModel):
    name: str = Field(min_length=3, max_length=255)
    alert_ids: list[int] = Field(min_length=2, description="At least two alerts to group")


class CorrelationAddAlerts(RequestModel):
    alert_ids: list[int] = Field(min_length=1)


class AutoCorrelateRequest(RequestModel):
    window_minutes: int | None = Field(None, ge=1, le=10080, description="Defaults to CORRELATION_WINDOW_MINUTES")
    min_alerts: int | None = Field(None, ge=2, le=1000, description="Defaults to CORRELATION_MIN_ALERTS")
    lookback_hours: int | None = Field(None, ge=1, le=8760, description="Defaults to CORRELATION_LOOKBACK_HOURS")


class CorrelationOut(ORMModel):
    id: int
    reference: str | None = None
    name: str
    rule: CorrelationRule
    asset_id: int | None = None
    category: SecurityCategory | None = None
    status: str
    alerts: list[AlertBrief]
    created_at: DT
    updated_at: DT

    @computed_field
    @property
    def alert_count(self) -> int:
        return len(self.alerts)


class CorrelationHistoryOut(ORMModel):
    id: int
    correlation_id: int
    action: str
    alert_id: int | None = None
    user_id: int | None = None
    details: str | None = None
    timestamp: DT


class AutoCorrelateResult(ORMModel):
    created: list[CorrelationOut]
    updated: list[CorrelationOut]


class RepeatedAlertGroup(ORMModel):
    asset_id: int
    asset_name: str
    category: SecurityCategory
    alert_count: int
    alert_ids: list[int]
    first_detected_at: DT
    last_detected_at: DT
    already_correlated: bool

