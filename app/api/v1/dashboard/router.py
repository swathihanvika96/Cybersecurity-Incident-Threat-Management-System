"""Dashboard metrics. Every figure is computed from live database rows (optionally cached for a few seconds)."""
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import DbSession, require_permission
from app.core.constants import P
from app.models import User
from app.schemas.common import COMMON_RESPONSES
from app.schemas.dashboard import (
    AlertStats,
    AnalystWorkload,
    DashboardSummary,
    HighRiskAsset,
    IncidentStats,
    OverdueRemediationStats,
    ResponseTimeStats,
    SLAStats,
    TrendPoint,
    VulnerabilityStats,
)
from app.services import dashboard_service as svc

router = APIRouter(prefix="/dashboard", tags=["Dashboard"], responses=COMMON_RESPONSES)

Reader = Annotated[User, Depends(require_permission(P.DASHBOARD_READ))]


@router.get("", response_model=DashboardSummary, summary="Full dashboard summary")
def summary(db: DbSession, _: Reader, days: int = Query(30, ge=1, le=365, description="Trend window in days")):
    return svc.summary(db, days)


@router.get("/incidents", response_model=IncidentStats, summary="Incident counters")
def incidents(db: DbSession, _: Reader):
    return svc.incident_stats(db)


@router.get("/alerts", response_model=AlertStats, summary="Alert counters")
def alerts(db: DbSession, _: Reader):
    return svc.alert_stats(db)


@router.get("/vulnerabilities", response_model=VulnerabilityStats, summary="Vulnerability counters")
def vulnerabilities(db: DbSession, _: Reader):
    return svc.vulnerability_stats(db)


@router.get("/high-risk-assets", response_model=list[HighRiskAsset], summary="High-risk assets")
def high_risk_assets(db: DbSession, _: Reader, limit: int = Query(10, ge=1, le=100)):
    return svc.high_risk_assets(db, limit)


@router.get("/response-times", response_model=ResponseTimeStats, summary="Average response / resolution times")
def response_times(db: DbSession, _: Reader):
    return svc.response_times(db)


@router.get("/sla", response_model=SLAStats, summary="SLA compliance")
def sla(db: DbSession, _: Reader):
    return svc.sla_stats(db)


@router.get("/remediation", response_model=OverdueRemediationStats, summary="Overdue remediation")
def remediation(db: DbSession, _: Reader):
    return svc.remediation_stats(db)


@router.get("/analyst-workload", response_model=list[AnalystWorkload], summary="Workload per analyst")
def analyst_workload(db: DbSession, _: Reader):
    return svc.analyst_workload(db)


@router.get("/incident-trend", response_model=list[TrendPoint], summary="Incidents created/resolved per day")
def incident_trend(db: DbSession, _: Reader, days: int = Query(30, ge=1, le=365)):
    return svc.incident_trend(db, days)
