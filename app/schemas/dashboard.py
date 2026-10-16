from pydantic import Field

from app.core.constants import RiskLevel
from app.schemas.asset import AssetBrief
from app.schemas.common import DT, ORMModel


class IncidentStats(ORMModel):
    total: int
    open: int = Field(description="new + assigned + investigating + containment")
    resolved: int = Field(description="resolved + closed")
    by_status: dict[str, int]
    by_severity: dict[str, int]


class AlertStats(ORMModel):
    total: int
    critical_total: int
    critical_open: int = Field(description="Critical alerts not yet resolved / marked false positive")
    by_severity: dict[str, int]


class VulnerabilityStats(ORMModel):
    total: int
    unresolved: int = Field(description="open + under_review + in_remediation")
    by_severity: dict[str, int] = Field(description="Counts of unresolved vulnerabilities per severity")
    by_status: dict[str, int]


class HighRiskAsset(ORMModel):
    asset: AssetBrief
    risk_score: float
    risk_level: RiskLevel
    open_vulnerabilities: int


class ResponseTimeStats(ORMModel):
    average_response_minutes: float | None = Field(description="Mean time to acknowledge (assignment)")
    average_resolution_minutes: float | None
    incidents_measured: int


class SLAStats(ORMModel):
    tracked: int
    compliant: int = Field(description="Resolved with no SLA breach")
    breached: int = Field(description="Any phase breached")
    in_progress: int
    compliance_percent: float | None = Field(description="compliant / (compliant + breached) * 100")


class OverdueRemediationStats(ORMModel):
    overdue: int
    total_unfinished: int


class AnalystWorkload(ORMModel):
    user_id: int
    full_name: str
    open_incidents: int
    open_alerts: int
    open_remediation_tasks: int
    open_playbook_tasks: int
    total_open: int


class TrendPoint(ORMModel):
    date: str
    created: int
    resolved: int


class DashboardSummary(ORMModel):
    generated_at: DT
    incidents: IncidentStats
    alerts: AlertStats
    vulnerabilities: VulnerabilityStats
    high_risk_assets: list[HighRiskAsset]
    response_times: ResponseTimeStats
    sla: SLAStats
    remediation: OverdueRemediationStats
    analyst_workload: list[AnalystWorkload]
    incident_trend: list[TrendPoint]
