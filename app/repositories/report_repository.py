"""Aggregate queries for the dashboard and reports. Everything is computed from live database rows."""
from dataclasses import dataclass
from datetime import date, datetime

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.constants import (
    ALERT_ACTIVE_STATUSES,
    INCIDENT_OPEN_STATUSES,
    REMEDIATION_UNFINISHED,
    VULN_UNRESOLVED_STATUSES,
)
from app.models import (
    Asset,
    AssetVulnerability,
    Incident,
    IncidentSLA,
    PlaybookExecution,
    PlaybookTask,
    RemediationTask,
    RiskAssessment,
    SecurityAlert,
    Vulnerability,
)
from app.utils.date_utils import end_exclusive, start_of_day, utcnow
from app.utils.filtering import validate_date_range


@dataclass
class ReportFilters:
    date_from: date | None = None
    date_to: date | None = None
    severity: list[str] | None = None
    status: list[str] | None = None
    risk_level: list[str] | None = None
    department_id: int | None = None
    asset_id: int | None = None
    analyst_id: int | None = None

    def as_dict(self) -> dict:
        return {k: (v.isoformat() if isinstance(v, date) else v) for k, v in self.__dict__.items() if v is not None}


def _in_range(column, f: ReportFilters):
    clauses = []
    if f.date_from:
        clauses.append(column >= start_of_day(f.date_from))
    if f.date_to:
        clauses.append(column < end_exclusive(f.date_to))
    return clauses


def _dept_assets(department_id: int):
    return select(Asset.id).where(Asset.department_id == department_id)


class ReportRepository:
    def __init__(self, db: Session):
        self.db = db

    # ------------------------------------------------------------------ dashboard counters
    def incident_counts(self) -> tuple[dict[str, int], dict[str, int]]:
        by_status = dict(self.db.execute(select(Incident.status, func.count(Incident.id)).group_by(Incident.status)).all())
        by_sev = dict(self.db.execute(select(Incident.severity, func.count(Incident.id)).group_by(Incident.severity)).all())
        return by_status, by_sev

    def alert_counts(self) -> dict:
        base = SecurityAlert.is_duplicate.is_(False)  # repeated (duplicate) alerts are not counted twice
        by_sev = dict(
            self.db.execute(
                select(SecurityAlert.severity, func.count(SecurityAlert.id)).where(base).group_by(SecurityAlert.severity)
            ).all()
        )
        critical_open = self.db.scalar(
            select(func.count(SecurityAlert.id)).where(
                base, SecurityAlert.severity == "critical",
                SecurityAlert.status.in_([s.value for s in ALERT_ACTIVE_STATUSES]),
            )
        ) or 0
        return {"by_severity": by_sev, "critical_open": critical_open}

    def vulnerability_counts(self) -> tuple[dict[str, int], dict[str, int]]:
        by_status = dict(self.db.execute(select(Vulnerability.status, func.count(Vulnerability.id)).group_by(Vulnerability.status)).all())
        by_sev_unresolved = dict(
            self.db.execute(
                select(Vulnerability.severity, func.count(Vulnerability.id))
                .where(Vulnerability.status.in_(VULN_UNRESOLVED_STATUSES))
                .group_by(Vulnerability.severity)
            ).all()
        )
        return by_status, by_sev_unresolved

    def response_times(self) -> tuple[float | None, float | None, int]:
        avg_resp, avg_res, count = self.db.execute(
            select(
                func.avg(IncidentSLA.response_time_minutes),
                func.avg(IncidentSLA.resolution_time_minutes),
                func.count(IncidentSLA.response_time_minutes),
            )
        ).one()
        return (
            round(float(avg_resp), 2) if avg_resp is not None else None,
            round(float(avg_res), 2) if avg_res is not None else None,
            int(count or 0),
        )

    def sla_counts(self) -> dict[str, int]:
        any_breach = or_(IncidentSLA.ack_breached, IncidentSLA.investigation_breached, IncidentSLA.resolution_breached)
        count = lambda *where: self.db.scalar(select(func.count(IncidentSLA.id)).where(*where)) or 0  # noqa: E731
        return {
            "tracked": count(),
            "compliant": count(IncidentSLA.resolved_at.is_not(None), ~any_breach),
            "breached": count(any_breach),
            "in_progress": count(IncidentSLA.resolved_at.is_(None), ~any_breach),
        }

    def remediation_counts(self) -> tuple[int, int]:
        unfinished = RemediationTask.status.in_(REMEDIATION_UNFINISHED)
        total = self.db.scalar(select(func.count(RemediationTask.id)).where(unfinished)) or 0
        overdue = self.db.scalar(
            select(func.count(RemediationTask.id)).where(unfinished, RemediationTask.due_date < utcnow())
        ) or 0
        return overdue, total

    def workload(self) -> dict[int, dict[str, int]]:
        result: dict[int, dict[str, int]] = {}

        def merge(key: str, rows) -> None:
            for user_id, count in rows:
                if user_id is not None:
                    result.setdefault(user_id, {})[key] = int(count)

        merge("open_incidents", self.db.execute(
            select(Incident.assigned_to_id, func.count(Incident.id))
            .where(Incident.status.in_(INCIDENT_OPEN_STATUSES)).group_by(Incident.assigned_to_id)))
        merge("open_alerts", self.db.execute(
            select(SecurityAlert.assigned_to_id, func.count(SecurityAlert.id))
            .where(SecurityAlert.status.in_([s.value for s in ALERT_ACTIVE_STATUSES]),
                   SecurityAlert.is_duplicate.is_(False))
            .group_by(SecurityAlert.assigned_to_id)))
        merge("open_remediation_tasks", self.db.execute(
            select(RemediationTask.assigned_to_id, func.count(RemediationTask.id))
            .where(RemediationTask.status.in_(REMEDIATION_UNFINISHED)).group_by(RemediationTask.assigned_to_id)))
        merge("open_playbook_tasks", self.db.execute(
            select(PlaybookTask.assigned_to_id, func.count(PlaybookTask.id))
            .join(PlaybookExecution, PlaybookExecution.id == PlaybookTask.execution_id)
            .where(PlaybookExecution.status == "running", PlaybookTask.status != "completed")
            .group_by(PlaybookTask.assigned_to_id)))
        return result

    def trend(self, start: date, end: date) -> tuple[dict[str, int], dict[str, int]]:
        def grouped(column) -> dict[str, int]:
            day = func.date(column)
            rows = self.db.execute(
                select(day, func.count(Incident.id))
                .where(column >= start_of_day(start), column < end_exclusive(end))
                .group_by(day)
            ).all()
            return {str(d)[:10]: int(c) for d, c in rows}

        return grouped(Incident.created_at), grouped(Incident.resolved_at)

    # ------------------------------------------------------------------ row-level facts for reports
    def incident_facts(self, f: ReportFilters, by: str = "created") -> list[dict]:
        column = Incident.created_at if by == "created" else Incident.resolved_at
        stmt = (
            select(
                Incident.id, Incident.created_at, Incident.resolved_at, Incident.severity, Incident.status,
                Incident.assigned_to_id, Incident.asset_id,
                IncidentSLA.response_time_minutes, IncidentSLA.resolution_time_minutes,
                IncidentSLA.ack_breached, IncidentSLA.investigation_breached, IncidentSLA.resolution_breached,
                IncidentSLA.sla_status, IncidentSLA.escalation_status,
            )
            .select_from(Incident)
            .outerjoin(IncidentSLA, IncidentSLA.incident_id == Incident.id)
        )
        validate_date_range(f.date_from, f.date_to)
        if by == "resolved":
            stmt = stmt.where(Incident.resolved_at.is_not(None))
        for clause in _in_range(column, f):
            stmt = stmt.where(clause)
        if f.severity:
            stmt = stmt.where(Incident.severity.in_(f.severity))
        if f.department_id is not None:
            stmt = stmt.where(Incident.asset_id.in_(_dept_assets(f.department_id)))
        if f.asset_id is not None:
            stmt = stmt.where(Incident.asset_id == f.asset_id)
        if f.analyst_id is not None:
            stmt = stmt.where(Incident.assigned_to_id == f.analyst_id)
        return [dict(r) for r in self.db.execute(stmt).mappings()]

    def alert_facts(self, f: ReportFilters) -> list[dict]:
        stmt = select(SecurityAlert.detected_at, SecurityAlert.severity, SecurityAlert.is_duplicate)
        validate_date_range(f.date_from, f.date_to)
        for clause in _in_range(SecurityAlert.detected_at, f):
            stmt = stmt.where(clause)
        if f.severity:
            stmt = stmt.where(SecurityAlert.severity.in_(f.severity))
        if f.department_id is not None:
            stmt = stmt.where(SecurityAlert.asset_id.in_(_dept_assets(f.department_id)))
        if f.asset_id is not None:
            stmt = stmt.where(SecurityAlert.asset_id == f.asset_id)
        if f.analyst_id is not None:
            stmt = stmt.where(SecurityAlert.assigned_to_id == f.analyst_id)
        return [dict(r) for r in self.db.execute(stmt).mappings()]

    def vulnerability_discovery_dates(self, f: ReportFilters) -> list[datetime]:
        stmt = select(Vulnerability.discovered_at)
        for clause in _in_range(Vulnerability.discovered_at, f):
            stmt = stmt.where(clause)
        if f.severity:
            stmt = stmt.where(Vulnerability.severity.in_(f.severity))
        if f.department_id is not None or f.asset_id is not None:
            mapped = select(AssetVulnerability.vulnerability_id)
            if f.asset_id is not None:
                mapped = mapped.where(AssetVulnerability.asset_id == f.asset_id)
            if f.department_id is not None:
                mapped = mapped.where(AssetVulnerability.asset_id.in_(_dept_assets(f.department_id)))
            stmt = stmt.where(Vulnerability.id.in_(mapped))
        return list(self.db.scalars(stmt))

    def remediation_approval_dates(self, f: ReportFilters) -> list[datetime]:
        stmt = select(RemediationTask.approved_at).where(RemediationTask.approved_at.is_not(None))
        for clause in _in_range(RemediationTask.approved_at, f):
            stmt = stmt.where(clause)
        if f.department_id is not None:
            stmt = stmt.where(RemediationTask.asset_id.in_(_dept_assets(f.department_id)))
        if f.asset_id is not None:
            stmt = stmt.where(RemediationTask.asset_id == f.asset_id)
        if f.analyst_id is not None:
            stmt = stmt.where(RemediationTask.assigned_to_id == f.analyst_id)
        return list(self.db.scalars(stmt))

    def remediation_approved_by_assignee(self, f: ReportFilters) -> dict[int, int]:
        stmt = (
            select(RemediationTask.assigned_to_id, func.count(RemediationTask.id))
            .where(RemediationTask.status == "approved", RemediationTask.assigned_to_id.is_not(None))
            .group_by(RemediationTask.assigned_to_id)
        )
        for clause in _in_range(RemediationTask.approved_at, f):
            stmt = stmt.where(clause)
        return {u: int(c) for u, c in self.db.execute(stmt)}

    def vulnerability_rows(self, f: ReportFilters) -> list[dict]:
        stmt = select(Vulnerability).order_by(Vulnerability.cvss_score.desc(), Vulnerability.id)
        for clause in _in_range(Vulnerability.discovered_at, f):
            stmt = stmt.where(clause)
        if f.severity:
            stmt = stmt.where(Vulnerability.severity.in_(f.severity))
        if f.status:
            stmt = stmt.where(Vulnerability.status.in_(f.status))
        if f.department_id is not None or f.asset_id is not None:
            mapped = select(AssetVulnerability.vulnerability_id)
            if f.asset_id is not None:
                mapped = mapped.where(AssetVulnerability.asset_id == f.asset_id)
            if f.department_id is not None:
                mapped = mapped.where(AssetVulnerability.asset_id.in_(_dept_assets(f.department_id)))
            stmt = stmt.where(Vulnerability.id.in_(mapped))
        vulns = list(self.db.scalars(stmt))
        ids = [v.id for v in vulns]
        if not ids:
            return []
        affected = dict(self.db.execute(
            select(AssetVulnerability.vulnerability_id, func.count(AssetVulnerability.id))
            .where(AssetVulnerability.vulnerability_id.in_(ids)).group_by(AssetVulnerability.vulnerability_id)).all())
        top_risk = dict(self.db.execute(
            select(RiskAssessment.vulnerability_id, func.max(RiskAssessment.risk_score))
            .join(AssetVulnerability, and_(AssetVulnerability.asset_id == RiskAssessment.asset_id,
                                           AssetVulnerability.vulnerability_id == RiskAssessment.vulnerability_id))
            .where(RiskAssessment.vulnerability_id.in_(ids), RiskAssessment.is_current.is_(True),
                   AssetVulnerability.status == "open")
            .group_by(RiskAssessment.vulnerability_id)).all())
        now = utcnow()
        return [
            {
                "reference": v.reference, "cve_id": v.cve_id, "title": v.title, "severity": v.severity,
                "cvss_score": v.cvss_score, "status": v.status, "affected_assets": int(affected.get(v.id, 0)),
                "max_risk_score": top_risk.get(v.id), "discovered_at": v.discovered_at,
                "remediation_deadline": v.remediation_deadline,
                "overdue": bool(v.remediation_deadline and v.remediation_deadline < now
                                and v.status in VULN_UNRESOLVED_STATUSES),
                "days_open": (now - v.discovered_at).days if v.status in VULN_UNRESOLVED_STATUSES else None,
            }
            for v in vulns
        ]

    def remediation_rows(self, f: ReportFilters) -> list[dict]:
        stmt = (
            select(RemediationTask, Vulnerability.reference, Vulnerability.severity)
            .join(Vulnerability, Vulnerability.id == RemediationTask.vulnerability_id)
            .order_by(RemediationTask.due_date, RemediationTask.id)
        )
        for clause in _in_range(RemediationTask.created_at, f):
            stmt = stmt.where(clause)
        if f.severity:
            stmt = stmt.where(Vulnerability.severity.in_(f.severity))
        if f.status:
            stmt = stmt.where(RemediationTask.status.in_(f.status))
        if f.department_id is not None:
            stmt = stmt.where(RemediationTask.asset_id.in_(_dept_assets(f.department_id)))
        if f.asset_id is not None:
            stmt = stmt.where(RemediationTask.asset_id == f.asset_id)
        if f.analyst_id is not None:
            stmt = stmt.where(RemediationTask.assigned_to_id == f.analyst_id)
        now = utcnow()
        return [
            {
                "reference": t.reference, "title": t.title, "vulnerability": vref, "vulnerability_severity": vsev,
                "asset_id": t.asset_id, "team": t.team.name if t.team else None,
                "assignee": t.assignee.full_name if t.assignee else None, "priority": t.priority,
                "status": t.status, "due_date": t.due_date, "approved_at": t.approved_at,
                "overdue": t.status in REMEDIATION_UNFINISHED and t.due_date < now,
            }
            for t, vref, vsev in self.db.execute(stmt).unique()
        ]
