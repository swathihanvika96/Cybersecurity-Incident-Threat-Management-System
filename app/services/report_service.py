"""Report generation and CSV export.

Report            | Rows                        | Date filter applies to      | Other filters used
------------------+-----------------------------+-----------------------------+------------------------------------
daily-incident-summary    | one per day         | incident created / alert detected | severity, department, asset, analyst
weekly-security-summary   | one per ISO week    | all activity in the week    | severity, department, asset, analyst
vulnerability-analysis    | one per vulnerability | discovered_at             | severity, status, department, asset
asset-risk                | one per asset (open vulns) | -                    | risk_level, department, asset
analyst-performance       | one per analyst     | incident created_at         | severity, department, asset, analyst
sla-compliance            | one per severity    | incident created_at         | severity, department, asset, analyst
remediation-status        | one per task        | task created_at             | severity (of vulnerability), status, department, asset, analyst
incident-resolution-trends| one per day/week    | created / resolved          | severity, department, asset, analyst
"""
from datetime import date, timedelta
from enum import StrEnum
from statistics import mean

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.constants import INCIDENT_OPEN_STATUSES, P
from app.core.exceptions import BadRequestError
from app.core.permissions import ensure_permission
from app.models import Asset, ReportExport, User
from app.repositories.report_repository import ReportFilters, ReportRepository
from app.repositories.risk_repository import RiskRepository
from app.services import audit_service, risk_service, sla_service
from app.utils.date_utils import attach_utc, utcnow, week_start


class ReportType(StrEnum):
    DAILY = "daily-incident-summary"
    WEEKLY = "weekly-security-summary"
    VULNERABILITY = "vulnerability-analysis"
    ASSET_RISK = "asset-risk"
    ANALYST = "analyst-performance"
    SLA = "sla-compliance"
    REMEDIATION = "remediation-status"
    TRENDS = "incident-resolution-trends"


COLUMNS: dict[str, list[str]] = {
    ReportType.DAILY: ["date", "incidents_created", "critical_incidents", "high_incidents", "incidents_resolved",
                       "alerts_received", "duplicate_alerts", "critical_alerts"],
    ReportType.WEEKLY: ["week_start", "week_end", "incidents_created", "incidents_resolved", "alerts_received",
                        "critical_alerts", "vulnerabilities_discovered", "remediation_approved", "sla_breaches"],
    ReportType.VULNERABILITY: ["reference", "cve_id", "title", "severity", "cvss_score", "status", "affected_assets",
                               "max_risk_score", "discovered_at", "remediation_deadline", "overdue", "days_open"],
    ReportType.ASSET_RISK: ["asset_id", "asset_name", "asset_type", "criticality", "department", "risk_score",
                            "risk_level", "open_vulnerabilities", "accepted_vulnerabilities"],
    ReportType.ANALYST: ["analyst_id", "analyst_name", "incidents_assigned", "incidents_resolved", "currently_open",
                         "avg_response_minutes", "avg_resolution_minutes", "sla_breaches",
                         "remediation_tasks_approved"],
    ReportType.SLA: ["severity", "incidents", "met", "breached", "in_progress", "compliance_percent",
                     "avg_response_minutes", "avg_resolution_minutes", "escalated"],
    ReportType.REMEDIATION: ["reference", "title", "vulnerability", "vulnerability_severity", "asset_id", "team",
                             "assignee", "priority", "status", "due_date", "approved_at", "overdue"],
    ReportType.TRENDS: ["period", "created", "resolved", "avg_resolution_minutes"],
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]


def ensure_report_access(user: User, report_type: ReportType, export: bool = False) -> None:
    ensure_permission(user, P.REPORT_READ)
    if report_type == ReportType.ANALYST:
        ensure_permission(user, P.REPORT_ANALYST, "Analyst performance reports are restricted to managers")
    if export:
        ensure_permission(user, P.REPORT_EXPORT, "Exporting reports requires report:export")


# --------------------------------------------------------------------------- helpers
def _avg(values) -> float | None:
    values = [v for v in values if v is not None]
    return round(mean(values), 2) if values else None


def _days(start: date, end: date) -> list[date]:
    return [start + timedelta(days=i) for i in range((end - start).days + 1)]


def _defaults(f: ReportFilters, days: int) -> None:
    today = utcnow().date()
    if f.date_from is None and f.date_to is None:
        f.date_to, f.date_from = today, today - timedelta(days=days - 1)
    elif f.date_to is None:
        f.date_to = today
    elif f.date_from is None:
        f.date_from = f.date_to - timedelta(days=days - 1)
    if f.date_from > f.date_to:
        raise BadRequestError("date_from must not be after date_to")
    if (f.date_to - f.date_from).days > 366:
        raise BadRequestError("Date range may not exceed 366 days for this report")


def _is_breached(fact: dict) -> bool:
    return bool(fact["ack_breached"] or fact["investigation_breached"] or fact["resolution_breached"])


# --------------------------------------------------------------------------- builders
def _daily(db: Session, f: ReportFilters, **_):
    _defaults(f, 7)
    repo = ReportRepository(db)
    created, resolved, alerts = repo.incident_facts(f), repo.incident_facts(f, "resolved"), repo.alert_facts(f)
    rows = []
    for day in _days(f.date_from, f.date_to):
        c = [x for x in created if x["created_at"].date() == day]
        a = [x for x in alerts if x["detected_at"].date() == day]
        rows.append({
            "date": day.isoformat(),
            "incidents_created": len(c),
            "critical_incidents": sum(1 for x in c if x["severity"] == "critical"),
            "high_incidents": sum(1 for x in c if x["severity"] == "high"),
            "incidents_resolved": sum(1 for x in resolved if x["resolved_at"].date() == day),
            "alerts_received": sum(1 for x in a if not x["is_duplicate"]),
            "duplicate_alerts": sum(1 for x in a if x["is_duplicate"]),
            "critical_alerts": sum(1 for x in a if x["severity"] == "critical" and not x["is_duplicate"]),
        })
    summary = {k: sum(r[k] for r in rows) for k in COLUMNS[ReportType.DAILY][1:]}
    summary["days"] = len(rows)
    return summary, rows


def _weekly(db: Session, f: ReportFilters, **_):
    _defaults(f, 28)
    repo = ReportRepository(db)
    # widen to whole ISO weeks so every row covers a full Monday-Sunday week
    wf = ReportFilters(**{**f.__dict__, "date_from": week_start(f.date_from),
                          "date_to": week_start(f.date_to) + timedelta(days=6)})
    created, resolved, alerts = repo.incident_facts(wf), repo.incident_facts(wf, "resolved"), repo.alert_facts(wf)
    vuln_dates, approvals = repo.vulnerability_discovery_dates(wf), repo.remediation_approval_dates(wf)
    rows, week, last = [], wf.date_from, wf.date_to
    while week <= last:
        end = week + timedelta(days=6)
        in_week = lambda d: week <= d.date() <= end  # noqa: E731
        c = [x for x in created if in_week(x["created_at"])]
        a = [x for x in alerts if in_week(x["detected_at"]) and not x["is_duplicate"]]
        rows.append({
            "week_start": week.isoformat(), "week_end": end.isoformat(),
            "incidents_created": len(c),
            "incidents_resolved": sum(1 for x in resolved if in_week(x["resolved_at"])),
            "alerts_received": len(a),
            "critical_alerts": sum(1 for x in a if x["severity"] == "critical"),
            "vulnerabilities_discovered": sum(1 for d in vuln_dates if in_week(d)),
            "remediation_approved": sum(1 for d in approvals if in_week(d)),
            "sla_breaches": sum(1 for x in c if _is_breached(x)),
        })
        week += timedelta(days=7)
    summary = {k: sum(r[k] for r in rows) for k in COLUMNS[ReportType.WEEKLY][2:]}
    summary["weeks"] = len(rows)
    f.date_from, f.date_to = wf.date_from, wf.date_to
    return summary, rows


def _vulnerabilities(db: Session, f: ReportFilters, **_):
    rows = ReportRepository(db).vulnerability_rows(f)
    summary = {
        "total": len(rows),
        "by_severity": {s: sum(1 for r in rows if r["severity"] == s) for s in SEVERITY_ORDER
                        if any(r["severity"] == s for r in rows)},
        "by_status": {s: sum(1 for r in rows if r["status"] == s) for s in sorted({r["status"] for r in rows})},
        "overdue": sum(1 for r in rows if r["overdue"]),
        "average_cvss": _avg(r["cvss_score"] for r in rows),
    }
    return summary, rows


def _asset_risk(db: Session, f: ReportFilters, **_):
    items = risk_service.asset_risk_items(db, RiskRepository(db).asset_risk_rows())
    rows = []
    for item in items:
        asset: Asset = item["asset"]
        if f.department_id is not None and asset.department_id != f.department_id:
            continue
        if f.asset_id is not None and asset.id != f.asset_id:
            continue
        if f.risk_level and item["risk_level"] not in f.risk_level:
            continue
        rows.append({
            "asset_id": asset.id, "asset_name": asset.name, "asset_type": asset.asset_type,
            "criticality": asset.criticality, "department": asset.department.name if asset.department else None,
            "risk_score": item["risk_score"], "risk_level": item["risk_level"],
            "open_vulnerabilities": item["open_vulnerabilities"],
            "accepted_vulnerabilities": item["accepted_vulnerabilities"],
        })
    summary = {"assets": len(rows),
               "by_risk_level": {lvl: sum(1 for r in rows if r["risk_level"] == lvl)
                                 for lvl in ("critical", "high", "medium", "low")
                                 if any(r["risk_level"] == lvl for r in rows)}}
    return summary, rows


def _analyst(db: Session, f: ReportFilters, **_):
    repo = ReportRepository(db)
    facts = [x for x in repo.incident_facts(f) if x["assigned_to_id"] is not None]
    approved = repo.remediation_approved_by_assignee(f)
    ids = {x["assigned_to_id"] for x in facts} | set(approved)
    if f.analyst_id is not None:
        ids &= {f.analyst_id}
    users = {u.id: u for u in db.scalars(select(User).where(User.id.in_(ids)))} if ids else {}
    rows = []
    for uid in sorted(ids):
        mine = [x for x in facts if x["assigned_to_id"] == uid]
        rows.append({
            "analyst_id": uid, "analyst_name": users[uid].full_name if uid in users else f"user {uid}",
            "incidents_assigned": len(mine),
            "incidents_resolved": sum(1 for x in mine if x["resolved_at"] is not None),
            "currently_open": sum(1 for x in mine if x["status"] in INCIDENT_OPEN_STATUSES),
            "avg_response_minutes": _avg(x["response_time_minutes"] for x in mine),
            "avg_resolution_minutes": _avg(x["resolution_time_minutes"] for x in mine),
            "sla_breaches": sum(1 for x in mine if _is_breached(x)),
            "remediation_tasks_approved": approved.get(uid, 0),
        })
    rows.sort(key=lambda r: (-r["incidents_resolved"], r["analyst_name"]))
    return {"analysts": len(rows), "incidents_assigned": sum(r["incidents_assigned"] for r in rows),
            "incidents_resolved": sum(r["incidents_resolved"] for r in rows)}, rows


def _sla(db: Session, f: ReportFilters, **_):
    sla_service.evaluate_all_open(db)
    facts = [x for x in ReportRepository(db).incident_facts(f) if x["sla_status"] is not None]
    rows = []
    for sev in SEVERITY_ORDER:
        mine = [x for x in facts if x["severity"] == sev]
        if not mine:
            continue
        met = sum(1 for x in mine if x["sla_status"] == "met")
        breached = sum(1 for x in mine if x["sla_status"] == "breached")
        rows.append({
            "severity": sev, "incidents": len(mine), "met": met, "breached": breached,
            "in_progress": sum(1 for x in mine if x["sla_status"] in ("on_track", "at_risk")),
            "compliance_percent": round(met / (met + breached) * 100, 1) if met + breached else None,
            "avg_response_minutes": _avg(x["response_time_minutes"] for x in mine),
            "avg_resolution_minutes": _avg(x["resolution_time_minutes"] for x in mine),
            "escalated": sum(1 for x in mine if x["escalation_status"] != "none"),
        })
    met, breached = sum(r["met"] for r in rows), sum(r["breached"] for r in rows)
    return {"incidents": sum(r["incidents"] for r in rows), "met": met, "breached": breached,
            "compliance_percent": round(met / (met + breached) * 100, 1) if met + breached else None}, rows


def _remediation(db: Session, f: ReportFilters, **_):
    rows = ReportRepository(db).remediation_rows(f)
    summary = {
        "total": len(rows), "overdue": sum(1 for r in rows if r["overdue"]),
        "by_status": {s: sum(1 for r in rows if r["status"] == s) for s in sorted({r["status"] for r in rows})},
        "by_priority": {p: sum(1 for r in rows if r["priority"] == p) for p in sorted({r["priority"] for r in rows})},
    }
    return summary, rows


def _trends(db: Session, f: ReportFilters, granularity: str = "day", **_):
    _defaults(f, 30)
    repo = ReportRepository(db)
    created, resolved = repo.incident_facts(f), repo.incident_facts(f, "resolved")
    if granularity == "week":
        starts = []
        cursor = week_start(f.date_from)
        while cursor <= f.date_to:
            starts.append(cursor)
            cursor += timedelta(days=7)
        spans = [(s, s + timedelta(days=6), f"{s.isoformat()} (week)") for s in starts]
    else:
        spans = [(d, d, d.isoformat()) for d in _days(f.date_from, f.date_to)]
    rows = []
    for start, end, label in spans:
        done = [x for x in resolved if start <= x["resolved_at"].date() <= end]
        rows.append({
            "period": label,
            "created": sum(1 for x in created if start <= x["created_at"].date() <= end),
            "resolved": len(done),
            "avg_resolution_minutes": _avg(x["resolution_time_minutes"] for x in done),
        })
    return {"created": sum(r["created"] for r in rows), "resolved": sum(r["resolved"] for r in rows),
            "granularity": granularity}, rows


BUILDERS = {
    ReportType.DAILY: _daily, ReportType.WEEKLY: _weekly, ReportType.VULNERABILITY: _vulnerabilities,
    ReportType.ASSET_RISK: _asset_risk, ReportType.ANALYST: _analyst, ReportType.SLA: _sla,
    ReportType.REMEDIATION: _remediation, ReportType.TRENDS: _trends,
}


# --------------------------------------------------------------------------- public API
def generate(db: Session, user: User, report_type: ReportType, filters: ReportFilters,
             granularity: str = "day") -> dict:
    ensure_report_access(user, report_type)
    summary, rows = BUILDERS[report_type](db, filters, granularity=granularity)
    parameters = filters.as_dict()
    if report_type == ReportType.TRENDS:
        parameters["granularity"] = granularity
    return {
        "report": report_type.value,
        "generated_at": attach_utc(utcnow()),
        "parameters": parameters,
        "summary": summary,
        "rows": rows,
    }


def export_csv(db: Session, user: User, report_type: ReportType, filters: ReportFilters,
               granularity: str = "day") -> tuple[str, list[dict], list[str]]:
    ensure_report_access(user, report_type, export=True)
    report = generate(db, user, report_type, filters, granularity)
    filename = f"{report_type.value}-{utcnow():%Y%m%d-%H%M%S}.csv"
    db.add(ReportExport(user_id=user.id, report_type=report_type.value, parameters=report["parameters"],
                        row_count=len(report["rows"]), file_name=filename))
    audit_service.record(db, user_id=user.id, action="report.export", entity_type="report", entity_id=None,
                         new={"report": report_type.value, "rows": len(report["rows"]),
                              "parameters": report["parameters"]})
    db.commit()
    return filename, report["rows"], COLUMNS[report_type]
