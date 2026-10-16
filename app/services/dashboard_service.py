"""Security dashboard. Every figure is computed from live database rows (never stored or estimated).

Scope notes
* incident / SLA figures are organisation-wide aggregates - they count sensitive incidents but never expose their
  content;
* alert figures exclude duplicate (repeated) alerts so one event is not counted several times;
* "SLA compliance" = resolved without any breach / (resolved without breach + breached);
* the summary is cached for DASHBOARD_CACHE_TTL_SECONDS when Redis is configured.
"""
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.constants import INCIDENT_DONE_STATUSES, INCIDENT_OPEN_STATUSES, RoleName
from app.models import Role, User
from app.repositories.report_repository import ReportRepository
from app.schemas.dashboard import DashboardSummary
from app.services import risk_service, sla_service
from app.utils import cache
from app.utils.date_utils import attach_utc, utcnow


def incident_stats(db: Session) -> dict:
    by_status, by_sev = ReportRepository(db).incident_counts()
    return {
        "total": sum(by_status.values()),
        "open": sum(by_status.get(s, 0) for s in INCIDENT_OPEN_STATUSES),
        "resolved": sum(by_status.get(s, 0) for s in INCIDENT_DONE_STATUSES),
        "by_status": by_status,
        "by_severity": by_sev,
    }


def alert_stats(db: Session) -> dict:
    data = ReportRepository(db).alert_counts()
    by_sev = data["by_severity"]
    return {
        "total": sum(by_sev.values()),
        "critical_total": by_sev.get("critical", 0),
        "critical_open": data["critical_open"],
        "by_severity": by_sev,
    }


def vulnerability_stats(db: Session) -> dict:
    by_status, by_sev = ReportRepository(db).vulnerability_counts()
    return {
        "total": sum(by_status.values()),
        "unresolved": sum(by_sev.values()),
        "by_severity": by_sev,
        "by_status": by_status,
    }


def high_risk_assets(db: Session, limit: int = 10) -> list[dict]:
    return [
        {"asset": i["asset"], "risk_score": i["risk_score"], "risk_level": i["risk_level"],
         "open_vulnerabilities": i["open_vulnerabilities"]}
        for i in risk_service.high_risk_assets(db, "high", limit)
    ]


def response_times(db: Session) -> dict:
    avg_resp, avg_res, count = ReportRepository(db).response_times()
    return {"average_response_minutes": avg_resp, "average_resolution_minutes": avg_res, "incidents_measured": count}


def sla_stats(db: Session) -> dict:
    sla_service.evaluate_all_open(db)  # make sure pending breaches are reflected
    counts = ReportRepository(db).sla_counts()
    decided = counts["compliant"] + counts["breached"]
    return {**counts, "compliance_percent": round(counts["compliant"] / decided * 100, 1) if decided else None}


def remediation_stats(db: Session) -> dict:
    overdue, total = ReportRepository(db).remediation_counts()
    return {"overdue": overdue, "total_unfinished": total}


def analyst_workload(db: Session) -> list[dict]:
    loads = ReportRepository(db).workload()
    analyst_ids = set(
        db.scalars(
            select(User.id).join(Role, Role.id == User.role_id).where(
                User.is_active.is_(True), Role.name == RoleName.SECURITY_ANALYST.value
            )
        )
    )
    ids = analyst_ids | set(loads)
    users = {u.id: u for u in db.scalars(select(User).where(User.id.in_(ids)))} if ids else {}
    rows = []
    for uid in ids:
        user = users.get(uid)
        if user is None or not user.is_active:
            continue
        data = loads.get(uid, {})
        row = {
            "user_id": uid, "full_name": user.full_name,
            "open_incidents": data.get("open_incidents", 0), "open_alerts": data.get("open_alerts", 0),
            "open_remediation_tasks": data.get("open_remediation_tasks", 0),
            "open_playbook_tasks": data.get("open_playbook_tasks", 0),
        }
        row["total_open"] = sum(v for k, v in row.items() if k.startswith("open_"))
        rows.append(row)
    return sorted(rows, key=lambda r: (-r["total_open"], r["full_name"]))


def incident_trend(db: Session, days: int = 30) -> list[dict]:
    end = utcnow().date()
    start = end - timedelta(days=days - 1)
    created, resolved = ReportRepository(db).trend(start, end)
    return [
        {"date": (d := (start + timedelta(days=i)).isoformat()), "created": created.get(d, 0),
         "resolved": resolved.get(d, 0)}
        for i in range(days)
    ]


def summary(db: Session, days: int = 30) -> dict:
    key = f"dashboard:summary:{days}"
    cached = cache.cache_get(key)
    if cached is not None:
        return cached
    data = DashboardSummary(
        generated_at=attach_utc(utcnow()),
        incidents=incident_stats(db),
        alerts=alert_stats(db),
        vulnerabilities=vulnerability_stats(db),
        high_risk_assets=high_risk_assets(db),
        response_times=response_times(db),
        sla=sla_stats(db),
        remediation=remediation_stats(db),
        analyst_workload=analyst_workload(db),
        incident_trend=incident_trend(db, days),
    ).model_dump(mode="json")
    cache.cache_set(key, data, settings.DASHBOARD_CACHE_TTL_SECONDS)
    return data
