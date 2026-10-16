"""SLA management.

Rules
-----
* Targets per severity (minutes, editable via PUT /slas/policies/{severity}) are applied when an incident is
  created; all deadlines are measured from the incident's creation time:
      acknowledgment deadline  = created + ack_minutes
      investigation deadline   = created + investigation_minutes   (investigation must have STARTED)
      resolution deadline      = created + resolution_minutes
* Acknowledgment = first assignment of an analyst; investigation start = status -> investigating;
  resolution = status -> resolved. Actual response time = acknowledged - created; actual resolution time =
  resolved - created (re-opening an incident clears them).
* A phase is breached when it was achieved after its deadline, or is still pending after its deadline.
* Status: breached (any phase breached) > met (resolved, none breached) > at_risk (a pending phase has used
  more than 1 - SLA_APPROACHING_FRACTION of its window) > on_track.
* Escalation: level = number of breached phases. Level >= 1 -> `escalated`; level >= 2, or any breach of a
  critical incident -> `critical_escalation`. Managers can also escalate manually.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.constants import SLA_DEFAULT_POLICIES, NotificationType, P
from app.core.exceptions import BadRequestError, ConflictError
from app.models import Incident, IncidentSLA, SLAHistory, SLAPolicy, User
from app.repositories.sla_repository import SLARepository
from app.schemas.incident_sla import SLAPolicyUpdate
from app.services import audit_service, notification_service
from app.utils.date_utils import minutes_between, utcnow
from app.utils.pagination import PageParams

PHASES = ("acknowledgment", "investigation", "resolution")


@dataclass
class SLAState:
    ack_breached: bool
    investigation_breached: bool
    resolution_breached: bool
    status: str

    @property
    def flags(self) -> tuple[bool, bool, bool]:
        return self.ack_breached, self.investigation_breached, self.resolution_breached


def _phase_table(sla: IncidentSLA):
    return (
        ("acknowledgment", sla.ack_deadline, sla.acknowledged_at),
        ("investigation", sla.investigation_deadline, sla.investigation_started_at),
        ("resolution", sla.resolution_deadline, sla.resolved_at),
    )


def compute_state(sla: IncidentSLA, created_at: datetime, now: datetime,
                  approaching_fraction: float | None = None) -> SLAState:
    """Pure evaluation of an SLA at `now` (no side effects)."""
    fraction = settings.SLA_APPROACHING_FRACTION if approaching_fraction is None else approaching_fraction
    flags = []
    for _, deadline, achieved_at in _phase_table(sla):
        flags.append(achieved_at > deadline if achieved_at is not None else now > deadline)
    if any(flags):
        status = "breached"
    elif sla.resolved_at is not None:
        status = "met"
    else:
        status = "on_track"
        for _, deadline, achieved_at in _phase_table(sla):
            if achieved_at is None:
                window = (deadline - created_at).total_seconds()
                if (deadline - now).total_seconds() <= window * fraction:
                    status = "at_risk"
                    break
    return SLAState(*flags, status)


def breached_phases(sla: IncidentSLA) -> list[str]:
    return [p for p, flag in zip(PHASES, (sla.ack_breached, sla.investigation_breached, sla.resolution_breached)) if flag]


def approaching_phases(sla: IncidentSLA, created_at: datetime, now: datetime,
                       fraction: float | None = None) -> list[str]:
    fraction = settings.SLA_APPROACHING_FRACTION if fraction is None else fraction
    result = []
    for phase, deadline, achieved_at in _phase_table(sla):
        if achieved_at is None and deadline >= now:
            window = (deadline - created_at).total_seconds()
            if (deadline - now).total_seconds() <= window * fraction:
                result.append(phase)
    return result


def escalation_status_for(level: int, severity: str) -> str:
    if level >= 2 or (level >= 1 and severity == "critical"):
        return "critical_escalation"
    if level >= 1:
        return "escalated"
    return "none"


def _log(db: Session, incident_id: int, event: str, details: str | None = None) -> None:
    db.add(SLAHistory(incident_id=incident_id, event=event, details=details))


# --------------------------------------------------------------------------- lifecycle hooks
def policy_minutes(db: Session, severity: str) -> tuple[int, int, int]:
    policy = SLARepository(db).policy(severity)
    if policy:
        return policy.ack_minutes, policy.investigation_minutes, policy.resolution_minutes
    return SLA_DEFAULT_POLICIES[severity]


def create_for_incident(db: Session, incident: Incident) -> IncidentSLA:
    ack, inv, res = policy_minutes(db, incident.severity)
    created = incident.created_at
    sla = IncidentSLA(
        incident=incident,
        severity=incident.severity,
        ack_deadline=created + timedelta(minutes=ack),
        investigation_deadline=created + timedelta(minutes=inv),
        resolution_deadline=created + timedelta(minutes=res),
    )
    db.add(sla)
    db.flush()
    _log(db, incident.id, "created", f"severity={incident.severity}; ack={ack}m investigation={inv}m resolution={res}m")
    return sla


def _sla_of(db: Session, incident: Incident) -> IncidentSLA | None:
    return incident.sla or SLARepository(db).for_incident(incident.id)


def mark_acknowledged(db: Session, incident: Incident, now: datetime | None = None) -> None:
    sla, now = _sla_of(db, incident), now or utcnow()
    if sla is None or sla.acknowledged_at is not None:
        return
    sla.acknowledged_at = now
    sla.response_time_minutes = minutes_between(incident.created_at, now)
    _log(db, incident.id, "acknowledged", f"response time {sla.response_time_minutes} min")
    apply_evaluation(db, incident, sla, now)


def mark_investigation_started(db: Session, incident: Incident, now: datetime | None = None) -> None:
    sla, now = _sla_of(db, incident), now or utcnow()
    if sla is None or sla.investigation_started_at is not None:
        return
    sla.investigation_started_at = now
    _log(db, incident.id, "investigation_started")
    apply_evaluation(db, incident, sla, now)


def mark_resolved(db: Session, incident: Incident, now: datetime | None = None) -> None:
    sla, now = _sla_of(db, incident), now or utcnow()
    if sla is None:
        return
    sla.resolved_at = now
    sla.resolution_time_minutes = minutes_between(incident.created_at, now)
    _log(db, incident.id, "resolved", f"resolution time {sla.resolution_time_minutes} min")
    apply_evaluation(db, incident, sla, now)


def mark_reopened(db: Session, incident: Incident, now: datetime | None = None) -> None:
    sla, now = _sla_of(db, incident), now or utcnow()
    if sla is None:
        return
    sla.resolved_at = None
    sla.resolution_time_minutes = None
    _log(db, incident.id, "reopened")
    apply_evaluation(db, incident, sla, now)


def recalculate_deadlines(db: Session, incident: Incident) -> None:
    """Severity changed: re-apply the new severity's policy to the existing SLA."""
    sla = _sla_of(db, incident)
    if sla is None:
        return
    ack, inv, res = policy_minutes(db, incident.severity)
    old = sla.severity
    sla.severity = incident.severity
    sla.ack_deadline = incident.created_at + timedelta(minutes=ack)
    sla.investigation_deadline = incident.created_at + timedelta(minutes=inv)
    sla.resolution_deadline = incident.created_at + timedelta(minutes=res)
    _log(db, incident.id, "deadlines_recalculated", f"severity {old} -> {incident.severity}")
    apply_evaluation(db, incident, sla)


# --------------------------------------------------------------------------- evaluation
def apply_evaluation(db: Session, incident: Incident, sla: IncidentSLA, now: datetime | None = None,
                     notify: bool = True) -> list[str]:
    """Recompute breach flags/status, escalate and notify. Returns newly breached phases. Caller commits."""
    now = now or utcnow()
    state = compute_state(sla, incident.created_at, now)
    old_flags = (sla.ack_breached, sla.investigation_breached, sla.resolution_breached)
    newly = [p for p, new, old in zip(PHASES, state.flags, old_flags) if new and not old]
    sla.ack_breached, sla.investigation_breached, sla.resolution_breached = state.flags
    sla.sla_status = state.status
    for phase in newly:
        _log(db, incident.id, "breached", f"{phase} deadline missed")
    level = sum(state.flags)
    if level > sla.escalation_level:
        sla.escalation_level = level
        sla.escalation_status = escalation_status_for(level, sla.severity)
        sla.escalated_at = now
        sla.escalation_reason = "SLA breached: " + ", ".join(breached_phases(sla))
        _log(db, incident.id, "escalated", f"level {level} ({sla.escalation_status}): {sla.escalation_reason}")
    if notify:
        for phase in newly:
            notification_service.notify_permission_holders(
                db, P.SLA_MANAGE, NotificationType.SLA_BREACH,
                f"SLA breach: {incident.reference} ({phase})",
                f"Incident {incident.reference} '{incident.title}' ({incident.severity}) missed its {phase} deadline.",
                extra_user_ids=[incident.assigned_to_id],
                entity_type="incident", entity_id=incident.id, dedupe=True, dedupe_on_title=True,
            )
    return newly


def evaluate_all_open(db: Session) -> dict[str, int]:
    """Re-evaluate every open incident's SLA (used by the worker and before listing breached/approaching)."""
    evaluated = newly_breached = escalated = 0
    for incident, sla in SLARepository(db).open_incident_slas():
        level_before = sla.escalation_level
        newly_breached += len(apply_evaluation(db, incident, sla))
        escalated += 1 if sla.escalation_level > level_before else 0
        evaluated += 1
    db.commit()
    return {"evaluated": evaluated, "newly_breached": newly_breached, "escalated": escalated}


def manual_escalate(db: Session, actor: User, incident: Incident, reason: str) -> IncidentSLA:
    sla = _sla_of(db, incident)
    if sla is None:
        raise BadRequestError("Incident has no SLA")
    if incident.status in ("resolved", "closed"):
        raise ConflictError("Resolved or closed incidents cannot be escalated")
    previous = {"level": sla.escalation_level, "status": sla.escalation_status}
    sla.escalation_level += 1
    sla.escalation_status = escalation_status_for(max(sla.escalation_level, 1), sla.severity)
    sla.escalated_at = utcnow()
    sla.escalation_reason = reason
    _log(db, incident.id, "escalated_manually", f"by user {actor.id}: {reason}")
    audit_service.record(
        db, user_id=actor.id, action="sla.escalate", entity_type="incident", entity_id=incident.id,
        previous=previous, new={"level": sla.escalation_level, "status": sla.escalation_status, "reason": reason},
    )
    notification_service.notify_permission_holders(
        db, P.SLA_MANAGE, NotificationType.SLA_BREACH, f"Incident escalated: {incident.reference}",
        f"Incident {incident.reference} was escalated by user {actor.id}: {reason}",
        exclude_user_id=actor.id, extra_user_ids=[incident.assigned_to_id],
        entity_type="incident", entity_id=incident.id,
    )
    db.commit()
    return sla


# --------------------------------------------------------------------------- policies & listings
def update_policy(db: Session, actor: User, severity: str, data: SLAPolicyUpdate) -> SLAPolicy:
    repo = SLARepository(db)
    policy = repo.policy(severity)
    if policy is None:
        policy = SLAPolicy(severity=severity, ack_minutes=0, investigation_minutes=0, resolution_minutes=0)
        db.add(policy)
    previous = {"ack_minutes": policy.ack_minutes, "investigation_minutes": policy.investigation_minutes,
                "resolution_minutes": policy.resolution_minutes}
    policy.ack_minutes = data.ack_minutes
    policy.investigation_minutes = data.investigation_minutes
    policy.resolution_minutes = data.resolution_minutes
    policy.updated_by_id = actor.id
    audit_service.record(db, user_id=actor.id, action="sla.policy_update", entity_type="sla_policy",
                         entity_id=policy.id, previous=previous, new=data.model_dump())
    db.commit()
    db.refresh(policy)
    return policy


def _items(rows, phases_fn) -> list[dict]:
    return [
        {
            "incident_id": inc.id,
            "incident_reference": inc.reference,
            "incident_title": inc.title,
            "incident_status": inc.status,
            "severity": inc.severity,
            "assigned_to_id": inc.assigned_to_id,
            "at_risk_phases": phases_fn(inc, sla),
            "sla": sla,
        }
        for inc, sla in rows
    ]


def _page(db: Session, user: User, params: PageParams, statuses: list[str], phases_fn, **opts):
    evaluate_all_open(db)
    stmt = SLARepository(db).listing(user, sla_status=statuses, **opts)
    from app.utils.pagination import count_rows

    total = count_rows(db, stmt)
    rows = [(i, s) for i, s in db.execute(stmt.limit(params.size).offset(params.offset))]
    return _items(rows, phases_fn), total


def list_breached(db: Session, user: User, params: PageParams, include_resolved: bool = False):
    return _page(db, user, params, ["breached"], lambda inc, sla: breached_phases(sla),
                 include_resolved=include_resolved)


def list_approaching(db: Session, user: User, params: PageParams):
    now = utcnow()
    return _page(db, user, params, ["at_risk"], lambda inc, sla: approaching_phases(sla, inc.created_at, now))


def list_escalated(db: Session, user: User, params: PageParams):
    return _page(db, user, params, ["on_track", "at_risk", "breached", "met"],
                 lambda inc, sla: breached_phases(sla), escalated_only=True)
