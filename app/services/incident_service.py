"""Incident creation, updates, alert linking, related incidents and notes. Lifecycle transitions (assign, status,
resolve, closure approval) live in incident_lifecycle_service."""
from datetime import timedelta

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.constants import SEVERITY_RANK, NotificationType, P
from app.core.exceptions import BadRequestError, ConflictError, NotFoundError
from app.core.permissions import (
    ensure_can_view_incident,
    ensure_can_work_incident,
    ensure_permission,
)
from app.models import Incident, IncidentAlert, IncidentHistory, IncidentRelation, InvestigationNote, User
from app.repositories.alert_repository import AlertRepository
from app.repositories.asset_repository import AssetRepository
from app.repositories.correlation_repository import CorrelationRepository
from app.repositories.incident_repository import IncidentRepository
from app.schemas.incident import IncidentCreate, IncidentRelationCreate, IncidentUpdate
from app.services import audit_service, correlation_service, notification_service, sla_service
from app.utils.date_utils import make_reference, utcnow

AUDIT_FIELDS = ("title", "category", "severity", "status", "is_sensitive", "asset_id", "assigned_to_id",
                "correlation_id")


def add_history(db: Session, incident_id: int, user_id: int | None, action: str, old=None, new=None,
                comment: str | None = None) -> None:
    db.add(
        IncidentHistory(
            incident_id=incident_id,
            user_id=user_id,
            action=action,
            old_value=None if old is None else str(old),
            new_value=None if new is None else str(new),
            comment=comment,
        )
    )


def get_visible(db: Session, user: User, incident_id: int) -> Incident:
    incident = IncidentRepository(db).require(incident_id)
    ensure_can_view_incident(user, incident)
    return incident


def _notify_critical(db: Session, incident: Incident, actor: User) -> None:
    notification_service.notify_permission_holders(
        db, P.INCIDENT_ASSIGN, NotificationType.CRITICAL_INCIDENT,
        f"Critical incident {incident.reference}",
        f"Critical incident '{incident.title}' ({incident.category}) was raised"
        + (f" on asset {incident.asset.name}" if incident.asset else "") + ".",
        exclude_user_id=actor.id, entity_type="incident", entity_id=incident.id,
    )


# --------------------------------------------------------------------------- creation
def create(db: Session, actor: User, data: IncidentCreate) -> Incident:
    arepo, irepo = AlertRepository(db), IncidentRepository(db)
    alert_ids = list(dict.fromkeys(data.alert_ids))
    correlation = None
    if data.correlation_id is not None:
        correlation = CorrelationRepository(db).require(data.correlation_id)
        alert_ids += [a.id for a in correlation.alerts if a.id not in alert_ids]
    alerts = arepo.by_ids(alert_ids)
    missing = sorted(set(alert_ids) - {a.id for a in alerts})
    if missing:
        raise NotFoundError(f"Alert(s) not found: {missing}")
    if any(a.status == "false_positive" for a in alerts):
        raise BadRequestError("False-positive alerts cannot be linked to an incident")
    linked = irepo.alerts_already_linked(alert_ids)
    if linked:
        raise ConflictError("Some alerts already belong to an incident", details={"alert_to_incident": linked})

    if not alerts and (data.category is None or data.severity is None or data.asset_id is None):
        raise BadRequestError("An incident without alerts requires category, severity and asset_id")

    top_alert = max(alerts, key=lambda a: (SEVERITY_RANK[a.severity], -a.id)) if alerts else None
    severity = data.severity or top_alert.severity
    category = data.category or (top_alert.category if top_alert else None)
    asset_id = data.asset_id
    if asset_id is None and alerts:
        asset_id = top_alert.asset_id
    asset = AssetRepository(db).require(asset_id)
    if data.is_sensitive:
        ensure_permission(actor, P.INCIDENT_SENSITIVE, "Marking an incident as sensitive requires incident:sensitive")

    # duplicate-incident rule: an open incident for the same asset + category within the window
    since = utcnow() - timedelta(hours=settings.DUPLICATE_INCIDENT_WINDOW_HOURS)
    duplicates = irepo.find_open_duplicates(asset.id, category, since)
    if duplicates and not data.allow_duplicate:
        raise ConflictError(
            "A similar open incident already exists for this asset and category",
            code="duplicate_incident",
            details={
                "rule": f"open incident, same asset and category, created within "
                        f"{settings.DUPLICATE_INCIDENT_WINDOW_HOURS}h",
                "existing_incidents": [{"id": d.id, "reference": d.reference, "status": d.status} for d in duplicates],
                "hint": "Link the alerts to the existing incident (POST /incidents/{id}/alerts) "
                        "or resubmit with allow_duplicate=true",
            },
        )

    now = utcnow()
    incident = Incident(
        title=data.title,
        description=data.description,
        category=category,
        severity=severity,
        status="new",
        is_sensitive=data.is_sensitive,
        asset_id=asset.id,
        correlation_id=data.correlation_id,
        created_by_id=actor.id,
    )
    irepo.add(incident)
    incident.reference = make_reference("INC", incident.id, now)
    for alert in alerts:
        db.add(IncidentAlert(incident_id=incident.id, alert_id=alert.id, linked_by_id=actor.id))
        if alert.status in ("new", "acknowledged"):
            alert.status = "in_progress"
    for dup in duplicates:
        db.add(IncidentRelation(incident_id=incident.id, related_incident_id=dup.id, relation_type="possible_duplicate",
                                reason="Same asset and category while another incident is open",
                                created_by_id=actor.id))
    add_history(db, incident.id, actor.id, "created", new=f"{severity}/{category}",
                comment=f"Created from {len(alerts)} alert(s)" if alerts else "Created manually")
    if correlation is not None:
        correlation_service.record_incident_link(db, correlation.id, actor.id, incident.reference)
    sla_service.create_for_incident(db, incident)
    audit_service.record(db, user_id=actor.id, action="incident.create", entity_type="incident",
                         entity_id=incident.id,
                         new={**audit_service.snapshot(incident, AUDIT_FIELDS), "alert_ids": alert_ids})
    if severity == "critical":
        _notify_critical(db, incident, actor)
    db.flush()

    if data.assigned_to_id is not None:
        from app.services import incident_lifecycle_service

        incident_lifecycle_service.assign(db, actor, incident, data.assigned_to_id, "Assigned at creation",
                                          commit=False)
    db.commit()
    db.refresh(incident)
    return incident


# --------------------------------------------------------------------------- updates
def _ensure_open(incident: Incident) -> None:
    if incident.status == "closed":
        raise ConflictError("Closed incidents are read-only")


def update(db: Session, actor: User, incident: Incident, data: IncidentUpdate) -> Incident:
    ensure_can_work_incident(actor, incident)
    _ensure_open(incident)
    values = data.model_dump(exclude_unset=True)
    for key in ("title", "category", "severity", "is_sensitive"):
        if key in values and values[key] is None:
            raise BadRequestError(f"{key} cannot be cleared")
    if "is_sensitive" in values and values["is_sensitive"] != incident.is_sensitive:
        ensure_permission(actor, P.INCIDENT_SENSITIVE, "Changing sensitivity requires incident:sensitive")
    before = audit_service.snapshot(incident, AUDIT_FIELDS)
    for key, value in values.items():
        setattr(incident, key, value)
    prev, new = audit_service.changes(before, audit_service.snapshot(incident, AUDIT_FIELDS))
    for field in new:
        add_history(db, incident.id, actor.id, f"{field}_changed", prev[field], new[field])
    if "severity" in new:
        audit_service.record(db, user_id=actor.id, action="incident.severity_change", entity_type="incident",
                             entity_id=incident.id, previous={"severity": prev["severity"]},
                             new={"severity": new["severity"]})
        prev.pop("severity"), new.pop("severity")
        sla_service.recalculate_deadlines(db, incident)
        if incident.severity == "critical":
            _notify_critical(db, incident, actor)
    if new:
        audit_service.record(db, user_id=actor.id, action="incident.update", entity_type="incident",
                             entity_id=incident.id, previous=prev, new=new)
    db.commit()
    db.refresh(incident)
    return incident


# --------------------------------------------------------------------------- alerts / relations / notes
def link_alerts(db: Session, actor: User, incident: Incident, alert_ids: list[int]) -> Incident:
    ensure_can_work_incident(actor, incident)
    _ensure_open(incident)
    if incident.status == "resolved":
        raise ConflictError("Re-open the incident before linking more alerts")
    alert_ids = list(dict.fromkeys(alert_ids))
    alerts = AlertRepository(db).by_ids(alert_ids)
    missing = sorted(set(alert_ids) - {a.id for a in alerts})
    if missing:
        raise NotFoundError(f"Alert(s) not found: {missing}")
    if any(a.status == "false_positive" for a in alerts):
        raise BadRequestError("False-positive alerts cannot be linked to an incident")
    linked = IncidentRepository(db).alerts_already_linked(alert_ids)
    if linked:
        raise ConflictError("Some alerts already belong to an incident", details={"alert_to_incident": linked})
    for alert in alerts:
        db.add(IncidentAlert(incident_id=incident.id, alert_id=alert.id, linked_by_id=actor.id))
        if alert.status in ("new", "acknowledged"):
            alert.status = "in_progress"
    top = max(alerts, key=lambda a: SEVERITY_RANK[a.severity])
    add_history(db, incident.id, actor.id, "alerts_linked", new=",".join(str(a.id) for a in alerts))
    audit_service.record(db, user_id=actor.id, action="incident.link_alerts", entity_type="incident",
                         entity_id=incident.id, new={"alert_ids": alert_ids})
    if SEVERITY_RANK[top.severity] > SEVERITY_RANK[incident.severity]:
        old = incident.severity
        incident.severity = top.severity
        add_history(db, incident.id, actor.id, "severity_changed", old, top.severity, "Raised by linked alert")
        audit_service.record(db, user_id=actor.id, action="incident.severity_change", entity_type="incident",
                             entity_id=incident.id, previous={"severity": old}, new={"severity": top.severity})
        sla_service.recalculate_deadlines(db, incident)
    db.commit()
    db.refresh(incident)
    return incident


def add_relation(db: Session, actor: User, incident: Incident, data: IncidentRelationCreate) -> IncidentRelation:
    ensure_can_work_incident(actor, incident)
    other = IncidentRepository(db).require(data.related_incident_id)
    ensure_can_view_incident(actor, other)
    if other.id == incident.id:
        raise BadRequestError("An incident cannot be related to itself")
    if IncidentRepository(db).get_relation(incident.id, other.id):
        raise ConflictError("These incidents are already related")
    relation = IncidentRelation(incident_id=incident.id, related_incident_id=other.id,
                                relation_type=data.relation_type, reason=data.reason, created_by_id=actor.id)
    db.add(relation)
    add_history(db, incident.id, actor.id, "related_incident_added", new=f"{other.reference} ({data.relation_type})")
    db.commit()
    return relation


def visible_relations(db: Session, user: User, incident: Incident) -> list[IncidentRelation]:
    repo = IncidentRepository(db)
    result = []
    for rel in repo.relations(incident.id):
        other_id = rel.related_incident_id if rel.incident_id == incident.id else rel.incident_id
        other = repo.get(other_id)
        if other is not None and (not other.is_sensitive or user.has_permission(P.INCIDENT_SENSITIVE)
                                  or user.id in (other.assigned_to_id, other.created_by_id)):
            result.append(rel)
    return result


def add_note(db: Session, actor: User, incident: Incident, content: str) -> InvestigationNote:
    ensure_can_work_incident(actor, incident)
    _ensure_open(incident)
    note = InvestigationNote(incident_id=incident.id, author_id=actor.id, note_type="note", content=content)
    db.add(note)
    add_history(db, incident.id, actor.id, "note_added")
    db.commit()
    db.refresh(note)
    return note
