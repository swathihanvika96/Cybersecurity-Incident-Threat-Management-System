"""Incident lifecycle: assignment, status transitions, resolution and closure approval.

new -> assigned -> investigating <-> containment -> resolved -> closed
 * `assigned`   : an analyst is assigned (also the SLA acknowledgment)
 * `resolved`   : requires resolution details; may be re-opened to `investigating`
 * `closed`     : only through the closure-approval workflow, by a manager who did not request the closure
"""
from sqlalchemy.orm import Session

from app.core.constants import (
    INCIDENT_RESOLVABLE_FROM,
    INCIDENT_STATUS_TRANSITIONS,
    NotificationType,
    P,
)
from app.core.exceptions import BadRequestError, ConflictError, ForbiddenError
from app.core.permissions import ensure_can_work_incident, ensure_permission
from app.models import Incident, IncidentAssignment, User
from app.repositories.incident_repository import IncidentRepository
from app.repositories.user_repository import UserRepository
from app.schemas.incident import IncidentResolve
from app.services import audit_service, notification_service, sla_service
from app.services.incident_service import add_history
from app.utils.date_utils import utcnow


def _finish(db: Session, incident: Incident, commit: bool) -> Incident:
    if commit:
        db.commit()
        db.refresh(incident)
    else:
        db.flush()
    return incident


# --------------------------------------------------------------------------- assignment
def assign(db: Session, actor: User, incident: Incident, assignee_id: int, comment: str | None = None,
           commit: bool = True) -> Incident:
    if incident.status in ("resolved", "closed"):
        raise ConflictError(f"Cannot assign a {incident.status} incident")
    assignee = UserRepository(db).get(assignee_id)
    if assignee is None:
        raise BadRequestError(f"User {assignee_id} not found")
    if not assignee.is_active:
        raise BadRequestError("Incidents can only be assigned to active users")
    if not assignee.has_permission(P.INCIDENT_WRITE):
        raise BadRequestError("The assignee does not have permission to work on incidents")
    is_manager = actor.has_permission(P.INCIDENT_ASSIGN)
    if not is_manager:
        # analysts may only claim an unassigned incident for themselves
        if not (assignee.id == actor.id and incident.assigned_to_id is None and actor.has_permission(P.INCIDENT_WRITE)):
            raise ForbiddenError("Only security managers can assign incidents to others; analysts may only claim "
                                 "an unassigned incident for themselves")
    if incident.assigned_to_id == assignee.id:
        raise ConflictError("Incident is already assigned to that analyst")
    if incident.is_sensitive and not (
        assignee.has_permission(P.INCIDENT_SENSITIVE) or assignee.id in (incident.created_by_id,)
    ):
        # the assignee gains access to a sensitive record through the assignment itself, so a manager must decide
        ensure_permission(actor, P.INCIDENT_SENSITIVE, "Assigning a sensitive incident requires incident:sensitive")

    now = utcnow()
    previous = incident.assigned_to_id
    for current in db.scalars(IncidentRepository(db).assignments_stmt(incident.id)):
        if current.is_active:
            current.is_active, current.unassigned_at = False, now
    db.add(IncidentAssignment(incident_id=incident.id, assigned_to_id=assignee.id, assigned_by_id=actor.id))
    incident.assigned_to_id = assignee.id
    old_status = incident.status
    if incident.status == "new":
        incident.status = "assigned"
    add_history(db, incident.id, actor.id, "assigned", previous, assignee.id, comment)
    if old_status != incident.status:
        add_history(db, incident.id, actor.id, "status_changed", old_status, incident.status)
    sla_service.mark_acknowledged(db, incident, now)
    audit_service.record(db, user_id=actor.id, action="incident.assign", entity_type="incident",
                         entity_id=incident.id, previous={"assigned_to_id": previous, "status": old_status},
                         new={"assigned_to_id": assignee.id, "status": incident.status})
    notification_service.notify(
        db, assignee.id, NotificationType.INCIDENT_ASSIGNED,
        f"Incident assigned: {incident.reference}",
        f"You were assigned {incident.severity} incident {incident.reference} '{incident.title}'.",
        entity_type="incident", entity_id=incident.id,
    ) if assignee.id != actor.id else None
    return _finish(db, incident, commit)


# --------------------------------------------------------------------------- status
def change_status(db: Session, actor: User, incident: Incident, status: str, comment: str | None) -> Incident:
    ensure_can_work_incident(actor, incident)
    old = incident.status
    if incident.status == "new":
        raise BadRequestError("Assign an analyst before progressing the incident")
    if status == old:
        raise ConflictError(f"Incident is already '{status}'")
    allowed = INCIDENT_STATUS_TRANSITIONS.get(old, set())
    if status not in allowed:
        raise BadRequestError(f"Invalid transition {old} -> {status}", details={"allowed": sorted(allowed)})
    now = utcnow()
    reopening = old == "resolved"
    incident.status = status
    if reopening:
        incident.resolved_at = None
        incident.closure_requested_by_id = incident.closure_requested_at = None
        sla_service.mark_reopened(db, incident, now)
    if status == "investigating":
        sla_service.mark_investigation_started(db, incident, now)
    add_history(db, incident.id, actor.id, "status_changed", old, status, comment)
    audit_service.record(db, user_id=actor.id, action="incident.status_change", entity_type="incident",
                         entity_id=incident.id, previous={"status": old}, new={"status": status, "comment": comment})
    return _finish(db, incident, True)


# --------------------------------------------------------------------------- resolution
def resolve(db: Session, actor: User, incident: Incident, data: IncidentResolve) -> Incident:
    ensure_can_work_incident(actor, incident)
    if incident.status not in INCIDENT_RESOLVABLE_FROM:
        raise BadRequestError(
            f"An incident can only be resolved from {sorted(INCIDENT_RESOLVABLE_FROM)} (current: {incident.status})"
        )
    now = utcnow()
    old = incident.status
    incident.status = "resolved"
    incident.resolved_at = now
    incident.resolution_summary = data.resolution_summary
    incident.resolution_details = data.resolution_details
    incident.root_cause = data.root_cause
    for alert in IncidentRepository(db).linked_alerts(incident.id):
        if alert.status in ("new", "acknowledged", "in_progress"):
            alert.status = "resolved"
    sla_service.mark_resolved(db, incident, now)
    add_history(db, incident.id, actor.id, "resolved", old, "resolved", data.resolution_summary)
    audit_service.record(db, user_id=actor.id, action="incident.resolve", entity_type="incident",
                         entity_id=incident.id, previous={"status": old},
                         new={"status": "resolved", "resolution_summary": data.resolution_summary})
    notification_service.notify_permission_holders(
        db, P.INCIDENT_APPROVE_CLOSURE, NotificationType.INCIDENT_RESOLVED,
        f"Incident resolved: {incident.reference}",
        f"Incident {incident.reference} '{incident.title}' was resolved: {data.resolution_summary}",
        exclude_user_id=actor.id, extra_user_ids=[incident.created_by_id],
        entity_type="incident", entity_id=incident.id,
    )
    return _finish(db, incident, True)


# --------------------------------------------------------------------------- closure approval
def request_closure(db: Session, actor: User, incident: Incident, comment: str | None) -> Incident:
    ensure_can_work_incident(actor, incident)
    if incident.status != "resolved":
        raise BadRequestError("Only resolved incidents can be submitted for closure")
    if incident.closure_requested_at is not None:
        raise ConflictError("Closure has already been requested and is awaiting approval")
    incident.closure_requested_by_id = actor.id
    incident.closure_requested_at = utcnow()
    add_history(db, incident.id, actor.id, "closure_requested", comment=comment)
    audit_service.record(db, user_id=actor.id, action="incident.closure_request", entity_type="incident",
                         entity_id=incident.id, new={"comment": comment})
    notification_service.notify_permission_holders(
        db, P.INCIDENT_APPROVE_CLOSURE, NotificationType.PENDING_APPROVAL,
        f"Closure approval needed: {incident.reference}",
        f"{incident.reference} '{incident.title}' is awaiting closure approval.",
        exclude_user_id=actor.id, entity_type="incident", entity_id=incident.id,
    )
    return _finish(db, incident, True)


def _ensure_pending_closure(incident: Incident) -> None:
    if incident.status != "resolved" or incident.closure_requested_at is None:
        raise BadRequestError("No closure request is pending for this incident")


def _four_eyes(actor: User, incident: Incident) -> None:
    if actor.id == incident.closure_requested_by_id:
        raise ForbiddenError("The closure must be approved by someone other than the person who requested it")


def approve_closure(db: Session, actor: User, incident: Incident, comment: str | None) -> Incident:
    _ensure_pending_closure(incident)
    _four_eyes(actor, incident)
    now = utcnow()
    incident.status = "closed"
    incident.closed_at = now
    incident.closure_approved_by_id = actor.id
    incident.closure_note = comment
    add_history(db, incident.id, actor.id, "closure_approved", "resolved", "closed", comment)
    audit_service.record(db, user_id=actor.id, action="incident.closure_approve", entity_type="incident",
                         entity_id=incident.id, previous={"status": "resolved"},
                         new={"status": "closed", "comment": comment})
    return _finish(db, incident, True)


def reject_closure(db: Session, actor: User, incident: Incident, comment: str | None) -> Incident:
    _ensure_pending_closure(incident)
    _four_eyes(actor, incident)
    if not comment or not comment.strip():
        raise BadRequestError("A comment explaining the rejection is required")
    now = utcnow()
    incident.status = "investigating"
    incident.resolved_at = None
    incident.closure_requested_by_id = incident.closure_requested_at = None
    incident.closure_note = comment
    sla_service.mark_reopened(db, incident, now)
    add_history(db, incident.id, actor.id, "closure_rejected", "resolved", "investigating", comment)
    audit_service.record(db, user_id=actor.id, action="incident.closure_reject", entity_type="incident",
                         entity_id=incident.id, previous={"status": "resolved"},
                         new={"status": "investigating", "comment": comment})
    notification_service.notify(
        db, incident.assigned_to_id, NotificationType.PENDING_APPROVAL,
        f"Closure rejected: {incident.reference}", f"Closure of {incident.reference} was rejected: {comment}",
        entity_type="incident", entity_id=incident.id,
    )
    return _finish(db, incident, True)
