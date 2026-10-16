"""Remediation workflow: create -> start -> evidence -> submit -> approve/reject (four-eyes) with full history.

Approving a task marks the finding mitigated on the affected asset(s); when no affected asset remains open the
vulnerability itself becomes `mitigated`.
"""
from datetime import timedelta

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.constants import REMEDIATION_TRANSITIONS, REMEDIATION_UNFINISHED, NotificationType, P
from app.core.exceptions import BadRequestError, ConflictError, ForbiddenError, NotFoundError
from app.models import (
    RemediationApproval,
    RemediationEvidence,
    RemediationHistory,
    RemediationTask,
    User,
)
from app.repositories.remediation_repository import RemediationRepository
from app.repositories.security_team_repository import SecurityTeamRepository
from app.repositories.user_repository import UserRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.schemas.remediation_evidence import RemediationEvidenceCreate
from app.schemas.remediation_task import RemediationCreate, RemediationUpdate
from app.services import audit_service, notification_service, risk_service
from app.utils.date_utils import make_reference, utcnow

AUDIT_FIELDS = ("title", "vulnerability_id", "asset_id", "assigned_team_id", "assigned_to_id", "priority", "status",
                "due_date")
EDITABLE_STATUSES = ("open", "in_progress", "rejected")


def _history(db: Session, task: RemediationTask, user_id: int | None, action: str, old: str | None = None,
             new: str | None = None, comment: str | None = None) -> None:
    db.add(RemediationHistory(task_id=task.id, user_id=user_id, action=action, old_status=old, new_status=new,
                              comment=comment))


def _validate_assignee(db: Session, user_id: int | None) -> User | None:
    if user_id is None:
        return None
    user = UserRepository(db).get(user_id)
    if user is None:
        raise NotFoundError(f"User {user_id} not found")
    if not user.is_active:
        raise BadRequestError("Tasks can only be assigned to active users")
    if not user.has_permission(P.REMEDIATION_WRITE):
        raise BadRequestError("The assignee does not have permission to work on remediation tasks")
    return user


def _validate_team(db: Session, team_id: int | None) -> None:
    if team_id is None:
        return
    team = SecurityTeamRepository(db).require(team_id)
    if not team.is_active:
        raise BadRequestError("The assigned team is inactive")


def can_work(db: Session, user: User, task: RemediationTask) -> bool:
    if not user.has_permission(P.REMEDIATION_WRITE):
        return False
    if user.has_permission(P.REMEDIATION_APPROVE) or user.id in (task.assigned_to_id, task.created_by_id):
        return True
    return bool(task.assigned_team_id and SecurityTeamRepository(db).get_member(task.assigned_team_id, user.id))


def _ensure_can_work(db: Session, user: User, task: RemediationTask) -> None:
    if not can_work(db, user, task):
        raise ForbiddenError("Only the assignee, a member of the assigned team, the creator or an approver may "
                             "work on this task")


def _transition(task: RemediationTask, new_status: str) -> str:
    old = task.status
    if new_status not in REMEDIATION_TRANSITIONS.get(old, set()):
        raise BadRequestError(
            f"Invalid transition {old} -> {new_status}",
            details={"allowed": sorted(REMEDIATION_TRANSITIONS.get(old, set()))},
        )
    task.status = new_status
    return old


# --------------------------------------------------------------------------- create / update
def create(db: Session, actor: User, data: RemediationCreate) -> RemediationTask:
    vrepo = VulnerabilityRepository(db)
    vuln = vrepo.require(data.vulnerability_id)
    if vuln.status in ("closed", "accepted_risk", "mitigated"):
        raise ConflictError(f"Cannot create remediation for a vulnerability that is {vuln.status}")
    if data.asset_id is not None:
        mapping = vrepo.get_mapping(data.asset_id, vuln.id)
        if mapping is None:
            raise BadRequestError("The vulnerability is not mapped to that asset")
        if mapping.status != "open":
            raise ConflictError(f"The finding on that asset is already {mapping.status}")
    if data.due_date <= utcnow():
        raise BadRequestError("due_date must be in the future")
    assignee = _validate_assignee(db, data.assigned_to_id)
    _validate_team(db, data.assigned_team_id)
    task = RemediationTask(
        vulnerability_id=vuln.id,
        asset_id=data.asset_id,
        title=data.title,
        description=data.description,
        assigned_team_id=data.assigned_team_id,
        assigned_to_id=data.assigned_to_id,
        priority=data.priority,
        due_date=data.due_date,
        status="open",
        created_by_id=actor.id,
    )
    RemediationRepository(db).add(task)
    task.reference = make_reference("REM", task.id)
    _history(db, task, actor.id, "created", None, "open")
    if vuln.status in ("open", "under_review"):
        vrepo.change_status(vuln, "in_remediation", actor.id, f"Remediation task {task.reference} created")
    audit_service.record(db, user_id=actor.id, action="remediation.create", entity_type="remediation_task",
                         entity_id=task.id, new=audit_service.snapshot(task, AUDIT_FIELDS))
    if assignee and assignee.id != actor.id:
        notification_service.notify(
            db, assignee.id, NotificationType.REMEDIATION_ASSIGNED, f"Remediation task assigned: {task.reference}",
            f"You were assigned '{task.title}' ({task.priority}); due {task.due_date:%Y-%m-%d %H:%M} UTC.",
            entity_type="remediation_task", entity_id=task.id,
        )
    db.commit()
    db.refresh(task)
    return task


def update(db: Session, actor: User, task: RemediationTask, data: RemediationUpdate) -> RemediationTask:
    _ensure_can_work(db, actor, task)
    if task.status not in EDITABLE_STATUSES:
        raise ConflictError(f"Tasks in status '{task.status}' cannot be edited")
    values = data.model_dump(exclude_unset=True)
    for key in ("title", "priority", "due_date"):
        if key in values and values[key] is None:
            raise BadRequestError(f"{key} cannot be cleared")
    if values.get("due_date") is not None and values["due_date"] <= utcnow():
        raise BadRequestError("due_date must be in the future")
    if "assigned_to_id" in values:
        _validate_assignee(db, values["assigned_to_id"])
    if "assigned_team_id" in values:
        _validate_team(db, values["assigned_team_id"])
    before = audit_service.snapshot(task, AUDIT_FIELDS)
    for key, value in values.items():
        setattr(task, key, value)
    prev, new = audit_service.changes(before, audit_service.snapshot(task, AUDIT_FIELDS))
    if new:
        _history(db, task, actor.id, "updated", comment=", ".join(sorted(new)))
        audit_service.record(db, user_id=actor.id, action="remediation.update", entity_type="remediation_task",
                             entity_id=task.id, previous=prev, new=new)
        if "assigned_to_id" in new and task.assigned_to_id and task.assigned_to_id != actor.id:
            notification_service.notify(
                db, task.assigned_to_id, NotificationType.REMEDIATION_ASSIGNED,
                f"Remediation task assigned: {task.reference}", f"You were assigned '{task.title}'.",
                entity_type="remediation_task", entity_id=task.id,
            )
    db.commit()
    db.refresh(task)
    return task


# --------------------------------------------------------------------------- workflow
def start(db: Session, actor: User, task: RemediationTask, comment: str | None) -> RemediationTask:
    _ensure_can_work(db, actor, task)
    old = _transition(task, "in_progress")
    _history(db, task, actor.id, "started" if old == "open" else "resumed", old, "in_progress", comment)
    audit_service.record(db, user_id=actor.id, action="remediation.status_change", entity_type="remediation_task",
                         entity_id=task.id, previous={"status": old}, new={"status": "in_progress"})
    db.commit()
    return task


def add_evidence(db: Session, actor: User, task: RemediationTask, data: RemediationEvidenceCreate) -> RemediationEvidence:
    _ensure_can_work(db, actor, task)
    if task.status != "in_progress":
        raise ConflictError("Evidence can only be recorded while the task is in progress")
    evidence = RemediationEvidence(task_id=task.id, description=data.description, reference_type=data.reference_type,
                                   reference_url=data.reference_url, added_by_id=actor.id)
    db.add(evidence)
    _history(db, task, actor.id, "evidence_added", comment=data.description[:200])
    audit_service.record(db, user_id=actor.id, action="remediation.evidence_add", entity_type="remediation_task",
                         entity_id=task.id, new={"reference_type": data.reference_type,
                                                 "reference_url": data.reference_url})
    db.commit()
    db.refresh(evidence)
    return evidence


def submit(db: Session, actor: User, task: RemediationTask, comment: str | None) -> RemediationTask:
    _ensure_can_work(db, actor, task)
    if task.status != "in_progress":
        raise ConflictError("Only tasks that are in progress can be submitted for approval")
    if RemediationRepository(db).evidence_count(task.id) == 0:
        raise BadRequestError("Record at least one piece of remediation evidence before submitting for approval")
    old = _transition(task, "pending_approval")
    task.submitted_by_id, task.submitted_at = actor.id, utcnow()
    _history(db, task, actor.id, "submitted", old, "pending_approval", comment)
    audit_service.record(db, user_id=actor.id, action="remediation.submit", entity_type="remediation_task",
                         entity_id=task.id, previous={"status": old}, new={"status": "pending_approval"})
    notification_service.notify_permission_holders(
        db, P.REMEDIATION_APPROVE, NotificationType.PENDING_APPROVAL,
        f"Remediation awaiting approval: {task.reference}", f"'{task.title}' was submitted for approval.",
        exclude_user_id=actor.id, entity_type="remediation_task", entity_id=task.id,
    )
    db.commit()
    return task


def _mark_mitigated(db: Session, actor: User, task: RemediationTask) -> None:
    vrepo = VulnerabilityRepository(db)
    vuln = vrepo.require(task.vulnerability_id)
    now = utcnow()
    for mapping in vrepo.mappings_for_vulnerability(vuln.id):
        if mapping.status == "open" and (task.asset_id is None or mapping.asset_id == task.asset_id):
            mapping.status, mapping.resolved_at = "mitigated", now
    db.flush()
    remaining = [m for m in vrepo.mappings_for_vulnerability(vuln.id)]
    if remaining and not any(m.status == "open" for m in remaining) and vuln.status in (
        "open", "under_review", "in_remediation"
    ):
        vrepo.change_status(vuln, "mitigated", actor.id, f"Remediation {task.reference} approved")
    risk_service.recalculate(db, actor, vulnerability_id=vuln.id)


def decide(db: Session, actor: User, task: RemediationTask, approve: bool, comments: str | None) -> RemediationTask:
    if task.status != "pending_approval":
        raise ConflictError("Only tasks pending approval can be approved or rejected")
    if actor.id == task.submitted_by_id:
        raise ForbiddenError("A task must be approved by someone other than the person who submitted it")
    if not approve and not (comments and comments.strip()):
        raise BadRequestError("Comments explaining the rejection are required")
    new_status = "approved" if approve else "rejected"
    old = _transition(task, new_status)
    db.add(RemediationApproval(task_id=task.id, approver_id=actor.id, decision=new_status, comments=comments))
    _history(db, task, actor.id, new_status, old, new_status, comments)
    if approve:
        task.approved_at = utcnow()
        _mark_mitigated(db, actor, task)
    audit_service.record(
        db, user_id=actor.id, action="remediation.approve" if approve else "remediation.reject",
        entity_type="remediation_task", entity_id=task.id, previous={"status": old},
        new={"status": new_status, "comments": comments},
    )
    notification_service.notify_many(
        db, [task.submitted_by_id, task.assigned_to_id], NotificationType.REMEDIATION_DECISION,
        f"Remediation {new_status}: {task.reference}",
        f"'{task.title}' was {new_status}" + (f": {comments}" if comments else "."),
        exclude_user_id=actor.id, entity_type="remediation_task", entity_id=task.id,
    )
    db.commit()
    db.refresh(task)
    return task


def cancel(db: Session, actor: User, task: RemediationTask, reason: str) -> RemediationTask:
    if not (actor.has_permission(P.REMEDIATION_APPROVE) or actor.id == task.created_by_id):
        raise ForbiddenError("Only the creator or an approver can cancel a remediation task")
    old = _transition(task, "cancelled")
    _history(db, task, actor.id, "cancelled", old, "cancelled", reason)
    audit_service.record(db, user_id=actor.id, action="remediation.cancel", entity_type="remediation_task",
                         entity_id=task.id, previous={"status": old}, new={"status": "cancelled", "reason": reason})
    db.commit()
    return task


# --------------------------------------------------------------------------- deadline monitoring
def notify_deadlines(db: Session) -> dict[str, int]:
    """Create 'due soon' (assignee) and 'overdue' (assignee + approvers) notifications. Caller commits.
    Idempotent: nothing new is created while an unread notification with the same title exists."""
    now = utcnow()
    soon = now + timedelta(hours=settings.REMEDIATION_DUE_SOON_HOURS)
    due_soon = overdue = 0
    stmt = RemediationRepository(db).filtered().where(
        RemediationTask.status.in_(REMEDIATION_UNFINISHED), RemediationTask.due_date <= soon
    )
    for task in db.scalars(stmt):
        is_overdue = task.due_date < now
        label = "overdue" if is_overdue else "due soon"
        title = f"Remediation {label}: {task.reference}"
        message = f"'{task.title}' is {label} (due {task.due_date:%Y-%m-%d %H:%M} UTC, status {task.status})."
        common = dict(entity_type="remediation_task", entity_id=task.id, dedupe=True, dedupe_on_title=True)
        if is_overdue:
            overdue += notification_service.notify_permission_holders(
                db, P.REMEDIATION_APPROVE, NotificationType.REMEDIATION_DEADLINE, title, message,
                extra_user_ids=[task.assigned_to_id], **common,
            )
        else:
            due_soon += notification_service.notify_many(
                db, [task.assigned_to_id], NotificationType.REMEDIATION_DEADLINE, title, message, **common
            )
    return {"due_soon_notifications": due_soon, "overdue_notifications": overdue}
