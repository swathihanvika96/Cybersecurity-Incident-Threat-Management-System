"""Response playbooks and their execution.

SIMULATED ACTIONS ONLY: completing a task records a result string such as "[SIMULATED] ... no change was made"; no
code in this platform connects to, scans or modifies a real system.

Rules
* tasks are completed strictly in step order (a task cannot be completed before all earlier steps are done)
* steps flagged `is_sensitive` need approval from a user with playbook:approve who is not the person who
  completed the task (four-eyes)
* every action is written to the playbook history (response history) and to the audit log where it matters
"""
from sqlalchemy.orm import Session

from app.core.constants import NotificationType, P
from app.core.exceptions import BadRequestError, ConflictError, ForbiddenError, NotFoundError
from app.core.permissions import ensure_can_view_incident
from app.models import (
    PlaybookExecution,
    PlaybookHistory,
    PlaybookStep,
    PlaybookTask,
    ResponsePlaybook,
    User,
)
from app.repositories.incident_repository import IncidentRepository
from app.repositories.playbook_repository import PlaybookRepository
from app.repositories.user_repository import UserRepository
from app.schemas.response_playbook import PlaybookCreate, PlaybookStepIn, PlaybookUpdate
from app.services import audit_service, notification_service
from app.utils.date_utils import utcnow


def _history(db: Session, execution_id: int, user_id: int | None, action: str, task_id: int | None = None,
             details: str | None = None) -> None:
    db.add(PlaybookHistory(execution_id=execution_id, task_id=task_id, user_id=user_id, action=action,
                           details=details))


def simulated_result(task: PlaybookTask) -> str:
    action = task.simulated_action or task.title
    return f"[SIMULATED] {action} - recorded only; no change was made to any real system."


# --------------------------------------------------------------------------- playbook definitions
def _build_steps(steps: list[PlaybookStepIn]) -> list[PlaybookStep]:
    return [
        PlaybookStep(step_order=i, title=s.title, description=s.description, step_type=s.step_type,
                     is_sensitive=s.is_sensitive, simulated_action=s.simulated_action)
        for i, s in enumerate(steps, start=1)
    ]


def create(db: Session, actor: User, data: PlaybookCreate) -> ResponsePlaybook:
    repo = PlaybookRepository(db)
    if repo.get_by_name(data.name):
        raise ConflictError("A playbook with this name already exists")
    playbook = ResponsePlaybook(name=data.name, description=data.description,
                                incident_category=data.incident_category, created_by_id=actor.id)
    playbook.steps = _build_steps(data.steps)
    repo.add(playbook)
    audit_service.record(db, user_id=actor.id, action="playbook.create", entity_type="playbook",
                         entity_id=playbook.id, new={"name": data.name, "steps": len(data.steps)})
    db.commit()
    db.refresh(playbook)
    return playbook


def update(db: Session, actor: User, playbook_id: int, data: PlaybookUpdate) -> ResponsePlaybook:
    repo = PlaybookRepository(db)
    playbook = repo.require(playbook_id)
    values = data.model_dump(exclude_unset=True)
    if "name" in values and (values["name"] is None):
        raise BadRequestError("name cannot be cleared")
    if "name" in values and values["name"] != playbook.name and repo.get_by_name(values["name"]):
        raise ConflictError("A playbook with this name already exists")
    previous = {k: getattr(playbook, k) for k in values}
    for key, value in values.items():
        setattr(playbook, key, value)
    audit_service.record(db, user_id=actor.id, action="playbook.update", entity_type="playbook",
                         entity_id=playbook.id, previous=previous, new=values)
    db.commit()
    db.refresh(playbook)
    return playbook


def replace_steps(db: Session, actor: User, playbook_id: int, steps: list[PlaybookStepIn]) -> ResponsePlaybook:
    playbook = PlaybookRepository(db).require(playbook_id)
    previous = len(playbook.steps)
    playbook.steps.clear()
    db.flush()
    playbook.steps.extend(_build_steps(steps))
    audit_service.record(db, user_id=actor.id, action="playbook.steps_replace", entity_type="playbook",
                         entity_id=playbook.id, previous={"steps": previous}, new={"steps": len(steps)})
    db.commit()
    db.refresh(playbook)
    return playbook


# --------------------------------------------------------------------------- execution
def _executor(db: Session, user_id: int) -> User:
    user = UserRepository(db).get(user_id)
    if user is None:
        raise NotFoundError(f"User {user_id} not found")
    if not user.is_active or not user.has_permission(P.PLAYBOOK_EXECUTE):
        raise BadRequestError(f"User {user_id} cannot be assigned playbook tasks")
    return user


def execute(db: Session, actor: User, playbook_id: int, incident_id: int, assignments: list) -> PlaybookExecution:
    repo = PlaybookRepository(db)
    playbook = repo.require(playbook_id)
    if not playbook.is_active:
        raise ConflictError("Playbook is inactive")
    incident = IncidentRepository(db).require(incident_id)
    ensure_can_view_incident(actor, incident)
    if incident.status in ("resolved", "closed"):
        raise ConflictError(f"Cannot run a playbook on a {incident.status} incident")
    if playbook.incident_category and playbook.incident_category != incident.category:
        raise BadRequestError(
            f"Playbook '{playbook.name}' is for '{playbook.incident_category}' incidents, "
            f"this incident is '{incident.category}'"
        )
    running = [e for e in db.scalars(repo.executions_stmt(incident_id=incident.id, status="running"))
               if e.playbook_id == playbook.id]
    if running:
        raise ConflictError(f"This playbook is already running on the incident (execution {running[0].id})")
    by_step: dict[int, int] = {}
    for item in assignments:
        if item.step_order > len(playbook.steps):
            raise BadRequestError(f"Step {item.step_order} does not exist in this playbook")
        by_step[item.step_order] = item.user_id
    for uid in set(by_step.values()):
        _executor(db, uid)
    default_user = incident.assigned_to_id

    execution = PlaybookExecution(playbook_id=playbook.id, incident_id=incident.id, started_by_id=actor.id)
    for step in playbook.steps:
        execution.tasks.append(
            PlaybookTask(
                step_id=step.id, step_order=step.step_order, title=step.title, description=step.description,
                step_type=step.step_type, requires_approval=step.is_sensitive,
                simulated_action=step.simulated_action,
                assigned_to_id=by_step.get(step.step_order, default_user),
            )
        )
    repo.add(execution)
    _history(db, execution.id, actor.id, "execution_started",
             details=f"Playbook '{playbook.name}' started on {incident.reference}")
    audit_service.record(db, user_id=actor.id, action="playbook.execute", entity_type="playbook_execution",
                         entity_id=execution.id, new={"playbook_id": playbook.id, "incident_id": incident.id})
    for uid in {t.assigned_to_id for t in execution.tasks if t.assigned_to_id and t.assigned_to_id != actor.id}:
        notification_service.notify(
            db, uid, NotificationType.PLAYBOOK_TASK_ASSIGNED, f"Playbook tasks assigned: {incident.reference}",
            f"You have response tasks from playbook '{playbook.name}' on incident {incident.reference}.",
            entity_type="playbook_execution", entity_id=execution.id, dedupe=True,
        )
    db.commit()
    db.refresh(execution)
    return execution


def _task_and_execution(db: Session, task_id: int) -> tuple[PlaybookTask, PlaybookExecution]:
    task = PlaybookRepository(db).get_task(task_id)
    if task is None:
        raise NotFoundError(f"Playbook task {task_id} not found")
    return task, PlaybookRepository(db).get_execution(task.execution_id)


def _ensure_running(execution: PlaybookExecution) -> None:
    if execution.status != "running":
        raise ConflictError(f"Execution is {execution.status}")


def _ensure_incident_access(db: Session, actor: User, execution: PlaybookExecution) -> None:
    ensure_can_view_incident(actor, IncidentRepository(db).require(execution.incident_id))


def assign_task(db: Session, actor: User, task_id: int, user_id: int) -> PlaybookTask:
    task, execution = _task_and_execution(db, task_id)
    _ensure_running(execution)
    _ensure_incident_access(db, actor, execution)
    if not (actor.has_permission(P.INCIDENT_ASSIGN) or actor.id == execution.started_by_id):
        raise ForbiddenError("Only the person who started the execution or a security manager can assign tasks")
    if task.status == "completed":
        raise ConflictError("Task is already completed")
    _executor(db, user_id)
    previous = task.assigned_to_id
    task.assigned_to_id = user_id
    _history(db, execution.id, actor.id, "task_assigned", task.id, f"{previous} -> {user_id}")
    if user_id != actor.id:
        notification_service.notify(
            db, user_id, NotificationType.PLAYBOOK_TASK_ASSIGNED, f"Playbook task assigned: {task.title}",
            f"You were assigned step {task.step_order} '{task.title}'.",
            entity_type="playbook_task", entity_id=task.id,
        )
    db.commit()
    return task


def _ensure_assignee(actor: User, task: PlaybookTask) -> None:
    if actor.id != task.assigned_to_id and not actor.has_permission(P.INCIDENT_ASSIGN):
        raise ForbiddenError("Only the assigned analyst (or a security manager) can work on this task")


def start_task(db: Session, actor: User, task_id: int) -> PlaybookTask:
    task, execution = _task_and_execution(db, task_id)
    _ensure_running(execution)
    _ensure_incident_access(db, actor, execution)
    _ensure_assignee(actor, task)
    if task.status not in ("pending", "rejected"):
        raise ConflictError(f"Task is {task.status}")
    task.status = "in_progress"
    _history(db, execution.id, actor.id, "task_started", task.id)
    db.commit()
    return task


def _check_order(execution: PlaybookExecution, task: PlaybookTask) -> None:
    blocking = [t.step_order for t in execution.tasks if t.step_order < task.step_order and t.status != "completed"]
    if blocking:
        raise ConflictError(f"Complete the earlier step(s) first: {blocking}")


def _finish_execution_if_done(db: Session, execution: PlaybookExecution, actor: User) -> None:
    if all(t.status == "completed" for t in execution.tasks):
        execution.status, execution.completed_at = "completed", utcnow()
        _history(db, execution.id, actor.id, "execution_completed")


def complete_task(db: Session, actor: User, task_id: int, notes: str | None) -> PlaybookTask:
    task, execution = _task_and_execution(db, task_id)
    _ensure_running(execution)
    _ensure_incident_access(db, actor, execution)
    _ensure_assignee(actor, task)
    if task.status in ("completed", "awaiting_approval"):
        raise ConflictError(f"Task is already {task.status.replace('_', ' ')}")
    _check_order(execution, task)
    task.completion_notes, task.completed_by_id, task.completed_at = notes, actor.id, utcnow()
    if task.requires_approval:
        task.status = "awaiting_approval"
        _history(db, execution.id, actor.id, "task_submitted_for_approval", task.id, notes)
        notification_service.notify_permission_holders(
            db, P.PLAYBOOK_APPROVE, NotificationType.PENDING_APPROVAL,
            f"Sensitive playbook action awaiting approval: {task.title}",
            f"Step {task.step_order} '{task.title}' needs approval before the playbook can continue.",
            exclude_user_id=actor.id, entity_type="playbook_task", entity_id=task.id, dedupe=True,
        )
    else:
        task.status, task.simulated_result = "completed", simulated_result(task)
        _history(db, execution.id, actor.id, "task_completed", task.id, task.simulated_result)
        _finish_execution_if_done(db, execution, actor)
    db.commit()
    db.refresh(task)
    return task


def review_task(db: Session, actor: User, task_id: int, approve: bool, comment: str | None) -> PlaybookTask:
    task, execution = _task_and_execution(db, task_id)
    _ensure_running(execution)
    if task.status != "awaiting_approval":
        raise ConflictError("Task is not awaiting approval")
    if actor.id == task.completed_by_id:
        raise ForbiddenError("A sensitive action must be approved by someone other than who performed it")
    if not approve and not (comment and comment.strip()):
        raise BadRequestError("A comment explaining the rejection is required")
    task.approved_by_id, task.approved_at, task.review_comment = actor.id, utcnow(), comment
    if approve:
        task.status, task.simulated_result = "completed", simulated_result(task)
        _history(db, execution.id, actor.id, "task_approved", task.id, task.simulated_result)
        _finish_execution_if_done(db, execution, actor)
    else:
        task.status = "rejected"
        _history(db, execution.id, actor.id, "task_rejected", task.id, comment)
    audit_service.record(
        db, user_id=actor.id, action="playbook.task_approve" if approve else "playbook.task_reject",
        entity_type="playbook_task", entity_id=task.id, previous={"status": "awaiting_approval"},
        new={"status": task.status, "comment": comment},
    )
    notification_service.notify(
        db, task.completed_by_id, NotificationType.PENDING_APPROVAL,
        f"Playbook action {'approved' if approve else 'rejected'}: {task.title}",
        comment or f"Your sensitive action was {'approved' if approve else 'rejected'}.",
        entity_type="playbook_task", entity_id=task.id,
    )
    db.commit()
    db.refresh(task)
    return task


def get_execution_visible(db: Session, actor: User, execution_id: int) -> PlaybookExecution:
    execution = PlaybookRepository(db).get_execution(execution_id)
    if execution is None:
        raise NotFoundError(f"Execution {execution_id} not found")
    _ensure_incident_access(db, actor, execution)
    return execution


def cancel_execution(db: Session, actor: User, execution_id: int, reason: str) -> PlaybookExecution:
    execution = get_execution_visible(db, actor, execution_id)
    _ensure_running(execution)
    if not (actor.has_permission(P.PLAYBOOK_MANAGE) or actor.id == execution.started_by_id):
        raise ForbiddenError("Only the starter or a playbook manager can cancel an execution")
    execution.status, execution.completed_at, execution.cancel_reason = "cancelled", utcnow(), reason
    _history(db, execution.id, actor.id, "execution_cancelled", details=reason)
    audit_service.record(db, user_id=actor.id, action="playbook.cancel", entity_type="playbook_execution",
                         entity_id=execution.id, new={"reason": reason})
    db.commit()
    db.refresh(execution)
    return execution
