"""Response playbooks. Every action is SIMULATED: completing a step records a simulated result and never touches a
real system."""
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import DbSession, require_any_permission, require_permission
from app.core.constants import P, PlaybookExecutionStatus, PlaybookTaskStatus, SecurityCategory
from app.models import User
from app.repositories.playbook_repository import PlaybookRepository
from app.schemas.common import COMMON_RESPONSES, Page
from app.schemas.playbook_task import (
    ExecutionCancel,
    PlaybookExecute,
    PlaybookExecutionOut,
    PlaybookHistoryOut,
    PlaybookTaskOut,
    TaskAssign,
    TaskComplete,
    TaskReview,
)
from app.schemas.response_playbook import PlaybookCreate, PlaybookOut, PlaybookStepsReplace, PlaybookUpdate
from app.services import playbook_service as svc
from app.utils.pagination import PageParams, page_params
from app.utils.response import make_page

router = APIRouter(prefix="/playbooks", tags=["Response Playbooks"], responses=COMMON_RESPONSES)

Manager = Annotated[User, Depends(require_permission(P.PLAYBOOK_MANAGE))]
Executor = Annotated[User, Depends(require_permission(P.PLAYBOOK_EXECUTE))]
Approver = Annotated[User, Depends(require_permission(P.PLAYBOOK_APPROVE))]
Viewer = Annotated[User, Depends(require_any_permission(P.PLAYBOOK_MANAGE, P.PLAYBOOK_EXECUTE, P.PLAYBOOK_APPROVE,
                                                         P.INCIDENT_READ))]


# --------------------------------------------------------------------------- executions (static paths first)
@router.get("/executions", response_model=Page[PlaybookExecutionOut], summary="List playbook executions")
def list_executions(
    db: DbSession,
    user: Viewer,
    params: Annotated[PageParams, Depends(page_params)],
    incident_id: int | None = None,
    status: PlaybookExecutionStatus | None = None,
):
    repo = PlaybookRepository(db)
    items, total = repo.page(repo.executions_stmt(incident_id=incident_id, status=status, user=user), params)
    return make_page(items, total, params)


@router.get("/executions/{execution_id}", response_model=PlaybookExecutionOut, summary="Get an execution")
def get_execution(execution_id: int, db: DbSession, user: Viewer):
    return svc.get_execution_visible(db, user, execution_id)


@router.post("/executions/{execution_id}/cancel", response_model=PlaybookExecutionOut,
             summary="Cancel a running execution")
def cancel_execution(execution_id: int, data: ExecutionCancel, db: DbSession, user: Executor):
    return svc.cancel_execution(db, user, execution_id, data.reason)


@router.get("/executions/{execution_id}/history", response_model=Page[PlaybookHistoryOut],
            summary="Execution history")
def execution_history(execution_id: int, db: DbSession, user: Viewer,
                      params: Annotated[PageParams, Depends(page_params)]):
    svc.get_execution_visible(db, user, execution_id)
    repo = PlaybookRepository(db)
    items, total = repo.page(repo.history_stmt(execution_id), params)
    return make_page(items, total, params)


# --------------------------------------------------------------------------- tasks
@router.get("/tasks/mine", response_model=Page[PlaybookTaskOut], summary="My playbook tasks")
def my_tasks(db: DbSession, user: Executor, params: Annotated[PageParams, Depends(page_params)],
             status: PlaybookTaskStatus | None = None):
    repo = PlaybookRepository(db)
    items, total = repo.page(repo.my_tasks_stmt(user.id, status), params)
    return make_page(items, total, params)


@router.post("/tasks/{task_id}/assign", response_model=PlaybookTaskOut, summary="Assign a task to an analyst")
def assign_task(task_id: int, data: TaskAssign, db: DbSession, user: Executor):
    return svc.assign_task(db, user, task_id, data.assigned_to_id)


@router.post("/tasks/{task_id}/start", response_model=PlaybookTaskOut, summary="Start a task")
def start_task(task_id: int, db: DbSession, user: Executor):
    return svc.start_task(db, user, task_id)


@router.post("/tasks/{task_id}/complete", response_model=PlaybookTaskOut,
             summary="Complete a task (the action is simulated)")
def complete_task(task_id: int, db: DbSession, user: Executor, data: TaskComplete | None = None):
    """Non-sensitive steps become `completed`; sensitive steps go to `awaiting_approval` and need a different
    user to approve them."""
    return svc.complete_task(db, user, task_id, data.notes if data else None)


@router.post("/tasks/{task_id}/approve", response_model=PlaybookTaskOut, summary="Approve a sensitive step")
def approve_task(task_id: int, db: DbSession, user: Approver, data: TaskReview | None = None):
    return svc.review_task(db, user, task_id, True, data.comment if data else None)


@router.post("/tasks/{task_id}/reject", response_model=PlaybookTaskOut, summary="Reject a sensitive step")
def reject_task(task_id: int, data: TaskReview, db: DbSession, user: Approver):
    return svc.review_task(db, user, task_id, False, data.comment)


# --------------------------------------------------------------------------- playbook definitions
@router.post("", response_model=PlaybookOut, status_code=status.HTTP_201_CREATED, summary="Create a playbook")
def create_playbook(data: PlaybookCreate, db: DbSession, actor: Manager):
    return svc.create(db, actor, data)


@router.get("", response_model=Page[PlaybookOut], summary="List playbooks")
def list_playbooks(
    db: DbSession,
    _: Viewer,
    params: Annotated[PageParams, Depends(page_params)],
    q: str | None = None,
    category: SecurityCategory | None = None,
    is_active: bool | None = Query(None),
):
    repo = PlaybookRepository(db)
    items, total = repo.page(repo.filtered(q=q, category=category, is_active=is_active), params)
    return make_page(items, total, params)


@router.get("/{playbook_id}", response_model=PlaybookOut, summary="Get a playbook")
def get_playbook(playbook_id: int, db: DbSession, _: Viewer):
    return PlaybookRepository(db).require(playbook_id)


@router.patch("/{playbook_id}", response_model=PlaybookOut, summary="Update a playbook")
def update_playbook(playbook_id: int, data: PlaybookUpdate, db: DbSession, actor: Manager):
    return svc.update(db, actor, playbook_id, data)


@router.put("/{playbook_id}/steps", response_model=PlaybookOut, summary="Replace the playbook steps")
def replace_steps(playbook_id: int, data: PlaybookStepsReplace, db: DbSession, actor: Manager):
    """Running executions keep the snapshot of steps they started with."""
    return svc.replace_steps(db, actor, playbook_id, data.steps)


@router.post("/{playbook_id}/execute", response_model=PlaybookExecutionOut, status_code=status.HTTP_201_CREATED,
             summary="Run a playbook against an incident (simulated)")
def execute_playbook(playbook_id: int, data: PlaybookExecute, db: DbSession, actor: Executor):
    return svc.execute(db, actor, playbook_id, data.incident_id, data.assignments)
