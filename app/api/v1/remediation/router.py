from datetime import date
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import DbSession, require_permission
from app.core.constants import P, Priority, RemediationStatus
from app.models import RemediationTask, User
from app.repositories import remediation_repository
from app.repositories.remediation_repository import RemediationRepository
from app.schemas.common import COMMON_RESPONSES, Page
from app.schemas.remediation_approval import RemediationApprovalOut
from app.schemas.remediation_evidence import RemediationEvidenceCreate, RemediationEvidenceOut
from app.schemas.remediation_task import (
    CancelBody,
    CommentBody,
    DecisionBody,
    RemediationCreate,
    RemediationHistoryOut,
    RemediationOut,
    RemediationUpdate,
)
from app.services import remediation_service
from app.utils.pagination import PageParams, page_params
from app.utils.response import make_page
from app.utils.sorting import apply_sorting

router = APIRouter(prefix="/remediation", tags=["Remediation"], responses=COMMON_RESPONSES)

Reader = Annotated[User, Depends(require_permission(P.REMEDIATION_READ))]
Writer = Annotated[User, Depends(require_permission(P.REMEDIATION_WRITE))]
Approver = Annotated[User, Depends(require_permission(P.REMEDIATION_APPROVE))]


def _task(db, task_id: int) -> RemediationTask:
    return RemediationRepository(db).require(task_id)


@router.post("/tasks", response_model=RemediationOut, status_code=status.HTTP_201_CREATED,
             summary="Create a remediation task for a vulnerability")
def create_task(data: RemediationCreate, db: DbSession, actor: Writer):
    return remediation_service.create(db, actor, data)


@router.get("/tasks", response_model=Page[RemediationOut], summary="Search and filter remediation tasks")
def list_tasks(
    db: DbSession,
    _: Reader,
    params: Annotated[PageParams, Depends(page_params)],
    q: str | None = Query(None, description="Search title, reference or description"),
    status: Annotated[list[RemediationStatus] | None, Query()] = None,
    priority: Annotated[list[Priority] | None, Query()] = None,
    vulnerability_id: int | None = None,
    asset_id: int | None = None,
    team_id: int | None = None,
    assigned_to_id: int | None = None,
    overdue: bool | None = None,
    due_from: date | None = None,
    due_to: date | None = None,
    sort_by: str | None = Query(None, description="due_date | created_at | priority | status | title"),
    sort_order: Literal["asc", "desc"] = "asc",
):
    repo = RemediationRepository(db)
    stmt = repo.filtered(q=q, status=status, priority=priority, vulnerability_id=vulnerability_id,
                         asset_id=asset_id, team_id=team_id, assigned_to_id=assigned_to_id, overdue=overdue,
                         due_from=due_from, due_to=due_to)
    stmt = apply_sorting(stmt, remediation_repository.SORT_MAP, sort_by, sort_order, "due_date",
                         tiebreak=RemediationTask.id)
    items, total = repo.page(stmt, params)
    return make_page(items, total, params)


@router.get("/tasks/{task_id}", response_model=RemediationOut, summary="Get a remediation task")
def get_task(task_id: int, db: DbSession, _: Reader):
    return _task(db, task_id)


@router.patch("/tasks/{task_id}", response_model=RemediationOut, summary="Update a remediation task")
def update_task(task_id: int, data: RemediationUpdate, db: DbSession, actor: Writer):
    return remediation_service.update(db, actor, _task(db, task_id), data)


@router.post("/tasks/{task_id}/start", response_model=RemediationOut, summary="Start work on the task")
def start_task(task_id: int, db: DbSession, actor: Writer, data: CommentBody | None = None):
    return remediation_service.start(db, actor, _task(db, task_id), data.comment if data else None)


@router.post("/tasks/{task_id}/evidence", response_model=RemediationEvidenceOut,
             status_code=status.HTTP_201_CREATED, summary="Attach evidence of the fix")
def add_evidence(task_id: int, data: RemediationEvidenceCreate, db: DbSession, actor: Writer):
    return remediation_service.add_evidence(db, actor, _task(db, task_id), data)


@router.get("/tasks/{task_id}/evidence", response_model=Page[RemediationEvidenceOut], summary="Task evidence")
def list_evidence(task_id: int, db: DbSession, _: Reader, params: Annotated[PageParams, Depends(page_params)]):
    repo = RemediationRepository(db)
    repo.require(task_id)
    items, total = repo.page(repo.evidence_stmt(task_id), params)
    return make_page(items, total, params)


@router.post("/tasks/{task_id}/submit", response_model=RemediationOut, summary="Submit the fix for approval")
def submit_task(task_id: int, db: DbSession, actor: Writer, data: CommentBody | None = None):
    """Requires at least one piece of evidence."""
    return remediation_service.submit(db, actor, _task(db, task_id), data.comment if data else None)


@router.post("/tasks/{task_id}/approve", response_model=RemediationOut, summary="Approve the remediation")
def approve_task(task_id: int, db: DbSession, actor: Approver, data: DecisionBody | None = None):
    """Four-eyes rule: the approver must differ from the submitter. Approval marks the vulnerability mapping
    mitigated and re-calculates risk."""
    return remediation_service.decide(db, actor, _task(db, task_id), True, data.comments if data else None)


@router.post("/tasks/{task_id}/reject", response_model=RemediationOut, summary="Reject the remediation")
def reject_task(task_id: int, data: DecisionBody, db: DbSession, actor: Approver):
    """`comments` is required when rejecting; the task goes back to the assignee."""
    return remediation_service.decide(db, actor, _task(db, task_id), False, data.comments)


@router.post("/tasks/{task_id}/cancel", response_model=RemediationOut, summary="Cancel the task")
def cancel_task(task_id: int, data: CancelBody, db: DbSession, actor: Writer):
    return remediation_service.cancel(db, actor, _task(db, task_id), data.reason)


@router.get("/tasks/{task_id}/history", response_model=Page[RemediationHistoryOut], summary="Task history")
def task_history(task_id: int, db: DbSession, _: Reader, params: Annotated[PageParams, Depends(page_params)]):
    repo = RemediationRepository(db)
    repo.require(task_id)
    items, total = repo.page(repo.history_stmt(task_id), params)
    return make_page(items, total, params)


@router.get("/tasks/{task_id}/approvals", response_model=Page[RemediationApprovalOut],
            summary="Approval decisions")
def task_approvals(task_id: int, db: DbSession, _: Reader, params: Annotated[PageParams, Depends(page_params)]):
    repo = RemediationRepository(db)
    repo.require(task_id)
    items, total = repo.page(repo.approvals_stmt(task_id), params)
    return make_page(items, total, params)
