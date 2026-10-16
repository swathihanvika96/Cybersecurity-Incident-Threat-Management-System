from datetime import date

from sqlalchemy import Select, func, select

from app.core.constants import REMEDIATION_UNFINISHED
from app.models import (
    RemediationApproval,
    RemediationEvidence,
    RemediationHistory,
    RemediationTask,
)
from app.repositories.base import BaseRepository
from app.utils.date_utils import end_exclusive, start_of_day, utcnow
from app.utils.filtering import text_search, validate_date_range
from app.utils.sorting import rank_case

PRIORITY_RANK = {"low": 1, "medium": 2, "high": 3, "urgent": 4}

SORT_MAP = {
    "due_date": RemediationTask.due_date,
    "created_at": RemediationTask.created_at,
    "priority": rank_case(RemediationTask.priority, PRIORITY_RANK),
    "status": RemediationTask.status,
    "title": RemediationTask.title,
}


class RemediationRepository(BaseRepository[RemediationTask]):
    model = RemediationTask
    label = "Remediation task"

    def filtered(
        self,
        *,
        q: str | None = None,
        status: list[str] | None = None,
        priority: list[str] | None = None,
        vulnerability_id: int | None = None,
        asset_id: int | None = None,
        team_id: int | None = None,
        assigned_to_id: int | None = None,
        overdue: bool | None = None,
        due_from: date | None = None,
        due_to: date | None = None,
    ) -> Select:
        stmt = text_search(select(RemediationTask), q, RemediationTask.title, RemediationTask.reference,
                           RemediationTask.description)
        if status:
            stmt = stmt.where(RemediationTask.status.in_(status))
        if priority:
            stmt = stmt.where(RemediationTask.priority.in_(priority))
        if vulnerability_id is not None:
            stmt = stmt.where(RemediationTask.vulnerability_id == vulnerability_id)
        if asset_id is not None:
            stmt = stmt.where(RemediationTask.asset_id == asset_id)
        if team_id is not None:
            stmt = stmt.where(RemediationTask.assigned_team_id == team_id)
        if assigned_to_id is not None:
            stmt = stmt.where(RemediationTask.assigned_to_id == assigned_to_id)
        overdue_clause = (RemediationTask.due_date < utcnow()) & RemediationTask.status.in_(REMEDIATION_UNFINISHED)
        if overdue is True:
            stmt = stmt.where(overdue_clause)
        elif overdue is False:
            stmt = stmt.where(~overdue_clause)
        validate_date_range(due_from, due_to)
        if due_from:
            stmt = stmt.where(RemediationTask.due_date >= start_of_day(due_from))
        if due_to:
            stmt = stmt.where(RemediationTask.due_date < end_exclusive(due_to))
        return stmt

    def evidence_stmt(self, task_id: int) -> Select:
        return select(RemediationEvidence).where(RemediationEvidence.task_id == task_id).order_by(
            RemediationEvidence.added_at.asc(), RemediationEvidence.id.asc()
        )

    def evidence_count(self, task_id: int) -> int:
        return self.db.scalar(select(func.count(RemediationEvidence.id)).where(RemediationEvidence.task_id == task_id)) or 0

    def history_stmt(self, task_id: int) -> Select:
        return select(RemediationHistory).where(RemediationHistory.task_id == task_id).order_by(
            RemediationHistory.timestamp.asc(), RemediationHistory.id.asc()
        )

    def approvals_stmt(self, task_id: int) -> Select:
        return select(RemediationApproval).where(RemediationApproval.task_id == task_id).order_by(
            RemediationApproval.decided_at.asc(), RemediationApproval.id.asc()
        )

    def tasks_for_vulnerability(self, vulnerability_id: int) -> list[RemediationTask]:
        return list(self.db.scalars(select(RemediationTask).where(RemediationTask.vulnerability_id == vulnerability_id)))

    def has_approved_task(self, vulnerability_id: int) -> bool:
        return (
            self.db.scalar(
                select(func.count(RemediationTask.id)).where(
                    RemediationTask.vulnerability_id == vulnerability_id, RemediationTask.status == "approved"
                )
            )
            or 0
        ) > 0
