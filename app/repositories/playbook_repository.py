from sqlalchemy import Select, select

from app.core.permissions import incident_visibility_clause
from app.models import Incident, PlaybookExecution, PlaybookHistory, PlaybookTask, ResponsePlaybook
from app.repositories.base import BaseRepository
from app.utils.filtering import text_search


class PlaybookRepository(BaseRepository[ResponsePlaybook]):
    model = ResponsePlaybook
    label = "Playbook"

    def get_by_name(self, name: str) -> ResponsePlaybook | None:
        return self.db.scalar(select(ResponsePlaybook).where(ResponsePlaybook.name == name))

    def filtered(
        self, *, q: str | None = None, category: str | None = None, is_active: bool | None = None
    ) -> Select:
        stmt = text_search(select(ResponsePlaybook), q, ResponsePlaybook.name, ResponsePlaybook.description)
        if category:
            stmt = stmt.where(ResponsePlaybook.incident_category == category)
        if is_active is not None:
            stmt = stmt.where(ResponsePlaybook.is_active.is_(is_active))
        return stmt.order_by(ResponsePlaybook.name)

    def executions_stmt(self, *, incident_id: int | None = None, status: str | None = None, user=None) -> Select:
        stmt = select(PlaybookExecution).order_by(PlaybookExecution.started_at.desc(), PlaybookExecution.id.desc())
        if user is not None:  # sensitive-incident rules also apply to the executions run against them
            stmt = stmt.where(
                PlaybookExecution.incident_id.in_(select(Incident.id).where(incident_visibility_clause(user)))
            )
        if incident_id is not None:
            stmt = stmt.where(PlaybookExecution.incident_id == incident_id)
        if status:
            stmt = stmt.where(PlaybookExecution.status == status)
        return stmt

    def get_execution(self, execution_id: int) -> PlaybookExecution | None:
        return self.db.get(PlaybookExecution, execution_id)

    def get_task(self, task_id: int) -> PlaybookTask | None:
        return self.db.get(PlaybookTask, task_id)

    def my_tasks_stmt(self, user_id: int, status: str | None = None) -> Select:
        stmt = (
            select(PlaybookTask)
            .join(PlaybookExecution, PlaybookExecution.id == PlaybookTask.execution_id)
            .where(PlaybookTask.assigned_to_id == user_id, PlaybookExecution.status == "running")
            .order_by(PlaybookTask.execution_id, PlaybookTask.step_order)
        )
        if status:
            stmt = stmt.where(PlaybookTask.status == status)
        return stmt

    def history_stmt(self, execution_id: int) -> Select:
        return (
            select(PlaybookHistory)
            .where(PlaybookHistory.execution_id == execution_id)
            .order_by(PlaybookHistory.timestamp.asc(), PlaybookHistory.id.asc())
        )
