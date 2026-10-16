from pydantic import Field, computed_field

from app.core.constants import Priority, RemediationStatus
from app.schemas.common import DT, DTIn, ORMModel, RequestModel
from app.schemas.security_team import TeamBrief
from app.schemas.user import UserBrief
from app.utils.date_utils import attach_utc, utcnow


class RemediationCreate(RequestModel):
    vulnerability_id: int
    asset_id: int | None = Field(None, description="Asset the fix applies to (must be mapped to the vulnerability)")
    title: str = Field(min_length=3, max_length=255)
    description: str | None = None
    assigned_team_id: int | None = None
    assigned_to_id: int | None = None
    priority: Priority = Priority.MEDIUM
    due_date: DTIn


class RemediationUpdate(RequestModel):
    title: str | None = Field(None, min_length=3, max_length=255)
    description: str | None = None
    assigned_team_id: int | None = None
    assigned_to_id: int | None = None
    priority: Priority | None = None
    due_date: DTIn | None = None


class CommentBody(RequestModel):
    comment: str | None = Field(None, max_length=1000)


class CancelBody(RequestModel):
    reason: str = Field(min_length=3, max_length=500)


class DecisionBody(RequestModel):
    comments: str | None = Field(None, max_length=1000, description="Required when rejecting")


class RemediationOut(ORMModel):
    id: int
    reference: str | None = None
    vulnerability_id: int
    asset_id: int | None = None
    title: str
    description: str | None = None
    team: TeamBrief | None = None
    assignee: UserBrief | None = None
    priority: Priority
    status: RemediationStatus
    due_date: DT
    created_by_id: int | None = None
    submitted_by_id: int | None = None
    submitted_at: DT | None = None
    approved_at: DT | None = None
    created_at: DT
    updated_at: DT

    @computed_field(description="Past its due date and not yet approved/cancelled")
    @property
    def is_overdue(self) -> bool:
        return self.status in ("open", "in_progress", "pending_approval", "rejected") and self.due_date < attach_utc(
            utcnow()
        )


class RemediationHistoryOut(ORMModel):
    id: int
    task_id: int
    user_id: int | None = None
    action: str
    old_status: str | None = None
    new_status: str | None = None
    comment: str | None = None
    timestamp: DT
