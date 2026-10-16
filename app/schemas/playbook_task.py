from pydantic import Field, computed_field

from app.core.constants import PlaybookExecutionStatus, PlaybookStepType, PlaybookTaskStatus
from app.schemas.common import DT, ORMModel, RequestModel


class StepAssignment(RequestModel):
    step_order: int = Field(ge=1)
    user_id: int


class PlaybookExecute(RequestModel):
    incident_id: int
    assignments: list[StepAssignment] = Field(default_factory=list, description="Optional per-step analyst assignment")


class TaskAssign(RequestModel):
    assigned_to_id: int


class TaskComplete(RequestModel):
    notes: str | None = Field(None, max_length=2000)


class TaskReview(RequestModel):
    comment: str | None = Field(None, max_length=1000, description="Required when rejecting")


class ExecutionCancel(RequestModel):
    reason: str = Field(min_length=3, max_length=500)


class PlaybookTaskOut(ORMModel):
    id: int
    execution_id: int
    step_order: int
    title: str
    description: str | None = None
    step_type: PlaybookStepType
    requires_approval: bool
    simulated_action: str | None = None
    assigned_to_id: int | None = None
    status: PlaybookTaskStatus
    completion_notes: str | None = None
    simulated_result: str | None = None
    completed_by_id: int | None = None
    completed_at: DT | None = None
    approved_by_id: int | None = None
    approved_at: DT | None = None
    review_comment: str | None = None


class PlaybookExecutionOut(ORMModel):
    id: int
    playbook_id: int
    incident_id: int
    started_by_id: int | None = None
    status: PlaybookExecutionStatus
    started_at: DT
    completed_at: DT | None = None
    cancel_reason: str | None = None
    tasks: list[PlaybookTaskOut]

    @computed_field(description="Percentage of tasks completed")
    @property
    def progress_percent(self) -> float:
        if not self.tasks:
            return 0.0
        done = sum(1 for t in self.tasks if t.status == "completed")
        return round(done / len(self.tasks) * 100, 1)


class PlaybookHistoryOut(ORMModel):
    id: int
    execution_id: int
    task_id: int | None = None
    user_id: int | None = None
    action: str
    details: str | None = None
    timestamp: DT
