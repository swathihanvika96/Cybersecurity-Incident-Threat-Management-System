from app.schemas.common import DT, ORMModel


class RemediationApprovalOut(ORMModel):
    id: int
    task_id: int
    approver_id: int
    decision: str
    comments: str | None = None
    decided_at: DT
