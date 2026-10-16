from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, EnumString
from app.utils.date_utils import utcnow


class RemediationApproval(Base):
    __tablename__ = "remediation_approvals"

    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("remediation_tasks.id", ondelete="CASCADE"), index=True)
    approver_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    decision: Mapped[str] = mapped_column(EnumString(20))
    comments: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
