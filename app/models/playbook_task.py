from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, EnumString, TimestampMixin


class PlaybookTask(Base, TimestampMixin):
    """A concrete, assignable task created from a playbook step when a playbook is executed.
    Actions are SIMULATED: completing a task only records a result, it never touches a real system."""

    __tablename__ = "playbook_tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    execution_id: Mapped[int] = mapped_column(ForeignKey("playbook_executions.id", ondelete="CASCADE"), index=True)
    step_id: Mapped[int | None] = mapped_column(ForeignKey("playbook_steps.id", ondelete="SET NULL"))
    step_order: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    step_type: Mapped[str] = mapped_column(EnumString(20))
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    simulated_action: Mapped[str | None] = mapped_column(String(255))
    assigned_to_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    status: Mapped[str] = mapped_column(EnumString(20), default="pending", index=True)
    completion_notes: Mapped[str | None] = mapped_column(Text)
    simulated_result: Mapped[str | None] = mapped_column(Text)
    completed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    approved_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime)
    review_comment: Mapped[str | None] = mapped_column(Text)
