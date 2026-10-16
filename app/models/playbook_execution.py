from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, EnumString
from app.models.playbook_task import PlaybookTask
from app.utils.date_utils import utcnow


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    id: Mapped[int] = mapped_column(primary_key=True)
    playbook_id: Mapped[int] = mapped_column(ForeignKey("response_playbooks.id"), index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    started_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(EnumString(20), default="running", index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    cancel_reason: Mapped[str | None] = mapped_column(String(500))

    tasks: Mapped[list[PlaybookTask]] = relationship(
        cascade="all, delete-orphan", lazy="selectin", order_by="PlaybookTask.step_order"
    )


class PlaybookHistory(Base):
    """Response history: every action taken while running a playbook."""

    __tablename__ = "playbook_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    execution_id: Mapped[int] = mapped_column(ForeignKey("playbook_executions.id", ondelete="CASCADE"), index=True)
    task_id: Mapped[int | None] = mapped_column(ForeignKey("playbook_tasks.id", ondelete="SET NULL"))
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(50))
    details: Mapped[str | None] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
