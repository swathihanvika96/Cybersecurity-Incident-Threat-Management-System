from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.utils.date_utils import utcnow


class RemediationEvidence(Base):
    __tablename__ = "remediation_evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("remediation_tasks.id", ondelete="CASCADE"), index=True)
    description: Mapped[str] = mapped_column(Text)
    reference_type: Mapped[str | None] = mapped_column(String(30))
    reference_url: Mapped[str | None] = mapped_column(String(500))
    added_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    added_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
