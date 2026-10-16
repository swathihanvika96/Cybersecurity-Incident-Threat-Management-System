from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.utils.date_utils import utcnow


class InvestigationNote(Base):
    """Free-text notes (note_type='note') and system timeline events (note_type='event').
    Attached to an incident and/or an investigation."""

    __tablename__ = "investigation_notes"
    __table_args__ = (
        CheckConstraint("incident_id IS NOT NULL OR investigation_id IS NOT NULL", name="ck_note_has_parent"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    investigation_id: Mapped[int | None] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    author_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    note_type: Mapped[str] = mapped_column(String(20), default="note")
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)
