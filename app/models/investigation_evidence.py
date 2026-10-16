from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, EnumString
from app.utils.date_utils import utcnow


class InvestigationEvidence(Base):
    """A reference to evidence (log path, storage URI, hash...). The platform stores references, not raw files."""

    __tablename__ = "investigation_evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(255))
    evidence_type: Mapped[str] = mapped_column(EnumString(30))
    description: Mapped[str | None] = mapped_column(Text)
    reference: Mapped[str] = mapped_column(String(500))
    sha256: Mapped[str | None] = mapped_column(String(64))
    added_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    added_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
