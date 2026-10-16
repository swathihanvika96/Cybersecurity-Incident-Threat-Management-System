from datetime import datetime

from sqlalchemy import DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.utils.date_utils import utcnow


class IncidentAlert(Base):
    """Links alerts to an incident. An alert belongs to at most one incident (unique alert_id)."""

    __tablename__ = "incident_alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("security_alerts.id"), unique=True)
    linked_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    linked_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
