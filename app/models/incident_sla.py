from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, EnumString, TimestampMixin
from app.utils.date_utils import utcnow


class SLAPolicy(Base):
    """Per-severity SLA targets in minutes (seeded with defaults; editable by managers)."""

    __tablename__ = "sla_policies"

    id: Mapped[int] = mapped_column(primary_key=True)
    severity: Mapped[str] = mapped_column(EnumString(20), unique=True)
    ack_minutes: Mapped[int] = mapped_column(Integer)
    investigation_minutes: Mapped[int] = mapped_column(Integer)
    resolution_minutes: Mapped[int] = mapped_column(Integer)
    updated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class IncidentSLA(Base, TimestampMixin):
    __tablename__ = "incident_slas"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), unique=True)
    severity: Mapped[str] = mapped_column(EnumString(20))

    ack_deadline: Mapped[datetime] = mapped_column(DateTime, index=True)
    investigation_deadline: Mapped[datetime] = mapped_column(DateTime, index=True)
    resolution_deadline: Mapped[datetime] = mapped_column(DateTime, index=True)

    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime)
    investigation_started_at: Mapped[datetime | None] = mapped_column(DateTime)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime)
    response_time_minutes: Mapped[float | None] = mapped_column(Float)
    resolution_time_minutes: Mapped[float | None] = mapped_column(Float)

    ack_breached: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    investigation_breached: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    resolution_breached: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    sla_status: Mapped[str] = mapped_column(EnumString(20), default="on_track", index=True)

    escalation_status: Mapped[str] = mapped_column(EnumString(30), default="none", index=True)
    escalation_level: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime)
    escalation_reason: Mapped[str | None] = mapped_column(Text)

    incident: Mapped[Optional["Incident"]] = relationship(back_populates="sla")  # noqa: F821
