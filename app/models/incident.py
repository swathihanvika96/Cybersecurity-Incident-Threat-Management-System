from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, EnumString, TimestampMixin
from app.models.asset import Asset
from app.models.incident_sla import IncidentSLA
from app.models.security_alert import SecurityAlert
from app.models.user import User
from app.utils.date_utils import utcnow


class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_asset_category_status", "asset_id", "category", "status"),
        Index("ix_incidents_status_severity", "status", "severity"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str | None] = mapped_column(String(30), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str] = mapped_column(EnumString(40), index=True)
    severity: Mapped[str] = mapped_column(EnumString(20), index=True)
    status: Mapped[str] = mapped_column(EnumString(20), default="new")
    is_sensitive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), index=True)
    correlation_id: Mapped[int | None] = mapped_column(ForeignKey("alert_correlations.id"), index=True)
    assigned_to_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)

    resolution_summary: Mapped[str | None] = mapped_column(String(500))
    resolution_details: Mapped[str | None] = mapped_column(Text)
    root_cause: Mapped[str | None] = mapped_column(Text)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, index=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime)
    closure_requested_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    closure_requested_at: Mapped[datetime | None] = mapped_column(DateTime)
    closure_approved_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    closure_note: Mapped[str | None] = mapped_column(Text)

    asset: Mapped[Optional[Asset]] = relationship(lazy="joined")
    assigned_to: Mapped[Optional[User]] = relationship(foreign_keys=[assigned_to_id], lazy="joined")
    sla: Mapped[Optional[IncidentSLA]] = relationship(back_populates="incident", uselist=False, lazy="joined")
    # alerts linked through incident_alerts (read-only; loaded on demand for detail views)
    alerts: Mapped[list[SecurityAlert]] = relationship(
        secondary="incident_alerts", viewonly=True, order_by="SecurityAlert.detected_at"
    )


class IncidentRelation(Base):
    """Tracks related / duplicate incidents."""

    __tablename__ = "incident_relations"
    __table_args__ = (UniqueConstraint("incident_id", "related_incident_id", name="uq_incident_relation"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    related_incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    relation_type: Mapped[str] = mapped_column(String(30), default="related")  # related | possible_duplicate | follow_up
    reason: Mapped[str | None] = mapped_column(String(500))
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
