from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, EnumString, TimestampMixin
from app.models.security_alert import SecurityAlert
from app.utils.date_utils import utcnow


class AlertCorrelation(Base, TimestampMixin):
    """A group of related alerts (e.g. repeated alerts of one category on the same asset)."""

    __tablename__ = "alert_correlations"

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str | None] = mapped_column(String(30), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    rule: Mapped[str] = mapped_column(EnumString(40))
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), index=True)
    category: Mapped[str | None] = mapped_column(EnumString(40))
    status: Mapped[str] = mapped_column(EnumString(20), default="open", index=True)  # open | closed
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))

    alerts: Mapped[list[SecurityAlert]] = relationship(lazy="selectin", order_by="SecurityAlert.detected_at")


class CorrelationHistory(Base):
    __tablename__ = "correlation_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    correlation_id: Mapped[int] = mapped_column(ForeignKey("alert_correlations.id", ondelete="CASCADE"), index=True)
    action: Mapped[str] = mapped_column(String(50))
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("security_alerts.id"))
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    details: Mapped[str | None] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
