from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, EnumString, TimestampMixin
from app.models.asset import Asset
from app.models.user import User


class SecurityAlert(Base, TimestampMixin):
    __tablename__ = "security_alerts"
    __table_args__ = (
        Index("ix_alerts_asset_category_detected", "asset_id", "category", "detected_at"),
        Index("ix_alerts_fingerprint_detected", "fingerprint", "detected_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str | None] = mapped_column(String(30), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(100), index=True)
    category: Mapped[str] = mapped_column(EnumString(40), index=True)
    severity: Mapped[str] = mapped_column(EnumString(20), index=True)
    status: Mapped[str] = mapped_column(EnumString(20), default="new", index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    assigned_to_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    detected_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    is_duplicate: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    duplicate_of_id: Mapped[int | None] = mapped_column(ForeignKey("security_alerts.id"))
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    correlation_id: Mapped[int | None] = mapped_column(ForeignKey("alert_correlations.id"), index=True)

    asset: Mapped[Asset] = relationship(lazy="joined")
    assigned_to: Mapped[Optional[User]] = relationship(foreign_keys=[assigned_to_id], lazy="joined")
