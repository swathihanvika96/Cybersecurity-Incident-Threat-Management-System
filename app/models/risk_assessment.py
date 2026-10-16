from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, EnumString
from app.utils.date_utils import utcnow


class RiskAssessment(Base):
    """One risk calculation for an (asset, vulnerability) pair. Older rows are kept as history
    (is_current=False); exactly one row per pair is current."""

    __tablename__ = "risk_assessments"
    __table_args__ = (Index("ix_risk_pair_current", "asset_id", "vulnerability_id", "is_current"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True)
    asset_criticality: Mapped[str] = mapped_column(EnumString(20))
    vulnerability_severity: Mapped[str] = mapped_column(EnumString(20))
    cvss_score: Mapped[float] = mapped_column(Float)
    risk_score: Mapped[float] = mapped_column(Float, index=True)
    risk_level: Mapped[str] = mapped_column(EnumString(20), index=True)
    formula_version: Mapped[str] = mapped_column(String(10))
    is_current: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    assessed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    assessed_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
