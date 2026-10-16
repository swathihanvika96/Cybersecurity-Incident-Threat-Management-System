from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, EnumString
from app.utils.date_utils import utcnow


class RiskAcceptance(Base):
    __tablename__ = "risk_acceptances"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True)
    justification: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(EnumString(20), default="active", index=True)
    accepted_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    accepted_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime)
    revoked_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime)
    revoke_reason: Mapped[str | None] = mapped_column(Text)
