from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, EnumString, TimestampMixin
from app.models.user import User


class InvestigationIncident(Base):
    __tablename__ = "investigation_incidents"
    __table_args__ = (UniqueConstraint("investigation_id", "incident_id", name="uq_inv_incident"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)


class InvestigationAlert(Base):
    __tablename__ = "investigation_alerts"
    __table_args__ = (UniqueConstraint("investigation_id", "alert_id", name="uq_inv_alert"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("security_alerts.id"), index=True)


class InvestigationAsset(Base):
    __tablename__ = "investigation_assets"
    __table_args__ = (UniqueConstraint("investigation_id", "asset_id", name="uq_inv_asset"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)


class Investigation(Base, TimestampMixin):
    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str | None] = mapped_column(String(30), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(EnumString(20), default="open", index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    summary: Mapped[str | None] = mapped_column(Text)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)

    owner: Mapped[Optional[User]] = relationship(foreign_keys=[owner_id], lazy="joined")
    incident_links: Mapped[list[InvestigationIncident]] = relationship(cascade="all, delete-orphan", lazy="selectin")
    alert_links: Mapped[list[InvestigationAlert]] = relationship(cascade="all, delete-orphan", lazy="selectin")
    asset_links: Mapped[list[InvestigationAsset]] = relationship(cascade="all, delete-orphan", lazy="selectin")

    @property
    def incident_ids(self) -> list[int]:
        return sorted(link.incident_id for link in self.incident_links)

    @property
    def alert_ids(self) -> list[int]:
        return sorted(link.alert_id for link in self.alert_links)

    @property
    def asset_ids(self) -> list[int]:
        return sorted(link.asset_id for link in self.asset_links)
