from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, EnumString, TimestampMixin
from app.models.security_team import SecurityTeam
from app.models.user import User


class RemediationTask(Base, TimestampMixin):
    __tablename__ = "remediation_tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str | None] = mapped_column(String(30), unique=True, index=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    assigned_team_id: Mapped[int | None] = mapped_column(ForeignKey("security_teams.id"), index=True)
    assigned_to_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    priority: Mapped[str] = mapped_column(EnumString(20), default="medium", index=True)
    status: Mapped[str] = mapped_column(EnumString(20), default="open", index=True)
    due_date: Mapped[datetime] = mapped_column(DateTime, index=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    submitted_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime)

    team: Mapped[Optional[SecurityTeam]] = relationship(lazy="joined")
    assignee: Mapped[Optional[User]] = relationship(foreign_keys=[assigned_to_id], lazy="joined")
