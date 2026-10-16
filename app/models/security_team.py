from typing import Optional

from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, EnumString, TimestampMixin
from app.models.team_member import TeamMember
from app.models.user import User


class SecurityTeam(Base, TimestampMixin):
    __tablename__ = "security_teams"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    team_type: Mapped[str] = mapped_column(EnumString(20), default="security", nullable=False)  # security | it
    manager_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    manager: Mapped[Optional[User]] = relationship(lazy="joined")
    members: Mapped[list[TeamMember]] = relationship(
        cascade="all, delete-orphan", lazy="selectin", order_by="TeamMember.id"
    )
