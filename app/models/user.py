from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import RoleName
from app.db.base import Base, TimestampMixin
from app.models.role import Role


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(150))
    phone: Mapped[str | None] = mapped_column(String(20))
    hashed_password: Mapped[str] = mapped_column(String(255))
    role_id: Mapped[int | None] = mapped_column(ForeignKey("roles.id"), index=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), index=True)
    department_id: Mapped[int | None] = mapped_column(ForeignKey("departments.id"), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime)
    deactivated_at: Mapped[datetime | None] = mapped_column(DateTime)

    role: Mapped[Optional[Role]] = relationship(lazy="joined")

    @property
    def role_name(self) -> str | None:
        return self.role.name if self.role else None

    @property
    def is_super_admin(self) -> bool:
        return self.role_name == RoleName.SUPER_ADMIN

    @property
    def permission_names(self) -> frozenset[str]:
        if self.role is None:
            return frozenset()
        return frozenset(p.name for p in self.role.permissions)

    def has_permission(self, permission: str) -> bool:
        return self.is_super_admin or permission in self.permission_names
