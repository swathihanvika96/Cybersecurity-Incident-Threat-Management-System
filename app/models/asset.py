from typing import Optional

from sqlalchemy import ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, EnumString, TimestampMixin
from app.models.department import Department
from app.models.user import User


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_asset_org_name"),
        Index("ix_assets_dept_status", "department_id", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), index=True)
    asset_type: Mapped[str] = mapped_column(EnumString(20), index=True)
    criticality: Mapped[str] = mapped_column(EnumString(20), index=True)
    status: Mapped[str] = mapped_column(EnumString(30), default="active", index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), index=True)
    location: Mapped[str | None] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    department_id: Mapped[int | None] = mapped_column(ForeignKey("departments.id"))
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)

    owner: Mapped[Optional[User]] = relationship(lazy="joined")
    department: Mapped[Optional[Department]] = relationship(lazy="joined")
