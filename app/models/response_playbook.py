from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, EnumString, TimestampMixin
from app.models.playbook_step import PlaybookStep


class ResponsePlaybook(Base, TimestampMixin):
    __tablename__ = "response_playbooks"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    incident_category: Mapped[str | None] = mapped_column(EnumString(40), index=True)  # null = any category
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))

    steps: Mapped[list[PlaybookStep]] = relationship(
        cascade="all, delete-orphan", lazy="selectin", order_by="PlaybookStep.step_order"
    )
