from sqlalchemy import Boolean, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, EnumString


class PlaybookStep(Base):
    __tablename__ = "playbook_steps"
    __table_args__ = (UniqueConstraint("playbook_id", "step_order", name="uq_playbook_step_order"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    playbook_id: Mapped[int] = mapped_column(ForeignKey("response_playbooks.id", ondelete="CASCADE"), index=True)
    step_order: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    step_type: Mapped[str] = mapped_column(EnumString(20))  # investigation | containment | recovery
    is_sensitive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)  # needs approval
    simulated_action: Mapped[str | None] = mapped_column(String(255))
