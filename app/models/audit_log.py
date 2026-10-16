from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, event
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.utils.date_utils import utcnow


class AuditLog(Base):
    """Append-only audit trail. ORM-level guards below reject UPDATE/DELETE; the API exposes read endpoints only."""

    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_entity", "entity_type", "entity_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    entity_type: Mapped[str] = mapped_column(String(60), index=True)
    entity_id: Mapped[int | None] = mapped_column()
    previous_value: Mapped[dict | None] = mapped_column(JSON)
    new_value: Mapped[dict | None] = mapped_column(JSON)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)


class AuditLogImmutableError(RuntimeError):
    pass


@event.listens_for(AuditLog, "before_update")
def _block_audit_update(mapper, connection, target):
    raise AuditLogImmutableError("Audit log records cannot be modified")


@event.listens_for(AuditLog, "before_delete")
def _block_audit_delete(mapper, connection, target):
    raise AuditLogImmutableError("Audit log records cannot be deleted")
