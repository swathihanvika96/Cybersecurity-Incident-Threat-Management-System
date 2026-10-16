from datetime import date

from sqlalchemy import Select, select

from app.models import AuditLog
from app.repositories.base import BaseRepository
from app.utils.filtering import date_range


class AuditRepository(BaseRepository[AuditLog]):
    model = AuditLog
    label = "Audit log entry"

    def filtered(
        self,
        *,
        user_id: int | None = None,
        action: str | None = None,
        entity_type: str | None = None,
        entity_id: int | None = None,
        date_from: date | None = None,
        date_to: date | None = None,
    ) -> Select:
        stmt = select(AuditLog)
        if user_id is not None:
            stmt = stmt.where(AuditLog.user_id == user_id)
        if action:
            stmt = stmt.where(AuditLog.action == action)
        if entity_type:
            stmt = stmt.where(AuditLog.entity_type == entity_type)
        if entity_id is not None:
            stmt = stmt.where(AuditLog.entity_id == entity_id)
        stmt = date_range(stmt, AuditLog.timestamp, date_from, date_to)
        return stmt.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
