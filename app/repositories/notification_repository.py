from datetime import datetime

from sqlalchemy import Select, func, select

from app.models import Notification
from app.repositories.base import BaseRepository


class NotificationRepository(BaseRepository[Notification]):
    model = Notification
    label = "Notification"

    def for_user(
        self,
        user_id: int,
        *,
        is_read: bool | None = None,
        notification_type: str | None = None,
        status: str | None = None,
    ) -> Select:
        stmt = select(Notification).where(Notification.user_id == user_id)
        if is_read is not None:
            stmt = stmt.where(Notification.is_read.is_(is_read))
        if notification_type:
            stmt = stmt.where(Notification.notification_type == notification_type)
        if status:
            stmt = stmt.where(Notification.status == status)
        return stmt.order_by(Notification.created_at.desc(), Notification.id.desc())

    def unread_count(self, user_id: int) -> int:
        return (
            self.db.scalar(
                select(func.count(Notification.id)).where(
                    Notification.user_id == user_id, Notification.is_read.is_(False)
                )
            )
            or 0
        )

    def exists_similar(self, user_id: int, notification_type: str, entity_type: str | None, entity_id: int | None,
                       title: str | None = None, unread_only: bool = True) -> bool:
        stmt = select(func.count(Notification.id)).where(
            Notification.user_id == user_id,
            Notification.notification_type == notification_type,
            Notification.entity_type == entity_type,
            Notification.entity_id == entity_id,
        )
        if title is not None:
            stmt = stmt.where(Notification.title == title)
        if unread_only:
            stmt = stmt.where(Notification.is_read.is_(False))
        return (self.db.scalar(stmt) or 0) > 0

    def queued(self, limit: int = 500) -> list[Notification]:
        return list(
            self.db.scalars(
                select(Notification)
                .where(Notification.status == "queued")
                .order_by(Notification.id)
                .limit(limit)
            )
        )

    def mark_all_read(self, user_id: int, now: datetime) -> int:
        rows = list(
            self.db.scalars(
                select(Notification).where(Notification.user_id == user_id, Notification.is_read.is_(False))
            )
        )
        for n in rows:
            n.is_read = True
            n.read_at = now
        return len(rows)
