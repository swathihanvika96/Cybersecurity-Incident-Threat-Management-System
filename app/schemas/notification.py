from app.core.constants import NotificationStatus, NotificationType
from app.schemas.common import DT, ORMModel


class NotificationOut(ORMModel):
    id: int
    notification_type: NotificationType
    title: str
    message: str
    entity_type: str | None = None
    entity_id: int | None = None
    status: NotificationStatus
    is_read: bool
    read_at: DT | None = None
    delivered_at: DT | None = None
    created_at: DT


class UnreadCount(ORMModel):
    unread: int


class ProcessResult(ORMModel):
    delivered: int
    failed: int
