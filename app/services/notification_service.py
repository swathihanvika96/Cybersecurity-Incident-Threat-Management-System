"""Notification generation, queueing and (simulated, in-app) delivery."""
from typing import Iterable

from sqlalchemy.orm import Session

from app.core.constants import NotificationStatus, NotificationType
from app.core.exceptions import NotFoundError
from app.core.logging import get_logger
from app.models import Notification, User
from app.repositories.notification_repository import NotificationRepository
from app.repositories.user_repository import UserRepository
from app.utils.date_utils import utcnow
from app.utils.pagination import PageParams

logger = get_logger("app.notifications")


def notify(
    db: Session,
    user_id: int | None,
    notification_type: NotificationType | str,
    title: str,
    message: str,
    *,
    entity_type: str | None = None,
    entity_id: int | None = None,
    dedupe: bool = False,
    dedupe_on_title: bool = False,
) -> Notification | None:
    """Queue a notification (status=queued). Delivery is performed by the notification worker.

    With `dedupe`, nothing is created if the user already has an UNREAD notification of the same type for the
    same entity (and title, when `dedupe_on_title`)."""
    if user_id is None:
        return None
    ntype = notification_type.value if isinstance(notification_type, NotificationType) else notification_type
    repo = NotificationRepository(db)
    if dedupe and repo.exists_similar(
        user_id, ntype, entity_type, entity_id, title=title if dedupe_on_title else None
    ):
        return None
    note = Notification(
        user_id=user_id,
        notification_type=ntype,
        title=title[:200],
        message=message,
        entity_type=entity_type,
        entity_id=entity_id,
        status=NotificationStatus.QUEUED.value,
    )
    db.add(note)
    return note


def notify_many(
    db: Session,
    user_ids: Iterable[int | None],
    notification_type: NotificationType | str,
    title: str,
    message: str,
    *,
    exclude_user_id: int | None = None,
    **kwargs,
) -> int:
    count = 0
    for uid in dict.fromkeys(u for u in user_ids if u is not None):  # unique, ordered
        if uid == exclude_user_id:
            continue
        if notify(db, uid, notification_type, title, message, **kwargs):
            count += 1
    return count


def permission_holder_ids(db: Session, permission: str) -> list[int]:
    return [u.id for u in UserRepository(db).with_permission(permission)]


def notify_permission_holders(
    db: Session,
    permission: str,
    notification_type: NotificationType | str,
    title: str,
    message: str,
    *,
    exclude_user_id: int | None = None,
    extra_user_ids: Iterable[int | None] = (),
    **kwargs,
) -> int:
    ids = permission_holder_ids(db, permission) + [u for u in extra_user_ids if u is not None]
    return notify_many(db, ids, notification_type, title, message, exclude_user_id=exclude_user_id, **kwargs)


# --------------------------------------------------------------------------- user-facing operations
def list_for_user(db: Session, user: User, params: PageParams, **filters):
    return NotificationRepository(db).page(NotificationRepository(db).for_user(user.id, **filters), params)


def unread_count(db: Session, user: User) -> int:
    return NotificationRepository(db).unread_count(user.id)


def _own(db: Session, user: User, notification_id: int) -> Notification:
    note = NotificationRepository(db).get(notification_id)
    if note is None or note.user_id != user.id:  # other users' notifications are indistinguishable from missing
        raise NotFoundError(f"Notification {notification_id} not found")
    return note


def mark_read(db: Session, user: User, notification_id: int, read: bool = True) -> Notification:
    note = _own(db, user, notification_id)
    note.is_read = read
    note.read_at = utcnow() if read else None
    db.commit()
    return note


def mark_all_read(db: Session, user: User) -> int:
    count = NotificationRepository(db).mark_all_read(user.id, utcnow())
    db.commit()
    return count


# --------------------------------------------------------------------------- background processing
def process_queue(db: Session, limit: int = 500) -> dict[str, int]:
    """Deliver queued notifications. Delivery channel is in-app (the row becomes visible as delivered); an e-mail or
    webhook channel can be plugged in at `_deliver` without touching callers."""
    delivered = failed = 0
    for note in NotificationRepository(db).queued(limit):
        try:
            _deliver(note)
            note.status = NotificationStatus.DELIVERED.value
            note.delivered_at = utcnow()
            note.error = None
            delivered += 1
        except Exception as exc:  # pragma: no cover - only reachable with a real external channel
            note.retry_count += 1
            note.error = str(exc)[:500]
            if note.retry_count >= 3:
                note.status = NotificationStatus.FAILED.value
                failed += 1
    db.commit()
    return {"delivered": delivered, "failed": failed}


def _deliver(note: Notification) -> None:
    logger.info(
        "notification delivered",
        extra={"notification_id": note.id, "user_id": note.user_id, "type": note.notification_type},
    )
