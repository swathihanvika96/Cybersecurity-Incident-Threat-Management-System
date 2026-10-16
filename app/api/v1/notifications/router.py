from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.deps import CurrentUser, DbSession, require_permission
from app.core.constants import NotificationStatus, NotificationType, P
from app.models import User
from app.schemas.common import COMMON_RESPONSES, MessageResponse, Page
from app.schemas.notification import NotificationOut, ProcessResult, UnreadCount
from app.services import notification_service
from app.utils.pagination import PageParams, page_params
from app.utils.response import make_page

router = APIRouter(prefix="/notifications", tags=["Notifications"], responses=COMMON_RESPONSES)

Manager = Annotated[User, Depends(require_permission(P.NOTIFICATION_MANAGE))]


@router.get("", response_model=Page[NotificationOut], summary="My notifications (newest first)")
def my_notifications(
    db: DbSession,
    user: CurrentUser,
    params: Annotated[PageParams, Depends(page_params)],
    is_read: bool | None = None,
    notification_type: NotificationType | None = None,
    status: NotificationStatus | None = None,
):
    """Users only ever see their own notifications."""
    items, total = notification_service.list_for_user(db, user, params, is_read=is_read,
                                                      notification_type=notification_type, status=status)
    return make_page(items, total, params)


@router.get("/unread-count", response_model=UnreadCount, summary="Number of unread notifications")
def unread_count(db: DbSession, user: CurrentUser):
    return {"unread": notification_service.unread_count(db, user)}


@router.post("/read-all", response_model=MessageResponse, summary="Mark all my notifications as read")
def read_all(db: DbSession, user: CurrentUser):
    count = notification_service.mark_all_read(db, user)
    return {"message": f"{count} notification(s) marked as read"}


@router.post("/process", response_model=ProcessResult, summary="Deliver queued notifications now")
def process_queue(db: DbSession, _: Manager):
    """Runs the same delivery step as the background worker (simulated in-app delivery)."""
    return notification_service.process_queue(db)


@router.post("/{notification_id}/read", response_model=NotificationOut, summary="Mark as read")
def mark_read(notification_id: int, db: DbSession, user: CurrentUser):
    return notification_service.mark_read(db, user, notification_id, True)


@router.post("/{notification_id}/unread", response_model=NotificationOut, summary="Mark as unread")
def mark_unread(notification_id: int, db: DbSession, user: CurrentUser):
    return notification_service.mark_read(db, user, notification_id, False)
