"""Delivers queued notifications (simulated in-app delivery)."""
from app.core.logging import get_logger
from app.db.session import SessionLocal
from app.services import notification_service

logger = get_logger("app.workers.notification")


def run_once() -> dict[str, int]:
    with SessionLocal() as db:
        result = notification_service.process_queue(db)
    if result["delivered"] or result["failed"]:
        logger.info("notification worker run", extra=result)
    return result
