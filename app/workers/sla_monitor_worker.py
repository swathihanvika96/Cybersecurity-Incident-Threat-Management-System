"""Evaluates the SLA of every open incident: updates status, flags breaches, escalates and notifies."""
from app.core.logging import get_logger
from app.db.session import SessionLocal
from app.services import sla_service

logger = get_logger("app.workers.sla")


def run_once() -> dict[str, int]:
    with SessionLocal() as db:
        result = sla_service.evaluate_all_open(db)
    logger.info("sla monitor run", extra=result)
    return result
