"""Raises 'due soon' / 'overdue' remediation notifications and expires lapsed risk acceptances."""
from app.core.logging import get_logger
from app.db.session import SessionLocal
from app.services import remediation_service, risk_service

logger = get_logger("app.workers.remediation")


def run_once() -> dict[str, int]:
    with SessionLocal() as db:
        result = remediation_service.notify_deadlines(db)
        result["acceptances_expired"] = risk_service.expire_acceptances(db)
        db.commit()
    logger.info("remediation deadline worker run", extra=result)
    return result
