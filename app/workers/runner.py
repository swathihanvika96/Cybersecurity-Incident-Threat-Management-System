"""Runs the periodic workers in one daemon thread (enable with ENABLE_BACKGROUND_WORKERS=true).

For multiple API replicas run the workers in exactly one process (e.g. a dedicated container with
`python -m app.workers.runner`), otherwise every replica repeats the same checks.
"""
import threading
import time

from app.core.config import settings
from app.core.logging import get_logger, setup_logging
from app.workers import notification_worker, remediation_deadline_worker, sla_monitor_worker

logger = get_logger("app.workers")
JOBS = (sla_monitor_worker, remediation_deadline_worker, notification_worker)  # notifications last: deliver new ones


def run_all_once() -> None:
    for job in JOBS:
        try:
            job.run_once()
        except Exception:  # noqa: BLE001 - one failing job must not stop the others
            logger.exception("worker job failed", extra={"job": job.__name__})


def _loop(stop: threading.Event) -> None:
    while not stop.is_set():
        run_all_once()
        stop.wait(settings.WORKER_INTERVAL_SECONDS)


def start_background(stop: threading.Event) -> threading.Thread:
    thread = threading.Thread(target=_loop, args=(stop,), name="background-workers", daemon=True)
    thread.start()
    logger.info("background workers started", extra={"interval": settings.WORKER_INTERVAL_SECONDS})
    return thread


if __name__ == "__main__":  # pragma: no cover
    setup_logging(settings.LOG_LEVEL, settings.LOG_JSON)
    event = threading.Event()
    try:
        _loop(event)
    except KeyboardInterrupt:
        event.set()
        time.sleep(0.1)
