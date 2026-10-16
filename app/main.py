"""Application factory: Security Incident, Alert & Vulnerability Management System."""
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import get_logger, setup_logging
from app.db.session import SessionLocal, engine
from app.middleware.request_context import RequestContextMiddleware
from app.middleware.request_logging import RequestLoggingMiddleware
from app.schemas.examples import apply_examples

logger = get_logger("app")

DESCRIPTION = """
Platform for **security alerts, incidents, vulnerabilities, risk, remediation, investigations, playbooks, SLAs,
audit, notifications, dashboards and reports**.

### Authenticating in Swagger
1. Call `POST /api/v1/auth/login` (or press **Authorize** and enter e-mail as *username* + password).
2. Use the returned `access_token`; refresh with `POST /api/v1/auth/refresh`.

### Conventions
* Lists are paginated: `?page=1&size=20` and return `{items, total, page, size, pages}`.
* Errors share one envelope: `{"success": false, "error": {"code", "message", "details"}, "request_id"}`.
* Timestamps are ISO-8601 UTC. Playbook actions are **simulated** only. Audit logs are append-only.
"""

TAGS = [
    {"name": "Authentication", "description": "Login, refresh, logout, password reset and account activation."},
    {"name": "Users", "description": "User accounts and role assignment."},
    {"name": "Roles & Permissions", "description": "Roles and their permissions."},
    {"name": "Organizations", "description": "Organizations."},
    {"name": "Departments", "description": "Departments inside an organization."},
    {"name": "Security Teams", "description": "Security teams and members."},
    {"name": "Assets", "description": "Servers, endpoints, applications and databases."},
    {"name": "Security Alerts", "description": "Alert intake with duplicate detection."},
    {"name": "Alert Correlation", "description": "Group repeated/related alerts."},
    {"name": "Incidents", "description": "Incident lifecycle, assignment, closure approval."},
    {"name": "Search", "description": "Advanced search over incidents and alerts."},
    {"name": "Vulnerabilities", "description": "Vulnerabilities and affected assets."},
    {"name": "Risk Assessment", "description": "Risk scoring, high-risk assets, risk acceptance."},
    {"name": "Remediation", "description": "Remediation tasks, evidence and approval."},
    {"name": "Investigations", "description": "Investigations, notes and access-controlled evidence."},
    {"name": "Response Playbooks", "description": "Simulated response playbooks."},
    {"name": "SLA Management", "description": "SLA policies, breaches and escalation."},
    {"name": "Audit Logs", "description": "Read-only audit trail."},
    {"name": "Notifications", "description": "In-app notifications."},
    {"name": "Dashboard", "description": "Live metrics."},
    {"name": "Reports", "description": "Reports and CSV export."},
    {"name": "Health", "description": "Liveness and readiness."},
]


def ensure_schema() -> None:
    """Development convenience: bring the database up to the latest Alembic revision on startup.

    Production never does this implicitly - run `alembic upgrade head` as a deployment step (the Dockerfile does).
    """
    from pathlib import Path

    from sqlalchemy import inspect

    tables = set(inspect(engine).get_table_names())
    if settings.is_production:
        if "permissions" not in tables:
            logger.error("database schema is missing - run `alembic upgrade head` before starting the API")
        return
    if "permissions" in tables and "alembic_version" not in tables:
        return  # schema was created without Alembic (e.g. AUTO_CREATE_TABLES); leave it alone
    from alembic import command
    from alembic.config import Config

    root = Path(__file__).resolve().parents[1]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "alembic"))
    command.upgrade(cfg, "head")  # no-op when already current


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging(settings.LOG_LEVEL, settings.LOG_JSON)
    if settings.AUTO_CREATE_TABLES:
        from app.db.base import Base

        Base.metadata.create_all(bind=engine)
    else:
        try:
            ensure_schema()
        except Exception:  # noqa: BLE001
            logger.exception("could not apply migrations automatically - run `alembic upgrade head`")
    if settings.SEED_ON_STARTUP:
        try:
            from app.db.init_db import seed_all

            with SessionLocal() as db:
                seed_all(db)
        except Exception:  # noqa: BLE001 - e.g. migrations not applied yet; /health/ready reports it
            logger.exception("startup seeding failed (have migrations been applied?)")
    stop = threading.Event()
    if settings.ENABLE_BACKGROUND_WORKERS:
        from app.workers.runner import start_background

        start_background(stop)
    logger.info("application started", extra={"environment": settings.ENVIRONMENT})
    yield
    stop.set()


def create_app() -> FastAPI:
    apply_examples()  # realistic sample payloads for Swagger UI
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        description=DESCRIPTION,
        openapi_tags=TAGS,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )
    app.add_middleware(RequestLoggingMiddleware)
    if settings.CORS_ORIGINS:
        app.add_middleware(CORSMiddleware, allow_origins=settings.CORS_ORIGINS, allow_credentials=True,
                           allow_methods=["*"], allow_headers=["*"], expose_headers=["X-Request-ID"])
    app.add_middleware(RequestContextMiddleware)  # outermost: request id available to everything else
    register_exception_handlers(app)
    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    @app.get("/health", tags=["Health"], summary="Liveness probe")
    def health():
        return {"status": "ok", "version": settings.VERSION}

    @app.get("/health/ready", tags=["Health"], summary="Readiness probe (checks the database)",
             responses={503: {"description": "Database unreachable"}})
    def ready():
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception:  # noqa: BLE001
            logger.exception("readiness check failed")
            return JSONResponse({"status": "unavailable", "database": "down"}, status_code=503)
        return {"status": "ready", "database": "up"}

    return app


app = create_app()
