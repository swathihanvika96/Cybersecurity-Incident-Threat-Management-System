"""Read-only audit trail. There is deliberately no create/update/delete endpoint, and the ORM layer rejects any
UPDATE or DELETE of an `audit_logs` row."""
from datetime import date
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import DbSession, require_permission
from app.core.constants import P
from app.models import User
from app.repositories.audit_repository import AuditRepository
from app.schemas.audit_log import AuditLogOut
from app.schemas.common import COMMON_RESPONSES, Page
from app.utils.pagination import PageParams, page_params
from app.utils.response import make_page

router = APIRouter(prefix="/audit-logs", tags=["Audit Logs"], responses=COMMON_RESPONSES)

Reader = Annotated[User, Depends(require_permission(P.AUDIT_READ))]


@router.get("", response_model=Page[AuditLogOut], summary="Search the audit trail (newest first)")
def list_audit_logs(
    db: DbSession,
    _: Reader,
    params: Annotated[PageParams, Depends(page_params)],
    user_id: int | None = Query(None, description="Who performed the action"),
    action: str | None = Query(None, description="e.g. incident.create, auth.login, evidence.access"),
    entity_type: str | None = Query(None, description="e.g. incident, asset, remediation_task"),
    entity_id: int | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
):
    """Entries are append-only: they cannot be edited or deleted through the API or the ORM."""
    repo = AuditRepository(db)
    items, total = repo.page(repo.filtered(user_id=user_id, action=action, entity_type=entity_type,
                                           entity_id=entity_id, date_from=date_from, date_to=date_to), params)
    return make_page(items, total, params)


@router.get("/{audit_log_id}", response_model=AuditLogOut, summary="Get one audit entry")
def get_audit_log(audit_log_id: int, db: DbSession, _: Reader):
    return AuditRepository(db).require(audit_log_id)
