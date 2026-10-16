from datetime import date
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import DbSession, require_permission
from app.core.constants import AlertStatus, P, SecurityCategory, Severity
from app.models import SecurityAlert, User
from app.repositories import alert_repository
from app.repositories.alert_repository import AlertRepository
from app.schemas.common import COMMON_RESPONSES, Page
from app.schemas.security_alert import AlertAssign, AlertCreate, AlertOut, AlertStatusUpdate, AlertUpdate
from app.services import alert_service
from app.utils.pagination import PageParams, page_params
from app.utils.response import make_page
from app.utils.sorting import apply_sorting

router = APIRouter(prefix="/alerts", tags=["Security Alerts"], responses=COMMON_RESPONSES)

Reader = Annotated[User, Depends(require_permission(P.ALERT_READ))]
Writer = Annotated[User, Depends(require_permission(P.ALERT_WRITE))]


@router.post("", response_model=AlertOut, status_code=status.HTTP_201_CREATED, summary="Create a security alert")
def create_alert(data: AlertCreate, db: DbSession, actor: Writer):
    """**Duplicate detection:** an alert with the same asset + category + source + title as a non-duplicate alert
    detected within `DUPLICATE_ALERT_WINDOW_MINUTES` is stored with `is_duplicate=true` and `duplicate_of_id`
    pointing at the original, whose `occurrence_count` is incremented (and severity raised if the repeat is more
    severe)."""
    return alert_service.create(db, actor, data)


@router.get("", response_model=Page[AlertOut], summary="Search, filter, sort and paginate alerts")
def list_alerts(
    db: DbSession,
    _: Reader,
    params: Annotated[PageParams, Depends(page_params)],
    q: str | None = Query(None, description="Search title, description, reference or source"),
    severity: Annotated[list[Severity] | None, Query(description="Repeat the parameter to match several")] = None,
    status: Annotated[list[AlertStatus] | None, Query(description="Repeat the parameter to match several")] = None,
    category: SecurityCategory | None = None,
    source: str | None = None,
    asset_id: int | None = None,
    department_id: int | None = None,
    assigned_to_id: int | None = None,
    is_duplicate: bool | None = None,
    correlation_id: int | None = None,
    date_from: date | None = Query(None, description="Detected on/after (UTC date)"),
    date_to: date | None = Query(None, description="Detected on/before (UTC date)"),
    sort_by: str | None = Query(None, description="detected_at | created_at | updated_at | severity | status | title | category"),
    sort_order: Literal["asc", "desc"] = "desc",
):
    repo = AlertRepository(db)
    stmt = repo.filtered(q=q, severity=severity, status=status, category=category, source=source, asset_id=asset_id,
                         department_id=department_id, assigned_to_id=assigned_to_id, is_duplicate=is_duplicate,
                         correlation_id=correlation_id, date_from=date_from, date_to=date_to)
    stmt = apply_sorting(stmt, alert_repository.SORT_MAP, sort_by, sort_order, "detected_at",
                         tiebreak=SecurityAlert.id)
    items, total = repo.page(stmt, params)
    return make_page(items, total, params)


@router.get("/{alert_id}", response_model=AlertOut, summary="Get an alert")
def get_alert(alert_id: int, db: DbSession, _: Reader):
    return alert_service.get(db, alert_id)


@router.patch("/{alert_id}", response_model=AlertOut, summary="Update an alert")
def update_alert(alert_id: int, data: AlertUpdate, db: DbSession, actor: Writer):
    return alert_service.update(db, actor, alert_id, data)


@router.patch("/{alert_id}/status", response_model=AlertOut, summary="Change the alert status")
def set_alert_status(alert_id: int, data: AlertStatusUpdate, db: DbSession, actor: Writer):
    """Allowed moves: new -> acknowledged | in_progress | false_positive; acknowledged -> in_progress | resolved |
    false_positive; in_progress -> resolved | false_positive; resolved -> in_progress; false_positive -> new."""
    return alert_service.set_status(db, actor, alert_id, data.status, data.comment)


@router.put("/{alert_id}/assignee", response_model=AlertOut, summary="Assign (or un-assign) an alert")
def assign_alert(alert_id: int, data: AlertAssign, db: DbSession, actor: Writer):
    """Analysts can take alerts for themselves; security managers can assign to any analyst."""
    return alert_service.assign(db, actor, alert_id, data.assigned_to_id)
