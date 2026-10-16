from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import DbSession, require_permission
from app.core.constants import P, SecurityCategory
from app.models import User
from app.repositories.correlation_repository import CorrelationRepository
from app.schemas.common import COMMON_RESPONSES, Page
from app.schemas.correlation import (
    AutoCorrelateRequest,
    AutoCorrelateResult,
    CorrelationAddAlerts,
    CorrelationCreate,
    CorrelationHistoryOut,
    CorrelationOut,
    RepeatedAlertGroup,
)
from app.services import correlation_service
from app.utils.pagination import PageParams, page_params
from app.utils.response import make_page

router = APIRouter(prefix="/correlations", tags=["Alert Correlation"], responses=COMMON_RESPONSES)

Reader = Annotated[User, Depends(require_permission(P.ALERT_READ))]
Writer = Annotated[User, Depends(require_permission(P.ALERT_WRITE))]


@router.get("/repeated-alerts", response_model=list[RepeatedAlertGroup],
            summary="Identify repeated alerts affecting the same asset")
def repeated_alerts(
    db: DbSession,
    _: Reader,
    window_minutes: int | None = Query(None, ge=1, le=10080, description="Max gap between consecutive alerts"),
    min_alerts: int | None = Query(None, ge=2, le=1000),
    lookback_hours: int | None = Query(None, ge=1, le=8760),
):
    """Rule: alerts of the same category on the same asset, each detected within `window_minutes` of the previous
    one, form a group; groups with at least `min_alerts` alerts are reported."""
    return correlation_service.find_repeated_groups(db, window_minutes, min_alerts, lookback_hours)


@router.post("/auto", response_model=AutoCorrelateResult, summary="Group repeated alerts automatically")
def auto_correlate(db: DbSession, actor: Writer, data: AutoCorrelateRequest | None = None):
    """Creates (or extends) one correlation per repeated-alert group among alerts not yet correlated."""
    data = data or AutoCorrelateRequest()
    return correlation_service.auto_correlate(db, actor, data.window_minutes, data.min_alerts, data.lookback_hours)


@router.post("", response_model=CorrelationOut, status_code=status.HTTP_201_CREATED,
             summary="Group related alerts manually")
def create_correlation(data: CorrelationCreate, db: DbSession, actor: Writer):
    return correlation_service.create_manual(db, actor, data.name, data.alert_ids)


@router.get("", response_model=Page[CorrelationOut], summary="List correlation groups")
def list_correlations(
    db: DbSession,
    _: Reader,
    params: Annotated[PageParams, Depends(page_params)],
    asset_id: int | None = None,
    category: SecurityCategory | None = None,
    status: str | None = Query(None, pattern="^(open|closed)$"),
):
    repo = CorrelationRepository(db)
    items, total = repo.page(repo.filtered(asset_id=asset_id, category=category, status=status), params)
    return make_page(items, total, params)


@router.get("/{correlation_id}", response_model=CorrelationOut, summary="Get a correlation group")
def get_correlation(correlation_id: int, db: DbSession, _: Reader):
    return CorrelationRepository(db).require(correlation_id)


@router.post("/{correlation_id}/alerts", response_model=CorrelationOut, summary="Add alerts to a correlation")
def add_alerts(correlation_id: int, data: CorrelationAddAlerts, db: DbSession, actor: Writer):
    return correlation_service.add_alerts(db, actor, correlation_id, data.alert_ids)


@router.delete("/{correlation_id}/alerts/{alert_id}", response_model=CorrelationOut,
               summary="Remove an alert from a correlation")
def remove_alert(correlation_id: int, alert_id: int, db: DbSession, actor: Writer):
    return correlation_service.remove_alert(db, actor, correlation_id, alert_id)


@router.get("/{correlation_id}/history", response_model=Page[CorrelationHistoryOut],
            summary="Correlation history")
def correlation_history(correlation_id: int, db: DbSession, _: Reader,
                        params: Annotated[PageParams, Depends(page_params)]):
    repo = CorrelationRepository(db)
    repo.require(correlation_id)
    items, total = repo.page(repo.history_stmt(correlation_id), params)
    return make_page(items, total, params)
