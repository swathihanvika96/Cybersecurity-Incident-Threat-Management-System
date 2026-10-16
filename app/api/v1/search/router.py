"""Unified advanced search across incidents and alerts."""
from datetime import date
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, literal, select, union_all

from app.api.deps import DbSession, require_any_permission
from app.core.constants import SEVERITY_RANK, P
from app.core.permissions import incident_visibility_clause
from app.models import Asset, Incident, SecurityAlert, User
from app.schemas.common import COMMON_RESPONSES, Page
from app.schemas.incident import SearchResultItem
from app.utils.filtering import date_range, escape_like, validate_date_range
from app.utils.pagination import PageParams, page_params
from app.utils.response import make_page
from app.utils.sorting import rank_case

router = APIRouter(prefix="/search", tags=["Search"], responses=COMMON_RESPONSES)

Searcher = Annotated[User, Depends(require_any_permission(P.INCIDENT_READ, P.ALERT_READ))]
SORTABLE = {"created_at", "severity", "status", "title"}


@router.get("", response_model=Page[SearchResultItem], summary="Search incidents and alerts together")
def search(
    db: DbSession,
    user: Searcher,
    params: Annotated[PageParams, Depends(page_params)],
    q: str | None = Query(None, description="Free text over title/description/reference; an exact reference "
                                            "number (INC-/ALR-...) always matches"),
    entity_types: Annotated[list[Literal["incident", "alert"]] | None, Query(
        description="Restrict to incidents and/or alerts (default: both)")] = None,
    severity: Annotated[list[str] | None, Query(description="e.g. critical, high")] = None,
    status: Annotated[list[str] | None, Query(description="Matched against the status of each record type")] = None,
    category: str | None = None,
    asset_id: int | None = None,
    assigned_to_id: int | None = Query(None, description="Analyst (assignee)"),
    department_id: int | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    sort_by: Literal["created_at", "severity", "status", "title"] = "created_at",
    sort_order: Literal["asc", "desc"] = "desc",
):
    """All filters combine with AND. Incidents are returned only when you hold `incident:read` (sensitive ones only
    if you may see them); alerts only when you hold `alert:read`."""
    validate_date_range(date_from, date_to)
    wanted = set(entity_types or ["incident", "alert"])
    pattern = f"%{escape_like(q.strip())}%" if q and q.strip() else None
    selects = []

    def common(stmt, model, text_cols, created_col, assignee_col):
        if pattern:
            from sqlalchemy import or_

            stmt = stmt.where(or_(*[c.ilike(pattern, escape="\\") for c in text_cols],
                                  model.reference == q.strip().upper()))
        if severity:
            stmt = stmt.where(model.severity.in_(severity))
        if status:
            stmt = stmt.where(model.status.in_(status))
        if category:
            stmt = stmt.where(model.category == category)
        if asset_id is not None:
            stmt = stmt.where(model.asset_id == asset_id)
        if assigned_to_id is not None:
            stmt = stmt.where(assignee_col == assigned_to_id)
        if department_id is not None:
            stmt = stmt.where(model.asset_id.in_(select(Asset.id).where(Asset.department_id == department_id)))
        return date_range(stmt, created_col, date_from, date_to)

    if "incident" in wanted and user.has_permission(P.INCIDENT_READ):
        stmt = select(
            literal("incident").label("entity_type"), Incident.id.label("id"), Incident.reference.label("reference"),
            Incident.title.label("title"), Incident.severity.label("severity"), Incident.status.label("status"),
            Incident.category.label("category"), Incident.asset_id.label("asset_id"),
            Incident.assigned_to_id.label("assigned_to_id"), Incident.created_at.label("created_at"),
        ).where(incident_visibility_clause(user))
        selects.append(common(stmt, Incident, [Incident.title, Incident.description, Incident.reference],
                              Incident.created_at, Incident.assigned_to_id))
    if "alert" in wanted and user.has_permission(P.ALERT_READ):
        stmt = select(
            literal("alert").label("entity_type"), SecurityAlert.id.label("id"),
            SecurityAlert.reference.label("reference"), SecurityAlert.title.label("title"),
            SecurityAlert.severity.label("severity"), SecurityAlert.status.label("status"),
            SecurityAlert.category.label("category"), SecurityAlert.asset_id.label("asset_id"),
            SecurityAlert.assigned_to_id.label("assigned_to_id"), SecurityAlert.detected_at.label("created_at"),
        )
        selects.append(common(stmt, SecurityAlert, [SecurityAlert.title, SecurityAlert.description,
                                                    SecurityAlert.reference, SecurityAlert.source],
                              SecurityAlert.detected_at, SecurityAlert.assigned_to_id))
    if not selects:
        return make_page([], 0, params)

    combined = (selects[0] if len(selects) == 1 else union_all(*selects)).subquery("results")
    total = db.scalar(select(func.count()).select_from(combined)) or 0
    order_col = {
        "created_at": combined.c.created_at, "title": combined.c.title, "status": combined.c.status,
        "severity": rank_case(combined.c.severity, SEVERITY_RANK),
    }[sort_by]
    order = order_col.desc() if sort_order == "desc" else order_col.asc()
    rows = db.execute(
        select(combined).order_by(order, combined.c.entity_type, combined.c.id.desc())
        .limit(params.size).offset(params.offset)
    ).mappings().all()
    return make_page([dict(r) for r in rows], total, params)
