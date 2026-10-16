from datetime import date
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import CurrentUser, DbSession, require_permission
from app.core.constants import IncidentStatus, P, SecurityCategory, Severity
from app.core.permissions import ensure_can_view_incident
from app.models import Incident, User
from app.repositories import incident_repository
from app.repositories.incident_repository import IncidentRepository
from app.schemas.common import COMMON_RESPONSES, Page
from app.schemas.incident import (
    ClosureDecision,
    ClosureRequest,
    IncidentAssign,
    IncidentAssignmentOut,
    IncidentCreate,
    IncidentDetail,
    IncidentHistoryOut,
    IncidentLinkAlerts,
    IncidentOut,
    IncidentRelationCreate,
    IncidentRelationOut,
    IncidentResolve,
    IncidentStatusUpdate,
    IncidentUpdate,
    NoteCreate,
)
from app.schemas.investigation_note import NoteOut
from app.services import incident_lifecycle_service as lifecycle
from app.services import incident_service
from app.utils.pagination import PageParams, page_params
from app.utils.response import make_page
from app.utils.sorting import apply_sorting

router = APIRouter(prefix="/incidents", tags=["Incidents"], responses=COMMON_RESPONSES)

Reader = Annotated[User, Depends(require_permission(P.INCIDENT_READ))]
Writer = Annotated[User, Depends(require_permission(P.INCIDENT_WRITE))]
Approver = Annotated[User, Depends(require_permission(P.INCIDENT_APPROVE_CLOSURE))]


def _incident(db, user: User, incident_id: int) -> Incident:
    return incident_service.get_visible(db, user, incident_id)


@router.post("", response_model=IncidentDetail, status_code=status.HTTP_201_CREATED,
             summary="Create an incident (from alerts, a correlation group, or manually)")
def create_incident(data: IncidentCreate, db: DbSession, actor: Writer):
    """Severity defaults to the highest linked-alert severity; an SLA is attached automatically.

    **Duplicate-incident rule:** if an *open* incident already exists for the same asset and category created within
    `DUPLICATE_INCIDENT_WINDOW_HOURS`, the request is rejected with `409 duplicate_incident` unless
    `allow_duplicate=true` (the new incident is then linked to the existing one as `possible_duplicate`)."""
    return incident_service.create(db, actor, data)


@router.get("", response_model=Page[IncidentOut], summary="List incidents")
def list_incidents(
    db: DbSession,
    user: Reader,
    params: Annotated[PageParams, Depends(page_params)],
    q: str | None = Query(None, description="Search title, description or reference"),
    reference: str | None = Query(None, description="Exact reference number, e.g. INC-2026-000012"),
    status: Annotated[list[IncidentStatus] | None, Query()] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    category: SecurityCategory | None = None,
    asset_id: int | None = None,
    department_id: int | None = None,
    assigned_to_id: int | None = None,
    created_by_id: int | None = None,
    is_sensitive: bool | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    sort_by: str | None = Query(None, description="created_at | updated_at | severity | status | title | reference"),
    sort_order: Literal["asc", "desc"] = "desc",
):
    """Sensitive incidents are omitted unless you hold `incident:sensitive`, are the assignee, or the creator."""
    repo = IncidentRepository(db)
    stmt = repo.filtered(user, q=q, reference=reference, status=status, severity=severity, category=category,
                         asset_id=asset_id, department_id=department_id, assigned_to_id=assigned_to_id,
                         created_by_id=created_by_id, is_sensitive=is_sensitive, date_from=date_from,
                         date_to=date_to)
    stmt = apply_sorting(stmt, incident_repository.SORT_MAP, sort_by, sort_order, "created_at", tiebreak=Incident.id)
    items, total = repo.page(stmt, params)
    return make_page(items, total, params)


@router.get("/{incident_id}", response_model=IncidentDetail, summary="Get an incident with its linked alerts")
def get_incident(incident_id: int, db: DbSession, user: Reader):
    return _incident(db, user, incident_id)


@router.patch("/{incident_id}", response_model=IncidentOut, summary="Update an incident")
def update_incident(incident_id: int, data: IncidentUpdate, db: DbSession, user: Writer):
    """A severity change is audited, written to the history and re-applies the SLA policy of the new severity."""
    return incident_service.update(db, user, _incident(db, user, incident_id), data)


@router.post("/{incident_id}/assign", response_model=IncidentOut, summary="Assign a responsible analyst")
def assign_incident(incident_id: int, data: IncidentAssign, db: DbSession, user: Writer):
    """Managers assign anyone; analysts can only claim an unassigned incident. The first assignment is the SLA
    acknowledgment and moves the incident from `new` to `assigned`."""
    incident = _incident(db, user, incident_id)
    return lifecycle.assign(db, user, incident, data.assigned_to_id, data.comment)


@router.patch("/{incident_id}/status", response_model=IncidentOut, summary="Change the incident status")
def change_status(incident_id: int, data: IncidentStatusUpdate, db: DbSession, user: Writer):
    """assigned -> investigating <-> containment; resolved -> investigating (re-open). Use `/resolve` to resolve and
    the closure endpoints to close."""
    return lifecycle.change_status(db, user, _incident(db, user, incident_id), data.status, data.comment)


@router.post("/{incident_id}/resolve", response_model=IncidentOut, summary="Resolve an incident")
def resolve_incident(incident_id: int, data: IncidentResolve, db: DbSession, user: Writer):
    return lifecycle.resolve(db, user, _incident(db, user, incident_id), data)


@router.post("/{incident_id}/closure/request", response_model=IncidentOut, summary="Request closure approval")
def request_closure(incident_id: int, db: DbSession, user: Writer, data: ClosureRequest | None = None):
    return lifecycle.request_closure(db, user, _incident(db, user, incident_id), data.comment if data else None)


@router.post("/{incident_id}/closure/approve", response_model=IncidentOut, summary="Approve closure")
def approve_closure(incident_id: int, db: DbSession, user: Approver, data: ClosureDecision | None = None):
    """Four-eyes rule: the approver must be a different person from the one who requested the closure."""
    return lifecycle.approve_closure(db, user, _incident(db, user, incident_id), data.comment if data else None)


@router.post("/{incident_id}/closure/reject", response_model=IncidentOut, summary="Reject closure")
def reject_closure(incident_id: int, data: ClosureDecision, db: DbSession, user: Approver):
    """Re-opens the incident (`investigating`); a comment is required."""
    return lifecycle.reject_closure(db, user, _incident(db, user, incident_id), data.comment)


@router.post("/{incident_id}/alerts", response_model=IncidentDetail, summary="Link more alerts to the incident")
def link_alerts(incident_id: int, data: IncidentLinkAlerts, db: DbSession, user: Writer):
    return incident_service.link_alerts(db, user, _incident(db, user, incident_id), data.alert_ids)


@router.post("/{incident_id}/related", response_model=IncidentRelationOut, status_code=status.HTTP_201_CREATED,
             summary="Mark another incident as related")
def add_related(incident_id: int, data: IncidentRelationCreate, db: DbSession, user: Writer):
    return incident_service.add_relation(db, user, _incident(db, user, incident_id), data)


@router.get("/{incident_id}/related", response_model=list[IncidentRelationOut], summary="Related incidents")
def related(incident_id: int, db: DbSession, user: Reader):
    return incident_service.visible_relations(db, user, _incident(db, user, incident_id))


@router.post("/{incident_id}/notes", response_model=NoteOut, status_code=status.HTTP_201_CREATED,
             summary="Add an investigation note")
def add_note(incident_id: int, data: NoteCreate, db: DbSession, user: Writer):
    return incident_service.add_note(db, user, _incident(db, user, incident_id), data.content)


@router.get("/{incident_id}/notes", response_model=Page[NoteOut], summary="Investigation notes")
def notes(incident_id: int, db: DbSession, user: Reader, params: Annotated[PageParams, Depends(page_params)]):
    _incident(db, user, incident_id)
    repo = IncidentRepository(db)
    items, total = repo.page(repo.notes_stmt(incident_id), params)
    return make_page(items, total, params)


@router.get("/{incident_id}/history", response_model=Page[IncidentHistoryOut], summary="Incident history")
def history(incident_id: int, db: DbSession, user: Reader, params: Annotated[PageParams, Depends(page_params)]):
    _incident(db, user, incident_id)
    repo = IncidentRepository(db)
    items, total = repo.page(repo.history_stmt(incident_id), params)
    return make_page(items, total, params)


@router.get("/{incident_id}/assignments", response_model=Page[IncidentAssignmentOut],
            summary="Assignment history")
def assignments(incident_id: int, db: DbSession, user: Reader, params: Annotated[PageParams, Depends(page_params)]):
    _incident(db, user, incident_id)
    repo = IncidentRepository(db)
    items, total = repo.page(repo.assignments_stmt(incident_id), params)
    return make_page(items, total, params)
