from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import DbSession, require_permission
from app.core.constants import P, Severity
from app.models import User
from app.repositories.sla_repository import SLARepository
from app.schemas.common import COMMON_RESPONSES, Page
from app.schemas.incident_sla import (
    EscalateRequest,
    IncidentSLAOut,
    SLAEvaluationResult,
    SLAHistoryOut,
    SLAIncidentItem,
    SLAPolicyOut,
    SLAPolicyUpdate,
)
from app.services import incident_service, sla_service
from app.core.exceptions import NotFoundError
from app.utils.pagination import PageParams, page_params
from app.utils.response import make_page

router = APIRouter(prefix="/slas", tags=["SLA Management"], responses=COMMON_RESPONSES)

Reader = Annotated[User, Depends(require_permission(P.SLA_READ))]
Manager = Annotated[User, Depends(require_permission(P.SLA_MANAGE))]


@router.get("/policies", response_model=list[SLAPolicyOut], summary="SLA policy per severity")
def policies(db: DbSession, _: Reader):
    """Deadlines are measured from incident creation: acknowledgment (first assignment), investigation start and
    resolution."""
    return SLARepository(db).policies()


@router.put("/policies/{severity}", response_model=SLAPolicyOut, summary="Update an SLA policy")
def update_policy(severity: Severity, data: SLAPolicyUpdate, db: DbSession, actor: Manager):
    """Applies to incidents created afterwards; open incidents keep their deadlines until their severity changes."""
    return sla_service.update_policy(db, actor, severity.value, data)


@router.get("/breached", response_model=Page[SLAIncidentItem], summary="Incidents that breached an SLA")
def breached(db: DbSession, user: Reader, params: Annotated[PageParams, Depends(page_params)],
             include_resolved: bool = Query(False)):
    items, total = sla_service.list_breached(db, user, params, include_resolved)
    return make_page(items, total, params)


@router.get("/approaching", response_model=Page[SLAIncidentItem], summary="Incidents approaching a deadline")
def approaching(db: DbSession, user: Reader, params: Annotated[PageParams, Depends(page_params)]):
    items, total = sla_service.list_approaching(db, user, params)
    return make_page(items, total, params)


@router.get("/escalated", response_model=Page[SLAIncidentItem], summary="Escalated incidents")
def escalated(db: DbSession, user: Reader, params: Annotated[PageParams, Depends(page_params)]):
    items, total = sla_service.list_escalated(db, user, params)
    return make_page(items, total, params)


@router.post("/evaluate", response_model=SLAEvaluationResult, summary="Evaluate all open incidents now")
def evaluate(db: DbSession, _: Manager):
    """The same check the background monitor runs: updates SLA status, flags breaches, escalates and notifies."""
    return sla_service.evaluate_all_open(db)


@router.get("/incidents/{incident_id}", response_model=IncidentSLAOut, summary="SLA of an incident")
def incident_sla(incident_id: int, db: DbSession, user: Reader):
    incident = incident_service.get_visible(db, user, incident_id)
    sla = SLARepository(db).for_incident(incident.id)
    if sla is None:
        raise NotFoundError(f"Incident {incident_id} has no SLA")
    sla_service.apply_evaluation(db, incident, sla)
    db.commit()
    return sla


@router.post("/incidents/{incident_id}/escalate", response_model=IncidentSLAOut, summary="Escalate manually")
def escalate(incident_id: int, data: EscalateRequest, db: DbSession, actor: Manager):
    incident = incident_service.get_visible(db, actor, incident_id)
    return sla_service.manual_escalate(db, actor, incident, data.reason)


@router.get("/incidents/{incident_id}/history", response_model=Page[SLAHistoryOut], summary="SLA history")
def sla_history(incident_id: int, db: DbSession, user: Reader, params: Annotated[PageParams, Depends(page_params)]):
    incident_service.get_visible(db, user, incident_id)
    repo = SLARepository(db)
    items, total = repo.page(repo.history_stmt(incident_id), params)
    return make_page(items, total, params)
