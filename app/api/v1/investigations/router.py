from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import DbSession, require_permission
from app.core.constants import InvestigationStatus, P
from app.models import User
from app.repositories.investigation_repository import InvestigationRepository
from app.schemas.common import COMMON_RESPONSES, Page
from app.schemas.incident import NoteCreate
from app.schemas.investigation import (
    InvestigationComplete,
    InvestigationCreate,
    InvestigationLink,
    InvestigationOut,
    InvestigationUpdate,
    OwnerChange,
)
from app.schemas.investigation_evidence import EvidenceCreate, EvidenceOut
from app.schemas.investigation_note import NoteOut
from app.services import investigation_service as svc
from app.utils.pagination import PageParams, page_params
from app.utils.response import make_page

router = APIRouter(prefix="/investigations", tags=["Investigations"], responses=COMMON_RESPONSES)

Reader = Annotated[User, Depends(require_permission(P.INVESTIGATION_READ))]
Writer = Annotated[User, Depends(require_permission(P.INVESTIGATION_WRITE))]
EvidenceReader = Annotated[User, Depends(require_permission(P.EVIDENCE_READ))]


@router.post("", response_model=InvestigationOut, status_code=status.HTTP_201_CREATED,
             summary="Open an investigation")
def create_investigation(data: InvestigationCreate, db: DbSession, actor: Writer):
    return svc.create(db, actor, data)


@router.get("", response_model=Page[InvestigationOut], summary="List investigations")
def list_investigations(
    db: DbSession,
    user: Reader,
    params: Annotated[PageParams, Depends(page_params)],
    q: str | None = None,
    status: InvestigationStatus | None = None,
    owner_id: int | None = None,
    incident_id: int | None = Query(None, description="Investigations linked to this incident"),
):
    """Investigations linked to sensitive incidents are hidden unless you may see those incidents."""
    repo = InvestigationRepository(db)
    items, total = repo.page(repo.filtered(user, q=q, status=status, owner_id=owner_id, incident_id=incident_id),
                             params)
    return make_page(items, total, params)


@router.get("/{investigation_id}", response_model=InvestigationOut, summary="Get an investigation")
def get_investigation(investigation_id: int, db: DbSession, user: Reader):
    return svc.get_accessible(db, user, investigation_id)


@router.patch("/{investigation_id}", response_model=InvestigationOut, summary="Update an investigation")
def update_investigation(investigation_id: int, data: InvestigationUpdate, db: DbSession, user: Writer):
    return svc.update(db, user, svc.get_accessible(db, user, investigation_id), data)


@router.post("/{investigation_id}/links", response_model=InvestigationOut,
             summary="Link incidents, alerts and assets")
def link(investigation_id: int, data: InvestigationLink, db: DbSession, user: Writer):
    return svc.link(db, user, svc.get_accessible(db, user, investigation_id), data)


@router.put("/{investigation_id}/owner", response_model=InvestigationOut, summary="Change the owner")
def change_owner(investigation_id: int, data: OwnerChange, db: DbSession, user: Writer):
    return svc.change_owner(db, user, svc.get_accessible(db, user, investigation_id), data.owner_id)


@router.post("/{investigation_id}/start", response_model=InvestigationOut, summary="Start the investigation")
def start(investigation_id: int, db: DbSession, user: Writer):
    return svc.start(db, user, svc.get_accessible(db, user, investigation_id))


@router.post("/{investigation_id}/complete", response_model=InvestigationOut,
             summary="Complete the investigation with a summary of findings")
def complete(investigation_id: int, data: InvestigationComplete, db: DbSession, user: Writer):
    return svc.complete(db, user, svc.get_accessible(db, user, investigation_id), data.summary)


@router.post("/{investigation_id}/close", response_model=InvestigationOut,
             summary="Close a completed investigation")
def close(investigation_id: int, db: DbSession, user: Writer):
    return svc.close(db, user, svc.get_accessible(db, user, investigation_id))


@router.post("/{investigation_id}/notes", response_model=NoteOut, status_code=status.HTTP_201_CREATED,
             summary="Add an investigation note")
def add_note(investigation_id: int, data: NoteCreate, db: DbSession, user: Writer):
    return svc.add_note(db, user, svc.get_accessible(db, user, investigation_id), data.content)


@router.get("/{investigation_id}/notes", response_model=Page[NoteOut], summary="Investigation notes and events")
def notes(investigation_id: int, db: DbSession, user: Reader, params: Annotated[PageParams, Depends(page_params)]):
    svc.get_accessible(db, user, investigation_id)
    repo = InvestigationRepository(db)
    items, total = repo.page(repo.notes_stmt(investigation_id), params)
    return make_page(items, total, params)


@router.post("/{investigation_id}/evidence", response_model=EvidenceOut, status_code=status.HTTP_201_CREATED,
             summary="Register evidence")
def add_evidence(investigation_id: int, data: EvidenceCreate, db: DbSession, user: Writer):
    """Only a reference (URI / path / ticket) and an optional SHA-256 are stored, never the evidence itself."""
    return svc.add_evidence(db, user, svc.get_accessible(db, user, investigation_id), data)


@router.get("/{investigation_id}/evidence", response_model=list[EvidenceOut],
            summary="List evidence (access is audited)")
def list_evidence(investigation_id: int, db: DbSession, user: EvidenceReader):
    """Requires `evidence:read`, and the investigation must be accessible. Every access writes an audit entry."""
    return svc.list_evidence(db, user, svc.get_accessible(db, user, investigation_id))


@router.get("/{investigation_id}/evidence/{evidence_id}", response_model=EvidenceOut,
            summary="Get one piece of evidence (access is audited)")
def get_evidence(investigation_id: int, evidence_id: int, db: DbSession, user: EvidenceReader):
    return svc.get_evidence(db, user, svc.get_accessible(db, user, investigation_id), evidence_id)
