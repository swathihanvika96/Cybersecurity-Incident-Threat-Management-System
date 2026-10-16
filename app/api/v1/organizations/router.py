from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import DbSession, require_permission
from app.core.constants import P
from app.models import Organization, User
from app.repositories.organization_repository import OrganizationRepository
from app.schemas.common import COMMON_RESPONSES, Page
from app.schemas.organization import OrganizationCreate, OrganizationOut, OrganizationUpdate
from app.services import organization_service
from app.utils.pagination import PageParams, page_params
from app.utils.response import make_page

router = APIRouter(prefix="/organizations", tags=["Organizations"], responses=COMMON_RESPONSES)

Reader = Annotated[User, Depends(require_permission(P.ORG_READ))]
Manager = Annotated[User, Depends(require_permission(P.ORG_MANAGE))]


@router.post("", response_model=OrganizationOut, status_code=status.HTTP_201_CREATED, summary="Register an organization")
def create_organization(data: OrganizationCreate, db: DbSession, actor: Manager):
    return organization_service.create(db, actor, data)


@router.get("", response_model=Page[OrganizationOut], summary="List organizations")
def list_organizations(
    db: DbSession,
    _: Reader,
    params: Annotated[PageParams, Depends(page_params)],
    q: str | None = Query(None, description="Search name or industry"),
    is_active: bool | None = None,
):
    repo = OrganizationRepository(db)
    items, total = repo.page(repo.filtered(q=q, is_active=is_active).order_by(Organization.name), params)
    return make_page(items, total, params)


@router.get("/{organization_id}", response_model=OrganizationOut, summary="Get an organization")
def get_organization(organization_id: int, db: DbSession, _: Reader):
    return OrganizationRepository(db).require(organization_id)


@router.patch("/{organization_id}", response_model=OrganizationOut, summary="Update an organization")
def update_organization(organization_id: int, data: OrganizationUpdate, db: DbSession, actor: Manager):
    return organization_service.update(db, actor, organization_id, data)
