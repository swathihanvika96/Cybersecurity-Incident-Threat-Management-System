from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import DbSession, require_permission
from app.core.constants import AssetCriticality, AssetStatus, AssetType, P
from app.models import Department, User
from app.repositories import asset_repository
from app.repositories.asset_repository import AssetRepository
from app.repositories.department_repository import DepartmentRepository
from app.schemas.asset import AssetOut
from app.schemas.common import COMMON_RESPONSES, Page
from app.schemas.department import DepartmentCreate, DepartmentOut, DepartmentUpdate
from app.services import department_service
from app.utils.pagination import PageParams, page_params
from app.utils.response import make_page
from app.utils.sorting import apply_sorting

router = APIRouter(prefix="/departments", tags=["Departments"], responses=COMMON_RESPONSES)

Reader = Annotated[User, Depends(require_permission(P.ORG_READ))]
Manager = Annotated[User, Depends(require_permission(P.ORG_MANAGE))]
AssetReader = Annotated[User, Depends(require_permission(P.ORG_READ, P.ASSET_READ))]


@router.post("", response_model=DepartmentOut, status_code=status.HTTP_201_CREATED, summary="Register a department")
def create_department(data: DepartmentCreate, db: DbSession, actor: Manager):
    return department_service.create(db, actor, data)


@router.get("", response_model=Page[DepartmentOut], summary="List departments")
def list_departments(
    db: DbSession,
    _: Reader,
    params: Annotated[PageParams, Depends(page_params)],
    organization_id: int | None = None,
    q: str | None = None,
    is_active: bool | None = None,
):
    repo = DepartmentRepository(db)
    stmt = repo.filtered(organization_id=organization_id, q=q, is_active=is_active).order_by(
        Department.organization_id, Department.name)
    items, total = repo.page(stmt, params)
    return make_page(items, total, params)


@router.get("/{department_id}", response_model=DepartmentOut, summary="Get a department")
def get_department(department_id: int, db: DbSession, _: Reader):
    return DepartmentRepository(db).require(department_id)


@router.patch("/{department_id}", response_model=DepartmentOut, summary="Update a department")
def update_department(department_id: int, data: DepartmentUpdate, db: DbSession, actor: Manager):
    return department_service.update(db, actor, department_id, data)


@router.get("/{department_id}/assets", response_model=Page[AssetOut], summary="View assets by department")
def department_assets(
    department_id: int,
    db: DbSession,
    _: AssetReader,
    params: Annotated[PageParams, Depends(page_params)],
    asset_type: AssetType | None = None,
    criticality: AssetCriticality | None = None,
    status: AssetStatus | None = None,
    sort_by: str | None = Query(None, description="name | criticality | created_at | updated_at | status | asset_type"),
    sort_order: Literal["asc", "desc"] = "asc",
):
    DepartmentRepository(db).require(department_id)
    repo = AssetRepository(db)
    stmt = repo.filtered(department_id=department_id, asset_type=asset_type, criticality=criticality, status=status)
    stmt = apply_sorting(stmt, asset_repository.SORT_MAP, sort_by, sort_order, "name", tiebreak=asset_repository.Asset.id)
    items, total = repo.page(stmt, params)
    return make_page(items, total, params)
