from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import DbSession, require_permission
from app.core.constants import AssetCriticality, AssetStatus, AssetType, P
from app.models import Asset, User
from app.repositories import asset_repository
from app.repositories.asset_repository import AssetRepository
from app.schemas.asset import (
    AssetCreate,
    AssetHistoryOut,
    AssetOut,
    AssetOwnerAssign,
    AssetStatusUpdate,
    AssetUpdate,
)
from app.schemas.common import COMMON_RESPONSES, Page
from app.services import asset_service
from app.utils.pagination import PageParams, page_params
from app.utils.response import make_page
from app.utils.sorting import apply_sorting

router = APIRouter(prefix="/assets", tags=["Assets"], responses=COMMON_RESPONSES)

Reader = Annotated[User, Depends(require_permission(P.ASSET_READ))]
Manager = Annotated[User, Depends(require_permission(P.ASSET_MANAGE))]


@router.post("", response_model=AssetOut, status_code=status.HTTP_201_CREATED,
             summary="Register an asset (server, endpoint, application or database)")
def create_asset(data: AssetCreate, db: DbSession, actor: Manager):
    return asset_service.create(db, actor, data)


@router.get("", response_model=Page[AssetOut], summary="Search and filter assets")
def list_assets(
    db: DbSession,
    _: Reader,
    params: Annotated[PageParams, Depends(page_params)],
    q: str | None = Query(None, description="Search name, hostname, IP address or description"),
    asset_type: AssetType | None = None,
    criticality: AssetCriticality | None = None,
    status: AssetStatus | None = None,
    organization_id: int | None = None,
    department_id: int | None = None,
    owner_id: int | None = None,
    sort_by: str | None = Query(None, description="name | criticality | created_at | updated_at | status | asset_type"),
    sort_order: Literal["asc", "desc"] = "asc",
):
    repo = AssetRepository(db)
    stmt = repo.filtered(q=q, asset_type=asset_type, criticality=criticality, status=status,
                         organization_id=organization_id, department_id=department_id, owner_id=owner_id)
    stmt = apply_sorting(stmt, asset_repository.SORT_MAP, sort_by, sort_order, "name", tiebreak=Asset.id)
    items, total = repo.page(stmt, params)
    return make_page(items, total, params)


@router.get("/{asset_id}", response_model=AssetOut, summary="Get an asset")
def get_asset(asset_id: int, db: DbSession, _: Reader):
    return AssetRepository(db).require(asset_id)


@router.patch("/{asset_id}", response_model=AssetOut, summary="Update an asset")
def update_asset(asset_id: int, data: AssetUpdate, db: DbSession, actor: Manager):
    """Changing the criticality re-calculates the risk of every open vulnerability on the asset."""
    return asset_service.update(db, actor, asset_id, data)


@router.patch("/{asset_id}/status", response_model=AssetOut, summary="Change the asset status")
def set_asset_status(asset_id: int, data: AssetStatusUpdate, db: DbSession, actor: Manager):
    return asset_service.set_status(db, actor, asset_id, data.status, data.reason)


@router.put("/{asset_id}/owner", response_model=AssetOut, summary="Assign (or clear) the asset owner")
def assign_owner(asset_id: int, data: AssetOwnerAssign, db: DbSession, actor: Manager):
    return asset_service.assign_owner(db, actor, asset_id, data.owner_id)


@router.get("/{asset_id}/history", response_model=Page[AssetHistoryOut], summary="Asset change history")
def asset_history(asset_id: int, db: DbSession, _: Reader, params: Annotated[PageParams, Depends(page_params)]):
    repo = AssetRepository(db)
    repo.require(asset_id)
    items, total = repo.page(repo.history_stmt(asset_id), params)
    return make_page(items, total, params)
