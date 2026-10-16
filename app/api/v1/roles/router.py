from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import DbSession, require_permission
from app.core.constants import P
from app.models import User
from app.repositories.user_repository import RoleRepository
from app.schemas.common import COMMON_RESPONSES, MessageResponse
from app.schemas.permission import PermissionOut
from app.schemas.role import RoleCreate, RoleOut, RolePermissionsUpdate
from app.services import user_service

router = APIRouter(prefix="/roles", tags=["Roles & Permissions"], responses=COMMON_RESPONSES)

Reader = Annotated[User, Depends(require_permission(P.USER_READ))]
Manager = Annotated[User, Depends(require_permission(P.ROLE_MANAGE))]


@router.get("", response_model=list[RoleOut], summary="List roles with their permissions")
def list_roles(db: DbSession, _: Reader):
    return RoleRepository(db).list_all()


@router.get("/permissions", response_model=list[PermissionOut], summary="List every permission in the system")
def list_permissions(db: DbSession, _: Reader):
    return RoleRepository(db).all_permissions()


@router.get("/{role_id}", response_model=RoleOut, summary="Get a role")
def get_role(role_id: int, db: DbSession, _: Reader):
    return RoleRepository(db).require(role_id)


@router.post("", response_model=RoleOut, status_code=status.HTTP_201_CREATED, summary="Create a custom role")
def create_role(data: RoleCreate, db: DbSession, actor: Manager):
    return user_service.create_role(db, actor, data)


@router.put("/{role_id}/permissions", response_model=RoleOut, summary="Replace a role's permission set")
def set_permissions(role_id: int, data: RolePermissionsUpdate, db: DbSession, actor: Manager):
    """The `super_admin` role always holds every permission and cannot be edited."""
    return user_service.set_role_permissions(db, actor, role_id, data.permissions)


@router.delete("/{role_id}", response_model=MessageResponse, summary="Delete a custom role")
def delete_role(role_id: int, db: DbSession, actor: Manager):
    user_service.delete_role(db, actor, role_id)
    return {"message": "Role deleted"}
