from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import DbSession, require_permission
from app.core.constants import P
from app.models import User
from app.repositories.user_repository import UserRepository
from app.schemas.common import COMMON_RESPONSES, Page
from app.schemas.user import RoleAssign, StatusChange, UserCreate, UserOut, UserUpdate
from app.services import user_service
from app.utils.pagination import PageParams, page_params
from app.utils.response import make_page

router = APIRouter(prefix="/users", tags=["Users"], responses=COMMON_RESPONSES)

Reader = Annotated[User, Depends(require_permission(P.USER_READ))]
Manager = Annotated[User, Depends(require_permission(P.USER_MANAGE))]


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED, summary="Create a user")
def create_user(data: UserCreate, db: DbSession, actor: Manager):
    """Administrator-created account (active immediately unless `is_active=false`). You cannot assign a role that
    carries permissions you do not hold yourself; only super admins can create super admins."""
    return user_service.create_user(db, actor, data)


@router.get("", response_model=Page[UserOut], summary="List users")
def list_users(
    db: DbSession,
    _: Reader,
    params: Annotated[PageParams, Depends(page_params)],
    q: str | None = Query(None, description="Search name or e-mail"),
    role_id: int | None = None,
    is_active: bool | None = None,
    organization_id: int | None = None,
    department_id: int | None = None,
):
    repo = UserRepository(db)
    stmt = repo.filtered(q=q, role_id=role_id, is_active=is_active, organization_id=organization_id,
                         department_id=department_id).order_by(User.full_name, User.id)
    items, total = repo.page(stmt, params)
    return make_page(items, total, params)


@router.get("/{user_id}", response_model=UserOut, summary="Get a user")
def get_user(user_id: int, db: DbSession, _: Reader):
    return UserRepository(db).require(user_id)


@router.patch("/{user_id}", response_model=UserOut, summary="Update a user")
def update_user(user_id: int, data: UserUpdate, db: DbSession, actor: Manager):
    return user_service.update_user(db, actor, user_id, data)


@router.put("/{user_id}/role", response_model=UserOut, summary="Assign a role")
def assign_role(user_id: int, data: RoleAssign, db: DbSession, actor: Manager):
    """Role changes are audited and take effect on the user's next request."""
    return user_service.assign_role(db, actor, user_id, data.role_id)


@router.post("/{user_id}/activate", response_model=UserOut, summary="Activate an account")
def activate(user_id: int, db: DbSession, actor: Manager, data: StatusChange | None = None):
    return user_service.set_active(db, actor, user_id, True, data.reason if data else None)


@router.post("/{user_id}/deactivate", response_model=UserOut, summary="Deactivate an account")
def deactivate(user_id: int, db: DbSession, actor: Manager, data: StatusChange | None = None):
    """Blocks login and immediately revokes every session of the user. You cannot deactivate yourself or the last
    active super admin."""
    return user_service.set_active(db, actor, user_id, False, data.reason if data else None)
