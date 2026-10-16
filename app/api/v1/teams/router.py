from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import DbSession, require_permission
from app.core.constants import P
from app.models import SecurityTeam, User
from app.repositories.security_team_repository import SecurityTeamRepository
from app.schemas.common import COMMON_RESPONSES, Page
from app.schemas.security_team import TeamCreate, TeamMemberAdd, TeamOut, TeamType, TeamUpdate
from app.services import team_service
from app.utils.pagination import PageParams, page_params
from app.utils.response import make_page

router = APIRouter(prefix="/teams", tags=["Security Teams"], responses=COMMON_RESPONSES)

Reader = Annotated[User, Depends(require_permission(P.USER_READ))]
Manager = Annotated[User, Depends(require_permission(P.TEAM_MANAGE))]


@router.post("", response_model=TeamOut, status_code=status.HTTP_201_CREATED, summary="Create a security team")
def create_team(data: TeamCreate, db: DbSession, actor: Manager):
    return team_service.create(db, actor, data)


@router.get("", response_model=Page[TeamOut], summary="List teams")
def list_teams(
    db: DbSession,
    _: Reader,
    params: Annotated[PageParams, Depends(page_params)],
    q: str | None = None,
    team_type: TeamType | None = None,
    is_active: bool | None = None,
):
    repo = SecurityTeamRepository(db)
    items, total = repo.page(repo.filtered(q=q, team_type=team_type, is_active=is_active).order_by(SecurityTeam.name),
                             params)
    return make_page(items, total, params)


@router.get("/{team_id}", response_model=TeamOut, summary="Get a team with its members")
def get_team(team_id: int, db: DbSession, _: Reader):
    return SecurityTeamRepository(db).require(team_id)


@router.patch("/{team_id}", response_model=TeamOut, summary="Update a team")
def update_team(team_id: int, data: TeamUpdate, db: DbSession, actor: Manager):
    return team_service.update(db, actor, team_id, data)


@router.post("/{team_id}/members", response_model=TeamOut, summary="Assign an analyst to the team")
def add_member(team_id: int, data: TeamMemberAdd, db: DbSession, actor: Manager):
    return team_service.add_member(db, actor, team_id, data)


@router.delete("/{team_id}/members/{user_id}", response_model=TeamOut, summary="Remove a member from the team")
def remove_member(team_id: int, user_id: int, db: DbSession, actor: Manager):
    return team_service.remove_member(db, actor, team_id, user_id)
