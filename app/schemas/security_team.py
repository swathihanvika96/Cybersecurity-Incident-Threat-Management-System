from typing import Literal

from pydantic import Field

from app.schemas.common import DT, ORMModel, RequestModel
from app.schemas.user import UserBrief

TeamType = Literal["security", "it"]
MemberRole = Literal["lead", "analyst"]


class TeamCreate(RequestModel):
    name: str = Field(min_length=2, max_length=150)
    description: str | None = None
    team_type: TeamType = "security"
    manager_id: int | None = None


class TeamUpdate(RequestModel):
    name: str | None = Field(None, min_length=2, max_length=150)
    description: str | None = None
    manager_id: int | None = None
    is_active: bool | None = None


class TeamMemberAdd(RequestModel):
    user_id: int
    member_role: MemberRole = "analyst"


class TeamMemberOut(ORMModel):
    user: UserBrief
    member_role: str
    added_at: DT


class TeamBrief(ORMModel):
    id: int
    name: str


class TeamOut(ORMModel):
    id: int
    name: str
    description: str | None = None
    team_type: str
    manager: UserBrief | None = None
    is_active: bool
    members: list[TeamMemberOut] = []
    created_at: DT
