"""Security teams and analyst assignment."""
from sqlalchemy.orm import Session

from app.core.exceptions import BadRequestError, ConflictError, NotFoundError
from app.models import SecurityTeam, TeamMember, User
from app.repositories.security_team_repository import SecurityTeamRepository
from app.repositories.user_repository import UserRepository
from app.schemas.security_team import TeamCreate, TeamMemberAdd, TeamUpdate
from app.services import audit_service

FIELDS = ("name", "description", "team_type", "manager_id", "is_active")


def _active_user(db: Session, user_id: int, label: str) -> User:
    user = UserRepository(db).get(user_id)
    if user is None:
        raise NotFoundError(f"{label} {user_id} not found")
    if not user.is_active:
        raise BadRequestError(f"{label} {user_id} is not active")
    return user


def create(db: Session, actor: User, data: TeamCreate) -> SecurityTeam:
    repo = SecurityTeamRepository(db)
    if repo.get_by_name(data.name):
        raise ConflictError("A team with this name already exists")
    if data.manager_id is not None:
        _active_user(db, data.manager_id, "Manager")
    team = repo.add(SecurityTeam(**data.model_dump()))
    audit_service.record(db, user_id=actor.id, action="team.create", entity_type="security_team",
                         entity_id=team.id, new=audit_service.snapshot(team, FIELDS))
    db.commit()
    db.refresh(team)
    return team


def update(db: Session, actor: User, team_id: int, data: TeamUpdate) -> SecurityTeam:
    repo = SecurityTeamRepository(db)
    team = repo.require(team_id)
    values = data.model_dump(exclude_unset=True)
    if "name" in values and values["name"] != team.name and repo.get_by_name(values["name"]):
        raise ConflictError("A team with this name already exists")
    if values.get("manager_id") is not None:
        _active_user(db, values["manager_id"], "Manager")
    before = audit_service.snapshot(team, FIELDS)
    for key, value in values.items():
        setattr(team, key, value)
    prev, new = audit_service.changes(before, audit_service.snapshot(team, FIELDS))
    if new:
        audit_service.record(db, user_id=actor.id, action="team.update", entity_type="security_team",
                             entity_id=team.id, previous=prev, new=new)
    db.commit()
    db.refresh(team)
    return team


def add_member(db: Session, actor: User, team_id: int, data: TeamMemberAdd) -> SecurityTeam:
    repo = SecurityTeamRepository(db)
    team = repo.require(team_id)
    if not team.is_active:
        raise BadRequestError("Cannot add members to an inactive team")
    _active_user(db, data.user_id, "User")
    if repo.get_member(team_id, data.user_id):
        raise ConflictError("User is already a member of this team")
    db.add(TeamMember(team_id=team_id, user_id=data.user_id, member_role=data.member_role))
    audit_service.record(db, user_id=actor.id, action="team.member_add", entity_type="security_team",
                         entity_id=team_id, new={"user_id": data.user_id, "member_role": data.member_role})
    db.commit()
    db.refresh(team)
    return team


def remove_member(db: Session, actor: User, team_id: int, user_id: int) -> SecurityTeam:
    repo = SecurityTeamRepository(db)
    team = repo.require(team_id)
    member = repo.get_member(team_id, user_id)
    if member is None:
        raise NotFoundError(f"User {user_id} is not a member of team {team_id}")
    db.delete(member)
    audit_service.record(db, user_id=actor.id, action="team.member_remove", entity_type="security_team",
                         entity_id=team_id, previous={"user_id": user_id, "member_role": member.member_role})
    db.commit()
    db.refresh(team)
    return team
