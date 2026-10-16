from sqlalchemy import Select, select

from app.models import SecurityTeam, TeamMember
from app.repositories.base import BaseRepository
from app.utils.filtering import text_search


class SecurityTeamRepository(BaseRepository[SecurityTeam]):
    model = SecurityTeam
    label = "Security team"

    def get_by_name(self, name: str) -> SecurityTeam | None:
        return self.db.scalar(select(SecurityTeam).where(SecurityTeam.name == name))

    def filtered(
        self, *, q: str | None = None, team_type: str | None = None, is_active: bool | None = None
    ) -> Select:
        stmt = text_search(select(SecurityTeam), q, SecurityTeam.name, SecurityTeam.description)
        if team_type:
            stmt = stmt.where(SecurityTeam.team_type == team_type)
        if is_active is not None:
            stmt = stmt.where(SecurityTeam.is_active.is_(is_active))
        return stmt

    def get_member(self, team_id: int, user_id: int) -> TeamMember | None:
        return self.db.scalar(select(TeamMember).where(TeamMember.team_id == team_id, TeamMember.user_id == user_id))
