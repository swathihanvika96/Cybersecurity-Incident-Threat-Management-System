from sqlalchemy import Select, select

from app.models import Organization
from app.repositories.base import BaseRepository
from app.utils.filtering import text_search


class OrganizationRepository(BaseRepository[Organization]):
    model = Organization
    label = "Organization"

    def get_by_name(self, name: str) -> Organization | None:
        return self.db.scalar(select(Organization).where(Organization.name == name))

    def filtered(self, *, q: str | None = None, is_active: bool | None = None) -> Select:
        stmt = text_search(select(Organization), q, Organization.name, Organization.industry)
        if is_active is not None:
            stmt = stmt.where(Organization.is_active.is_(is_active))
        return stmt
