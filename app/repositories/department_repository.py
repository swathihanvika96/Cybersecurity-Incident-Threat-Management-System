from sqlalchemy import Select, select

from app.models import Department
from app.repositories.base import BaseRepository
from app.utils.filtering import text_search


class DepartmentRepository(BaseRepository[Department]):
    model = Department
    label = "Department"

    def get_by_name(self, organization_id: int, name: str) -> Department | None:
        return self.db.scalar(
            select(Department).where(Department.organization_id == organization_id, Department.name == name)
        )

    def filtered(
        self, *, organization_id: int | None = None, q: str | None = None, is_active: bool | None = None
    ) -> Select:
        stmt = text_search(select(Department), q, Department.name)
        if organization_id is not None:
            stmt = stmt.where(Department.organization_id == organization_id)
        if is_active is not None:
            stmt = stmt.where(Department.is_active.is_(is_active))
        return stmt
