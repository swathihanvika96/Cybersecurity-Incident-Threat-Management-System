from sqlalchemy import Select, func, or_, select

from app.core.constants import RoleName
from app.models import Permission, Role, User, role_permissions
from app.repositories.base import BaseRepository
from app.utils.filtering import text_search


class UserRepository(BaseRepository[User]):
    model = User
    label = "User"

    def get_by_email(self, email: str) -> User | None:
        return self.db.scalar(select(User).where(User.email == email.strip().lower()))

    def filtered(
        self,
        *,
        q: str | None = None,
        role_id: int | None = None,
        is_active: bool | None = None,
        organization_id: int | None = None,
        department_id: int | None = None,
    ) -> Select:
        stmt = select(User)
        stmt = text_search(stmt, q, User.full_name, User.email)
        if role_id is not None:
            stmt = stmt.where(User.role_id == role_id)
        if is_active is not None:
            stmt = stmt.where(User.is_active.is_(is_active))
        if organization_id is not None:
            stmt = stmt.where(User.organization_id == organization_id)
        if department_id is not None:
            stmt = stmt.where(User.department_id == department_id)
        return stmt

    def with_permission(self, permission: str) -> list[User]:
        """Active users whose role grants `permission` (super admins always qualify)."""
        granting_roles = (
            select(role_permissions.c.role_id)
            .join(Permission, Permission.id == role_permissions.c.permission_id)
            .where(Permission.name == permission)
        )
        stmt = (
            select(User)
            .join(Role, Role.id == User.role_id)
            .where(User.is_active.is_(True))
            .where(or_(Role.name == RoleName.SUPER_ADMIN.value, Role.id.in_(granting_roles)))
            .order_by(User.id)
        )
        return list(self.db.scalars(stmt).unique())

    def count_active_super_admins(self, exclude_user_id: int | None = None) -> int:
        stmt = (
            select(func.count(User.id))
            .join(Role, Role.id == User.role_id)
            .where(Role.name == RoleName.SUPER_ADMIN.value, User.is_active.is_(True))
        )
        if exclude_user_id is not None:
            stmt = stmt.where(User.id != exclude_user_id)
        return self.db.scalar(stmt) or 0


class RoleRepository(BaseRepository[Role]):
    model = Role
    label = "Role"

    def get_by_name(self, name: str) -> Role | None:
        return self.db.scalar(select(Role).where(Role.name == name))

    def list_all(self) -> list[Role]:
        return list(self.db.scalars(select(Role).order_by(Role.id)))

    def permissions_by_names(self, names: list[str]) -> list[Permission]:
        if not names:
            return []
        return list(self.db.scalars(select(Permission).where(Permission.name.in_(names))))

    def all_permissions(self) -> list[Permission]:
        return list(self.db.scalars(select(Permission).order_by(Permission.name)))

    def user_count(self, role_id: int) -> int:
        return self.db.scalar(select(func.count(User.id)).where(User.role_id == role_id)) or 0
