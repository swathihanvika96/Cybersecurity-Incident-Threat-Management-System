"""User administration, role assignment and role/permission management."""
from sqlalchemy.orm import Session

from app.core.constants import ALL_PERMISSIONS, RoleName
from app.core.exceptions import BadRequestError, ConflictError, ForbiddenError, NotFoundError
from app.core.security import hash_password
from app.models import Department, Organization, Role, User
from app.repositories.user_repository import RoleRepository, UserRepository
from app.schemas.role import RoleCreate
from app.schemas.user import UserCreate, UserUpdate
from app.services import audit_service, auth_service
from app.utils.date_utils import utcnow

USER_AUDIT_FIELDS = ("email", "full_name", "phone", "role_id", "organization_id", "department_id", "is_active")


# --------------------------------------------------------------------------- guards
def _guard_privileged(actor: User, target_role: Role | None, target_user: User | None = None) -> None:
    """Privilege-escalation guards.

    * only a super admin may grant the super_admin role or modify a super admin account;
    * nobody can hand out a role carrying permissions they do not hold themselves.
    """
    if actor.is_super_admin:
        return
    if target_role is not None:
        if target_role.name == RoleName.SUPER_ADMIN.value:
            raise ForbiddenError("Only a super admin can assign the super_admin role")
        if not {p.name for p in target_role.permissions} <= set(actor.permission_names):
            raise ForbiddenError("You cannot assign a role that carries permissions you do not hold yourself")
    if target_user is not None and target_user.is_super_admin:
        raise ForbiddenError("Only a super admin can modify a super admin account")


def _validate_org_dept(db: Session, organization_id: int | None, department_id: int | None) -> None:
    if organization_id is not None and db.get(Organization, organization_id) is None:
        raise NotFoundError(f"Organization {organization_id} not found")
    if department_id is not None:
        dept = db.get(Department, department_id)
        if dept is None:
            raise NotFoundError(f"Department {department_id} not found")
        if organization_id is not None and dept.organization_id != organization_id:
            raise BadRequestError("Department does not belong to the given organization")


# --------------------------------------------------------------------------- users
def create_user(db: Session, actor: User, data: UserCreate) -> User:
    repo = UserRepository(db)
    if repo.get_by_email(data.email):
        raise ConflictError("A user with this email already exists")
    role = RoleRepository(db).require(data.role_id) if data.role_id is not None else None
    _guard_privileged(actor, role)
    _validate_org_dept(db, data.organization_id, data.department_id)
    user = User(
        email=data.email,
        full_name=data.full_name,
        phone=data.phone,
        hashed_password=hash_password(data.password),
        role_id=data.role_id,
        organization_id=data.organization_id,
        department_id=data.department_id,
        is_active=data.is_active,
    )
    repo.add(user)
    audit_service.record(db, user_id=actor.id, action="user.create", entity_type="user", entity_id=user.id,
                         new=audit_service.snapshot(user, USER_AUDIT_FIELDS))
    db.commit()
    db.refresh(user)
    return user


def update_user(db: Session, actor: User, user_id: int, data: UserUpdate) -> User:
    user = UserRepository(db).require(user_id)
    _guard_privileged(actor, None, user)
    values = data.model_dump(exclude_unset=True)
    if "role_id" in values:
        raise BadRequestError("Use PUT /users/{id}/role to change a role")
    org_id = values.get("organization_id", user.organization_id)
    _validate_org_dept(db, org_id, values.get("department_id", user.department_id))
    before = audit_service.snapshot(user, USER_AUDIT_FIELDS)
    for key, value in values.items():
        setattr(user, key, value)
    prev, new = audit_service.changes(before, audit_service.snapshot(user, USER_AUDIT_FIELDS))
    if new:
        audit_service.record(db, user_id=actor.id, action="user.update", entity_type="user", entity_id=user.id,
                             previous=prev, new=new)
    db.commit()
    return user


def assign_role(db: Session, actor: User, user_id: int, role_id: int | None) -> User:
    user = UserRepository(db).require(user_id)
    role = RoleRepository(db).require(role_id) if role_id is not None else None
    _guard_privileged(actor, role, user)
    if user.id == actor.id:
        raise BadRequestError("You cannot change your own role")
    if user.is_super_admin and (role is None or role.name != RoleName.SUPER_ADMIN.value) and user.is_active:
        if UserRepository(db).count_active_super_admins(exclude_user_id=user.id) == 0:
            raise BadRequestError("Cannot remove the last active super admin")
    previous = {"role_id": user.role_id, "role": user.role_name}
    user.role_id = role.id if role else None
    db.flush()
    db.refresh(user)
    audit_service.record(db, user_id=actor.id, action="user.role_change", entity_type="user", entity_id=user.id,
                         previous=previous, new={"role_id": user.role_id, "role": user.role_name})
    db.commit()
    return user


def set_active(db: Session, actor: User, user_id: int, active: bool, reason: str | None) -> User:
    user = UserRepository(db).require(user_id)
    _guard_privileged(actor, None, user)
    if user.is_active == active:
        raise ConflictError(f"User is already {'active' if active else 'inactive'}")
    if not active:
        if user.id == actor.id:
            raise BadRequestError("You cannot deactivate your own account")
        if user.is_super_admin and UserRepository(db).count_active_super_admins(exclude_user_id=user.id) == 0:
            raise BadRequestError("Cannot deactivate the last active super admin")
    user.is_active = active
    user.deactivated_at = None if active else utcnow()
    if not active:
        auth_service.revoke_all_sessions(db, user.id)  # kills existing access/refresh tokens
    audit_service.record(
        db, user_id=actor.id, action="user.activate" if active else "user.deactivate", entity_type="user",
        entity_id=user.id, previous={"is_active": not active}, new={"is_active": active, "reason": reason},
    )
    db.commit()
    return user


# --------------------------------------------------------------------------- roles / permissions
def _validate_permissions(names: list[str]) -> list[str]:
    unknown = sorted(set(names) - set(ALL_PERMISSIONS))
    if unknown:
        raise BadRequestError("Unknown permissions", details={"unknown": unknown, "allowed": sorted(ALL_PERMISSIONS)})
    return sorted(set(names))


def create_role(db: Session, actor: User, data: RoleCreate) -> Role:
    repo = RoleRepository(db)
    if repo.get_by_name(data.name):
        raise ConflictError("A role with this name already exists")
    names = _validate_permissions(data.permissions)
    role = Role(name=data.name, description=data.description, is_system=False)
    role.permissions = repo.permissions_by_names(names)
    repo.add(role)
    audit_service.record(db, user_id=actor.id, action="role.create", entity_type="role", entity_id=role.id,
                         new={"name": role.name, "permissions": names})
    db.commit()
    return role


def set_role_permissions(db: Session, actor: User, role_id: int, names: list[str]) -> Role:
    repo = RoleRepository(db)
    role = repo.require(role_id)
    if role.name == RoleName.SUPER_ADMIN.value:
        raise BadRequestError("The super_admin role always holds every permission and cannot be edited")
    names = _validate_permissions(names)
    previous = sorted(p.name for p in role.permissions)
    role.permissions = repo.permissions_by_names(names)
    audit_service.record(db, user_id=actor.id, action="role.permissions_update", entity_type="role",
                         entity_id=role.id, previous={"permissions": previous}, new={"permissions": names})
    db.commit()
    return role


def delete_role(db: Session, actor: User, role_id: int) -> None:
    repo = RoleRepository(db)
    role = repo.require(role_id)
    if role.is_system:
        raise BadRequestError("System roles cannot be deleted")
    if repo.user_count(role.id):
        raise ConflictError("Role is still assigned to users")
    audit_service.record(db, user_id=actor.id, action="role.delete", entity_type="role", entity_id=role.id,
                         previous={"name": role.name})
    db.delete(role)
    db.commit()
