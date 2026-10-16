"""Idempotent seed: permissions, roles (+ role->permission matrix), SLA policies and the first super admin.

Run manually:  python -m app.db.init_db
"""
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.constants import (
    ALL_PERMISSIONS,
    ROLE_DESCRIPTIONS,
    ROLE_PERMISSIONS,
    SLA_DEFAULT_POLICIES,
    RoleName,
)
from app.core.logging import get_logger, setup_logging
from app.core.security import hash_password
from app.db import base  # noqa: F401  (re-exported Base)
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.models import Permission, Role, SLAPolicy, User

logger = get_logger("app.db.init")


def seed_permissions_and_roles(db: Session) -> None:
    existing_perms = {p.name: p for p in db.scalars(select(Permission))}
    for name in ALL_PERMISSIONS:
        if name not in existing_perms:
            existing_perms[name] = Permission(name=name, description=name.replace(":", " ").replace("_", " "))
            db.add(existing_perms[name])
    db.flush()

    existing_roles = {r.name: r for r in db.scalars(select(Role))}
    for role_name, perms in ROLE_PERMISSIONS.items():
        role = existing_roles.get(role_name.value)
        if role is None:
            role = Role(name=role_name.value, description=ROLE_DESCRIPTIONS[role_name], is_system=True)
            role.permissions = [existing_perms[p] for p in perms]
            db.add(role)
        elif role.name == RoleName.SUPER_ADMIN:
            role.permissions = [existing_perms[p] for p in perms]  # keep super admin complete
        # other existing roles keep their (possibly customised) permission set
    db.flush()


def seed_sla_policies(db: Session) -> None:
    existing = {p.severity for p in db.scalars(select(SLAPolicy))}
    for severity, (ack, investigate, resolve) in SLA_DEFAULT_POLICIES.items():
        if severity not in existing:
            db.add(SLAPolicy(severity=severity, ack_minutes=ack, investigation_minutes=investigate,
                             resolution_minutes=resolve))
    db.flush()


def seed_first_admin(db: Session) -> None:
    email = settings.FIRST_SUPERADMIN_EMAIL.lower()
    if db.scalar(select(User).where(User.email == email)):
        return
    role = db.scalar(select(Role).where(Role.name == RoleName.SUPER_ADMIN.value))
    db.add(User(email=email, full_name=settings.FIRST_SUPERADMIN_NAME,
                hashed_password=hash_password(settings.FIRST_SUPERADMIN_PASSWORD), role_id=role.id, is_active=True))
    logger.info("created first super admin", extra={"email": email})


def seed_all(db: Session) -> None:
    seed_permissions_and_roles(db)
    seed_sla_policies(db)
    seed_first_admin(db)
    db.commit()


def init_db(create_tables: bool = False) -> None:
    if create_tables:
        Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_all(db)


if __name__ == "__main__":
    setup_logging(settings.LOG_LEVEL, settings.LOG_JSON)
    init_db(create_tables=settings.AUTO_CREATE_TABLES)
    print("Database seeded.")
