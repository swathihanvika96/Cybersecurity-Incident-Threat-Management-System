from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError
from app.models import Organization, User
from app.repositories.organization_repository import OrganizationRepository
from app.schemas.organization import OrganizationCreate, OrganizationUpdate
from app.services import audit_service

FIELDS = ("name", "description", "industry", "contact_email", "contact_phone", "is_active")


def create(db: Session, actor: User, data: OrganizationCreate) -> Organization:
    repo = OrganizationRepository(db)
    if repo.get_by_name(data.name):
        raise ConflictError("An organization with this name already exists")
    org = repo.add(Organization(**data.model_dump()))
    audit_service.record(db, user_id=actor.id, action="organization.create", entity_type="organization",
                         entity_id=org.id, new=audit_service.snapshot(org, FIELDS))
    db.commit()
    return org


def update(db: Session, actor: User, org_id: int, data: OrganizationUpdate) -> Organization:
    repo = OrganizationRepository(db)
    org = repo.require(org_id)
    values = data.model_dump(exclude_unset=True)
    if "name" in values and values["name"] != org.name and repo.get_by_name(values["name"]):
        raise ConflictError("An organization with this name already exists")
    before = audit_service.snapshot(org, FIELDS)
    for key, value in values.items():
        setattr(org, key, value)
    prev, new = audit_service.changes(before, audit_service.snapshot(org, FIELDS))
    if new:
        audit_service.record(db, user_id=actor.id, action="organization.update", entity_type="organization",
                             entity_id=org.id, previous=prev, new=new)
    db.commit()
    return org
