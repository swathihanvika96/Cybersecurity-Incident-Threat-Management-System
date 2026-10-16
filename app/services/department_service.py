from sqlalchemy.orm import Session

from app.core.exceptions import BadRequestError, ConflictError
from app.models import Department, User
from app.repositories.department_repository import DepartmentRepository
from app.repositories.organization_repository import OrganizationRepository
from app.schemas.department import DepartmentCreate, DepartmentUpdate
from app.services import audit_service

FIELDS = ("organization_id", "name", "description", "is_active")


def create(db: Session, actor: User, data: DepartmentCreate) -> Department:
    org = OrganizationRepository(db).require(data.organization_id)
    if not org.is_active:
        raise BadRequestError("Cannot add departments to an inactive organization")
    repo = DepartmentRepository(db)
    if repo.get_by_name(data.organization_id, data.name):
        raise ConflictError("This organization already has a department with that name")
    dept = repo.add(Department(**data.model_dump()))
    audit_service.record(db, user_id=actor.id, action="department.create", entity_type="department",
                         entity_id=dept.id, new=audit_service.snapshot(dept, FIELDS))
    db.commit()
    return dept


def update(db: Session, actor: User, dept_id: int, data: DepartmentUpdate) -> Department:
    repo = DepartmentRepository(db)
    dept = repo.require(dept_id)
    values = data.model_dump(exclude_unset=True)
    if "name" in values and values["name"] != dept.name and repo.get_by_name(dept.organization_id, values["name"]):
        raise ConflictError("This organization already has a department with that name")
    before = audit_service.snapshot(dept, FIELDS)
    for key, value in values.items():
        setattr(dept, key, value)
    prev, new = audit_service.changes(before, audit_service.snapshot(dept, FIELDS))
    if new:
        audit_service.record(db, user_id=actor.id, action="department.update", entity_type="department",
                             entity_id=dept.id, previous=prev, new=new)
    db.commit()
    return dept
