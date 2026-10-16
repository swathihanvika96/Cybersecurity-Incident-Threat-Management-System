"""Asset registration, ownership, status and change history."""
from sqlalchemy.orm import Session

from app.core.exceptions import BadRequestError, ConflictError, NotFoundError
from app.models import Asset, AssetHistory, Department, User
from app.repositories.asset_repository import AssetRepository
from app.repositories.organization_repository import OrganizationRepository
from app.repositories.user_repository import UserRepository
from app.schemas.asset import AssetCreate, AssetUpdate
from app.services import audit_service

AUDIT_FIELDS = (
    "name", "asset_type", "criticality", "status", "hostname", "ip_address", "location", "description",
    "organization_id", "department_id", "owner_id",
)


def _history(db: Session, asset: Asset, actor: User, action: str, field: str | None = None, old=None, new=None):
    db.add(
        AssetHistory(
            asset_id=asset.id,
            changed_by_id=actor.id,
            action=action,
            field_name=field,
            old_value=None if old is None else str(old),
            new_value=None if new is None else str(new),
        )
    )


def _validate_owner(db: Session, owner_id: int | None) -> None:
    if owner_id is None:
        return
    owner = UserRepository(db).get(owner_id)
    if owner is None:
        raise NotFoundError(f"User {owner_id} not found")
    if not owner.is_active:
        raise BadRequestError("Asset owner must be an active user")


def _validate_department(db: Session, organization_id: int, department_id: int | None) -> None:
    if department_id is None:
        return
    dept = db.get(Department, department_id)
    if dept is None:
        raise NotFoundError(f"Department {department_id} not found")
    if dept.organization_id != organization_id:
        raise BadRequestError("Department does not belong to the asset's organization")


def create(db: Session, actor: User, data: AssetCreate) -> Asset:
    org = OrganizationRepository(db).require(data.organization_id)
    if not org.is_active:
        raise BadRequestError("Cannot register assets for an inactive organization")
    _validate_department(db, data.organization_id, data.department_id)
    _validate_owner(db, data.owner_id)
    repo = AssetRepository(db)
    if repo.get_by_name(data.organization_id, data.name):
        raise ConflictError("The organization already has an asset with that name")
    asset = repo.add(Asset(**data.model_dump()))
    _history(db, asset, actor, "created")
    audit_service.record(db, user_id=actor.id, action="asset.create", entity_type="asset", entity_id=asset.id,
                         new=audit_service.snapshot(asset, AUDIT_FIELDS))
    db.commit()
    db.refresh(asset)
    return asset


def _apply_changes(db: Session, actor: User, asset: Asset, values: dict, action: str) -> None:
    before = audit_service.snapshot(asset, AUDIT_FIELDS)
    for key, value in values.items():
        setattr(asset, key, value)
    after = audit_service.snapshot(asset, AUDIT_FIELDS)
    prev, new = audit_service.changes(before, after)
    for field in new:
        _history(db, asset, actor, action, field, prev[field], new[field])
    if new:
        audit_service.record(db, user_id=actor.id, action=f"asset.{action}", entity_type="asset",
                             entity_id=asset.id, previous=prev, new=new)
    if "criticality" in new:
        # asset criticality feeds the risk formula: keep risk assessments consistent
        from app.services import risk_service

        risk_service.recalculate(db, actor, asset_id=asset.id)


def update(db: Session, actor: User, asset_id: int, data: AssetUpdate) -> Asset:
    repo = AssetRepository(db)
    asset = repo.require(asset_id)
    values = data.model_dump(exclude_unset=True)
    if "name" in values and values["name"] != asset.name and repo.get_by_name(asset.organization_id, values["name"]):
        raise ConflictError("The organization already has an asset with that name")
    if "department_id" in values:
        _validate_department(db, asset.organization_id, values["department_id"])
    _apply_changes(db, actor, asset, values, "update")
    db.commit()
    db.refresh(asset)
    return asset


def set_status(db: Session, actor: User, asset_id: int, status: str, reason: str | None) -> Asset:
    asset = AssetRepository(db).require(asset_id)
    if asset.status == status:
        raise ConflictError(f"Asset is already '{status}'")
    if asset.status == "decommissioned":
        raise BadRequestError("A decommissioned asset cannot be re-activated; register a new asset instead")
    _apply_changes(db, actor, asset, {"status": status}, "status_change")
    if reason:
        _history(db, asset, actor, "status_reason", "status", None, reason)
    db.commit()
    db.refresh(asset)
    return asset


def assign_owner(db: Session, actor: User, asset_id: int, owner_id: int | None) -> Asset:
    asset = AssetRepository(db).require(asset_id)
    _validate_owner(db, owner_id)
    _apply_changes(db, actor, asset, {"owner_id": owner_id}, "owner_change")
    db.commit()
    db.refresh(asset)
    return asset
