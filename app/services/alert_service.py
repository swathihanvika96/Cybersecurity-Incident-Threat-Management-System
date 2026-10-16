"""Security alerts: creation with duplicate detection, updates, status tracking and assignment."""
import hashlib
from datetime import timedelta

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.constants import ALERT_TRANSITIONS, SEVERITY_RANK, P
from app.core.exceptions import BadRequestError, ConflictError, ForbiddenError, NotFoundError
from app.models import SecurityAlert, User
from app.repositories.alert_repository import AlertRepository
from app.repositories.asset_repository import AssetRepository
from app.repositories.incident_repository import IncidentRepository
from app.repositories.user_repository import UserRepository
from app.schemas.security_alert import AlertCreate, AlertUpdate
from app.services import audit_service
from app.utils.date_utils import make_reference, utcnow

AUDIT_FIELDS = ("title", "source", "category", "severity", "status", "asset_id", "assigned_to_id", "detected_at",
                "is_duplicate", "duplicate_of_id")
MAX_FUTURE_SKEW = timedelta(minutes=5)


def compute_fingerprint(asset_id: int, category: str, source: str, title: str) -> str:
    """Identity of 'the same alert': asset + category + source + normalised title."""
    normalised = " ".join(title.lower().split())
    raw = f"{asset_id}|{category}|{source.strip().lower()}|{normalised}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _validate_assignee(db: Session, assignee_id: int | None) -> User | None:
    if assignee_id is None:
        return None
    user = UserRepository(db).get(assignee_id)
    if user is None:
        raise NotFoundError(f"User {assignee_id} not found")
    if not user.is_active:
        raise BadRequestError("Alerts can only be assigned to active users")
    if not user.has_permission(P.ALERT_WRITE):
        raise BadRequestError("The assignee does not have permission to work on alerts")
    return user


def _ensure_may_assign(actor: User, assignee: User | None) -> None:
    """Analysts may only take alerts themselves; managers (incident:assign) may assign anyone."""
    if assignee is not None and assignee.id != actor.id and not actor.has_permission(P.INCIDENT_ASSIGN):
        raise ForbiddenError("You can only assign alerts to yourself")


def create(db: Session, actor: User, data: AlertCreate) -> SecurityAlert:
    asset = AssetRepository(db).require(data.asset_id)
    assignee = _validate_assignee(db, data.assigned_to_id)
    _ensure_may_assign(actor, assignee)
    now = utcnow()
    detected_at = data.detected_at or now
    if detected_at > now + MAX_FUTURE_SKEW:
        raise BadRequestError("detected_at cannot be in the future")
    repo = AlertRepository(db)
    fingerprint = compute_fingerprint(asset.id, data.category, data.source, data.title)
    original = repo.find_original(fingerprint, detected_at, settings.DUPLICATE_ALERT_WINDOW_MINUTES)
    alert = SecurityAlert(
        title=data.title,
        description=data.description,
        source=data.source,
        category=data.category,
        severity=data.severity,
        status="new",
        asset_id=asset.id,
        assigned_to_id=data.assigned_to_id,
        created_by_id=actor.id,
        detected_at=detected_at,
        fingerprint=fingerprint,
    )
    if original is not None:
        alert.is_duplicate = True
        alert.duplicate_of_id = original.id
        original.occurrence_count += 1
        if SEVERITY_RANK[data.severity] > SEVERITY_RANK[original.severity]:
            audit_service.record(
                db, user_id=actor.id, action="alert.severity_change", entity_type="alert", entity_id=original.id,
                previous={"severity": original.severity}, new={"severity": data.severity, "reason": "duplicate"},
            )
            original.severity = data.severity
    repo.add(alert)
    alert.reference = make_reference("ALR", alert.id, now)
    audit_service.record(db, user_id=actor.id, action="alert.create", entity_type="alert", entity_id=alert.id,
                         new=audit_service.snapshot(alert, AUDIT_FIELDS))
    db.commit()
    db.refresh(alert)
    return alert


def get(db: Session, alert_id: int) -> SecurityAlert:
    return AlertRepository(db).require(alert_id)


def _ensure_editable(db: Session, alert: SecurityAlert) -> None:
    incident = IncidentRepository(db).incident_of_alert(alert.id)
    if incident is not None and incident.status == "closed":
        raise ConflictError(f"Alert belongs to closed incident {incident.reference} and can no longer be modified")


def update(db: Session, actor: User, alert_id: int, data: AlertUpdate) -> SecurityAlert:
    alert = get(db, alert_id)
    _ensure_editable(db, alert)
    values = data.model_dump(exclude_unset=True)
    for key in ("title", "source", "category", "severity"):
        if key in values and values[key] is None:
            raise BadRequestError(f"{key} cannot be cleared")
    before = audit_service.snapshot(alert, AUDIT_FIELDS)
    for key, value in values.items():
        setattr(alert, key, value)
    if {"title", "source", "category"} & values.keys():
        alert.fingerprint = compute_fingerprint(alert.asset_id, alert.category, alert.source, alert.title)
    prev, new = audit_service.changes(before, audit_service.snapshot(alert, AUDIT_FIELDS))
    if "severity" in new:
        audit_service.record(db, user_id=actor.id, action="alert.severity_change", entity_type="alert",
                             entity_id=alert.id, previous={"severity": prev["severity"]},
                             new={"severity": new["severity"]})
        prev.pop("severity"), new.pop("severity")
    if new:
        audit_service.record(db, user_id=actor.id, action="alert.update", entity_type="alert", entity_id=alert.id,
                             previous=prev, new=new)
    db.commit()
    db.refresh(alert)
    return alert


def set_status(db: Session, actor: User, alert_id: int, status: str, comment: str | None) -> SecurityAlert:
    alert = get(db, alert_id)
    _ensure_editable(db, alert)
    if status == alert.status:
        raise ConflictError(f"Alert is already '{status}'")
    if status not in ALERT_TRANSITIONS.get(alert.status, set()):
        raise BadRequestError(
            f"Invalid transition {alert.status} -> {status}",
            details={"allowed": sorted(ALERT_TRANSITIONS.get(alert.status, set()))},
        )
    old = alert.status
    alert.status = status
    audit_service.record(db, user_id=actor.id, action="alert.status_change", entity_type="alert",
                         entity_id=alert.id, previous={"status": old}, new={"status": status, "comment": comment})
    db.commit()
    db.refresh(alert)
    return alert


def assign(db: Session, actor: User, alert_id: int, assignee_id: int | None) -> SecurityAlert:
    alert = get(db, alert_id)
    _ensure_editable(db, alert)
    assignee = _validate_assignee(db, assignee_id)
    _ensure_may_assign(actor, assignee)
    if assignee_id is None and alert.assigned_to_id not in (None, actor.id) and not actor.has_permission(P.INCIDENT_ASSIGN):
        raise ForbiddenError("Only a security manager can un-assign another analyst's alert")
    if alert.assigned_to_id == assignee_id:
        raise ConflictError("Alert is already assigned to that user" if assignee_id else "Alert is not assigned")
    previous = alert.assigned_to_id
    alert.assigned_to_id = assignee_id
    audit_service.record(db, user_id=actor.id, action="alert.assign", entity_type="alert", entity_id=alert.id,
                         previous={"assigned_to_id": previous}, new={"assigned_to_id": assignee_id})
    db.commit()
    db.refresh(alert)
    return alert
