"""Investigations: links to incidents/alerts/assets, notes and timeline, evidence references with access control.

Access rules
* read      : investigation:read, and - when a linked incident is sensitive - the right to see that incident
              (owner and creator always have access to their own investigation)
* write     : investigation:write AND (owner, creator or a security manager)
* evidence  : evidence:read is required to see evidence; every evidence view is written to the audit log
"""
from sqlalchemy.orm import Session

from app.core.constants import P
from app.core.exceptions import BadRequestError, ConflictError, ForbiddenError, NotFoundError
from app.core.permissions import can_view_incident, ensure_permission
from app.models import (
    Asset,
    Investigation,
    InvestigationAlert,
    InvestigationAsset,
    InvestigationEvidence,
    InvestigationIncident,
    InvestigationNote,
    SecurityAlert,
    User,
)
from app.repositories.incident_repository import IncidentRepository
from app.repositories.investigation_repository import InvestigationRepository
from app.repositories.user_repository import UserRepository
from app.schemas.investigation import InvestigationCreate, InvestigationLink, InvestigationUpdate
from app.schemas.investigation_evidence import EvidenceCreate
from app.services import audit_service
from app.utils.date_utils import make_reference, utcnow

OPEN_STATUSES = ("open", "in_progress")


# --------------------------------------------------------------------------- access
def _ensure_can_read(db: Session, user: User, inv: Investigation) -> None:
    ensure_permission(user, P.INVESTIGATION_READ)
    if user.id in (inv.owner_id, inv.created_by_id) or user.has_permission(P.INCIDENT_SENSITIVE):
        return
    for incident in InvestigationRepository(db).linked_incidents(inv.id):
        if incident.is_sensitive and not can_view_incident(user, incident):
            raise ForbiddenError("This investigation is linked to a sensitive incident you are not allowed to access")


def get_accessible(db: Session, user: User, investigation_id: int) -> Investigation:
    inv = InvestigationRepository(db).require(investigation_id)
    _ensure_can_read(db, user, inv)
    return inv


def _ensure_can_write(db: Session, user: User, inv: Investigation) -> None:
    _ensure_can_read(db, user, inv)
    ensure_permission(user, P.INVESTIGATION_WRITE)
    if not (user.id in (inv.owner_id, inv.created_by_id) or user.has_permission(P.INCIDENT_ASSIGN)):
        raise ForbiddenError("Only the investigation owner, its creator or a security manager can modify it")


def _ensure_active(inv: Investigation) -> None:
    if inv.status not in OPEN_STATUSES:
        raise ConflictError(f"Investigation is {inv.status} and read-only")


def _event(db: Session, inv: Investigation, user_id: int | None, text: str) -> None:
    db.add(InvestigationNote(investigation_id=inv.id, author_id=user_id, note_type="event", content=text))


def _autostart(db: Session, inv: Investigation, actor: User) -> None:
    if inv.status == "open":
        inv.status = "in_progress"
        _event(db, inv, actor.id, "Investigation started")


# --------------------------------------------------------------------------- linking helpers
def _resolve_links(db: Session, actor: User, incident_ids: list[int], alert_ids: list[int], asset_ids: list[int]):
    incident_ids, alert_ids, asset_ids = (list(dict.fromkeys(x)) for x in (incident_ids, alert_ids, asset_ids))
    incidents = IncidentRepository(db).by_ids_list(incident_ids) if incident_ids else []
    missing = sorted(set(incident_ids) - {i.id for i in incidents})
    if missing:
        raise NotFoundError(f"Incident(s) not found: {missing}")
    hidden = [i.id for i in incidents if not can_view_incident(actor, i)]
    if hidden:
        raise ForbiddenError(f"You are not allowed to access incident(s): {hidden}")
    from sqlalchemy import select

    alerts = list(db.scalars(select(SecurityAlert.id).where(SecurityAlert.id.in_(alert_ids)))) if alert_ids else []
    missing = sorted(set(alert_ids) - set(alerts))
    if missing:
        raise NotFoundError(f"Alert(s) not found: {missing}")
    assets = list(db.scalars(select(Asset.id).where(Asset.id.in_(asset_ids)))) if asset_ids else []
    missing = sorted(set(asset_ids) - set(assets))
    if missing:
        raise NotFoundError(f"Asset(s) not found: {missing}")
    return incident_ids, alert_ids, asset_ids


def _add_links(inv: Investigation, incident_ids, alert_ids, asset_ids) -> dict[str, list[int]]:
    added: dict[str, list[int]] = {"incident_ids": [], "alert_ids": [], "asset_ids": []}
    existing = (set(inv.incident_ids), set(inv.alert_ids), set(inv.asset_ids))
    for i in incident_ids:
        if i not in existing[0]:
            inv.incident_links.append(InvestigationIncident(incident_id=i))
            added["incident_ids"].append(i)
    for a in alert_ids:
        if a not in existing[1]:
            inv.alert_links.append(InvestigationAlert(alert_id=a))
            added["alert_ids"].append(a)
    for s in asset_ids:
        if s not in existing[2]:
            inv.asset_links.append(InvestigationAsset(asset_id=s))
            added["asset_ids"].append(s)
    return added


# --------------------------------------------------------------------------- commands
def create(db: Session, actor: User, data: InvestigationCreate) -> Investigation:
    owner_id = data.owner_id or actor.id
    owner = UserRepository(db).get(owner_id)
    if owner is None:
        raise NotFoundError(f"User {owner_id} not found")
    if not owner.is_active or not owner.has_permission(P.INVESTIGATION_WRITE):
        raise BadRequestError("The owner must be an active user who can conduct investigations")
    incident_ids, alert_ids, asset_ids = _resolve_links(db, actor, data.incident_ids, data.alert_ids, data.asset_ids)
    inv = Investigation(title=data.title, description=data.description, owner_id=owner_id, created_by_id=actor.id,
                        status="open")
    InvestigationRepository(db).add(inv)
    inv.reference = make_reference("INV", inv.id)
    _add_links(inv, incident_ids, alert_ids, asset_ids)
    _event(db, inv, actor.id, f"Investigation opened; owner user {owner_id}")
    audit_service.record(db, user_id=actor.id, action="investigation.create", entity_type="investigation",
                         entity_id=inv.id, new={"title": inv.title, "owner_id": owner_id, "incident_ids": incident_ids,
                                                "alert_ids": alert_ids, "asset_ids": asset_ids})
    db.commit()
    db.refresh(inv)
    return inv


def update(db: Session, actor: User, inv: Investigation, data: InvestigationUpdate) -> Investigation:
    _ensure_can_write(db, actor, inv)
    _ensure_active(inv)
    values = data.model_dump(exclude_unset=True)
    if "title" in values and values["title"] is None:
        raise BadRequestError("title cannot be cleared")
    previous = {k: getattr(inv, k) for k in values}
    for key, value in values.items():
        setattr(inv, key, value)
    audit_service.record(db, user_id=actor.id, action="investigation.update", entity_type="investigation",
                         entity_id=inv.id, previous=previous, new=values)
    db.commit()
    db.refresh(inv)
    return inv


def link(db: Session, actor: User, inv: Investigation, data: InvestigationLink) -> Investigation:
    _ensure_can_write(db, actor, inv)
    _ensure_active(inv)
    incident_ids, alert_ids, asset_ids = _resolve_links(db, actor, data.incident_ids, data.alert_ids, data.asset_ids)
    added = _add_links(inv, incident_ids, alert_ids, asset_ids)
    if not any(added.values()):
        raise ConflictError("Everything given is already linked to this investigation")
    _autostart(db, inv, actor)
    _event(db, inv, actor.id, "Linked records: " + "; ".join(f"{k}={v}" for k, v in added.items() if v))
    audit_service.record(db, user_id=actor.id, action="investigation.link", entity_type="investigation",
                         entity_id=inv.id, new=added)
    db.commit()
    db.refresh(inv)
    return inv


def change_owner(db: Session, actor: User, inv: Investigation, owner_id: int) -> Investigation:
    _ensure_can_write(db, actor, inv)
    _ensure_active(inv)
    owner = UserRepository(db).get(owner_id)
    if owner is None:
        raise NotFoundError(f"User {owner_id} not found")
    if not owner.is_active or not owner.has_permission(P.INVESTIGATION_WRITE):
        raise BadRequestError("The new owner must be an active user who can conduct investigations")
    if owner_id == inv.owner_id:
        raise ConflictError("That user already owns this investigation")
    if not (actor.id == inv.owner_id or actor.has_permission(P.INCIDENT_ASSIGN)):
        raise ForbiddenError("Only the current owner or a security manager can transfer ownership")
    previous = inv.owner_id
    inv.owner_id = owner_id
    _event(db, inv, actor.id, f"Ownership transferred from user {previous} to user {owner_id}")
    audit_service.record(db, user_id=actor.id, action="investigation.owner_change", entity_type="investigation",
                         entity_id=inv.id, previous={"owner_id": previous}, new={"owner_id": owner_id})
    db.commit()
    db.refresh(inv)
    return inv


def start(db: Session, actor: User, inv: Investigation) -> Investigation:
    _ensure_can_write(db, actor, inv)
    if inv.status != "open":
        raise ConflictError(f"Investigation is already {inv.status}")
    _autostart(db, inv, actor)
    audit_service.record(db, user_id=actor.id, action="investigation.start", entity_type="investigation",
                         entity_id=inv.id, previous={"status": "open"}, new={"status": "in_progress"})
    db.commit()
    return inv


def complete(db: Session, actor: User, inv: Investigation, summary: str) -> Investigation:
    _ensure_can_write(db, actor, inv)
    _ensure_active(inv)
    from sqlalchemy import func, select

    has_content = db.scalar(
        select(func.count(InvestigationNote.id)).where(
            InvestigationNote.investigation_id == inv.id, InvestigationNote.note_type == "note"
        )
    ) or db.scalar(
        select(func.count(InvestigationEvidence.id)).where(InvestigationEvidence.investigation_id == inv.id)
    )
    if not has_content:
        raise BadRequestError("Record at least one investigation note or piece of evidence before completing")
    old = inv.status
    inv.status, inv.summary, inv.completed_at = "completed", summary, utcnow()
    _event(db, inv, actor.id, "Investigation completed")
    audit_service.record(db, user_id=actor.id, action="investigation.complete", entity_type="investigation",
                         entity_id=inv.id, previous={"status": old}, new={"status": "completed", "summary": summary})
    db.commit()
    db.refresh(inv)
    return inv


def close(db: Session, actor: User, inv: Investigation) -> Investigation:
    _ensure_can_read(db, actor, inv)
    ensure_permission(actor, P.INCIDENT_APPROVE_CLOSURE, "Closing an investigation requires a security manager")
    if inv.status != "completed":
        raise ConflictError("Only completed investigations can be closed")
    inv.status = "closed"
    _event(db, inv, actor.id, "Investigation closed")
    audit_service.record(db, user_id=actor.id, action="investigation.close", entity_type="investigation",
                         entity_id=inv.id, previous={"status": "completed"}, new={"status": "closed"})
    db.commit()
    return inv


def add_note(db: Session, actor: User, inv: Investigation, content: str) -> InvestigationNote:
    _ensure_can_write(db, actor, inv)
    _ensure_active(inv)
    _autostart(db, inv, actor)
    note = InvestigationNote(investigation_id=inv.id, author_id=actor.id, note_type="note", content=content)
    db.add(note)
    db.commit()
    db.refresh(note)
    return note


# --------------------------------------------------------------------------- evidence
def add_evidence(db: Session, actor: User, inv: Investigation, data: EvidenceCreate) -> InvestigationEvidence:
    _ensure_can_write(db, actor, inv)
    _ensure_active(inv)
    _autostart(db, inv, actor)
    evidence = InvestigationEvidence(
        investigation_id=inv.id, title=data.title, evidence_type=data.evidence_type, description=data.description,
        reference=data.reference, sha256=data.sha256.lower() if data.sha256 else None, added_by_id=actor.id,
    )
    db.add(evidence)
    db.flush()
    _event(db, inv, actor.id, f"Evidence added: {data.title} ({data.evidence_type})")
    audit_service.record(db, user_id=actor.id, action="evidence.add", entity_type="investigation_evidence",
                         entity_id=evidence.id, new={"investigation_id": inv.id, "title": data.title,
                                                     "evidence_type": data.evidence_type})
    db.commit()
    db.refresh(evidence)
    return evidence


def _ensure_evidence_access(db: Session, actor: User, inv: Investigation) -> None:
    _ensure_can_read(db, actor, inv)
    ensure_permission(actor, P.EVIDENCE_READ, "Evidence access is restricted to authorised investigators")


def list_evidence(db: Session, actor: User, inv: Investigation) -> list[InvestigationEvidence]:
    _ensure_evidence_access(db, actor, inv)
    items = list(db.scalars(InvestigationRepository(db).evidence_stmt(inv.id)))
    for item in items:
        audit_service.record(db, user_id=actor.id, action="evidence.access", entity_type="investigation_evidence",
                             entity_id=item.id, new={"investigation_id": inv.id, "via": "list"})
    db.commit()
    return items


def get_evidence(db: Session, actor: User, inv: Investigation, evidence_id: int) -> InvestigationEvidence:
    _ensure_evidence_access(db, actor, inv)
    item = InvestigationRepository(db).get_evidence(inv.id, evidence_id)
    if item is None:
        raise NotFoundError(f"Evidence {evidence_id} not found in investigation {inv.id}")
    audit_service.record(db, user_id=actor.id, action="evidence.access", entity_type="investigation_evidence",
                         entity_id=item.id, new={"investigation_id": inv.id, "via": "detail"})
    db.commit()
    return item
