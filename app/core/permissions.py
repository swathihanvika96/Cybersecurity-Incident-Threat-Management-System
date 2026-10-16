"""Permission checks and access rules for sensitive incident records.

Roles map to permissions (see core.constants.ROLE_PERMISSIONS); permissions are stored in the database and can be
edited through the role-management API. Endpoint guards live in api.deps; object-level rules live here.
"""
from sqlalchemy import ColumnElement, or_, true

from app.core.constants import P
from app.core.exceptions import ForbiddenError


def has_permission(user, permission: str) -> bool:
    return user.has_permission(permission)


def ensure_permission(user, permission: str, message: str | None = None) -> None:
    if not user.has_permission(permission):
        raise ForbiddenError(message or f"Missing required permission: {permission}")


def ensure_any_permission(user, *permissions: str) -> None:
    if not any(user.has_permission(p) for p in permissions):
        raise ForbiddenError("Missing required permission: one of " + ", ".join(permissions))


# ----------------------------------------------------------------------------- incident access
def incident_visibility_clause(user) -> ColumnElement[bool]:
    """SQL clause limiting incidents to those `user` may see.

    Sensitive incidents are visible only to holders of `incident:sensitive`, the assigned analyst and the creator.
    """
    from app.models.incident import Incident

    if user.has_permission(P.INCIDENT_SENSITIVE):
        return true()
    return or_(
        Incident.is_sensitive.is_(False),
        Incident.assigned_to_id == user.id,
        Incident.created_by_id == user.id,
    )


def can_view_incident(user, incident) -> bool:
    if not user.has_permission(P.INCIDENT_READ):
        return False
    if not incident.is_sensitive:
        return True
    return (
        user.has_permission(P.INCIDENT_SENSITIVE)
        or incident.assigned_to_id == user.id
        or incident.created_by_id == user.id
    )


def ensure_can_view_incident(user, incident) -> None:
    if not can_view_incident(user, incident):
        raise ForbiddenError("This incident is restricted: sensitive incident records require special access")


def can_work_incident(user, incident) -> bool:
    """May modify the incident (notes, status, resolve...): writer who is the assignee/creator, or a manager."""
    if not user.has_permission(P.INCIDENT_WRITE) or not can_view_incident(user, incident):
        return False
    return user.has_permission(P.INCIDENT_ASSIGN) or user.id in (incident.assigned_to_id, incident.created_by_id)


def ensure_can_work_incident(user, incident) -> None:
    ensure_can_view_incident(user, incident)
    if not can_work_incident(user, incident):
        raise ForbiddenError("Only the assigned analyst, the creator or a security manager may perform this action")
