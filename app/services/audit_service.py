"""Append-only audit trail. Records are added to the caller's session so they commit atomically with the change
they describe (callers commit)."""
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any, Iterable

from sqlalchemy.orm import Session

from app.core.logging import client_ip_var
from app.models import AuditLog


def to_jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_jsonable(v) for v in value]
    return value


def snapshot(obj: Any, fields: Iterable[str]) -> dict[str, Any]:
    return {f: to_jsonable(getattr(obj, f, None)) for f in fields}


def changes(before: dict[str, Any], after: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return only the fields whose value differs, as (previous, new)."""
    prev, new = {}, {}
    for key in after:
        if before.get(key) != after.get(key):
            prev[key] = before.get(key)
            new[key] = after.get(key)
    return prev, new


def record(
    db: Session,
    *,
    user_id: int | None,
    action: str,
    entity_type: str,
    entity_id: int | None,
    previous: Any = None,
    new: Any = None,
) -> AuditLog:
    entry = AuditLog(
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        previous_value=to_jsonable(previous) if previous is not None else None,
        new_value=to_jsonable(new) if new is not None else None,
        ip_address=client_ip_var.get(),
    )
    db.add(entry)
    return entry
