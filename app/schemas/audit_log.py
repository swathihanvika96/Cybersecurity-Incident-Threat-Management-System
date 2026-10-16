from typing import Any

from app.schemas.common import DT, ORMModel


class AuditLogOut(ORMModel):
    id: int
    user_id: int | None = None
    action: str
    entity_type: str
    entity_id: int | None = None
    previous_value: Any | None = None
    new_value: Any | None = None
    ip_address: str | None = None
    timestamp: DT
