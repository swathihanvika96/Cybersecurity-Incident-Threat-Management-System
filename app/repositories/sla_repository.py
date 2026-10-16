from sqlalchemy import Select, select

from app.core.constants import INCIDENT_DONE_STATUSES, INCIDENT_OPEN_STATUSES
from app.core.permissions import incident_visibility_clause
from app.models import Incident, IncidentSLA, SLAHistory, SLAPolicy
from app.repositories.base import BaseRepository


class SLARepository(BaseRepository[IncidentSLA]):
    model = IncidentSLA
    label = "SLA"

    def for_incident(self, incident_id: int) -> IncidentSLA | None:
        return self.db.scalar(select(IncidentSLA).where(IncidentSLA.incident_id == incident_id))

    def policy(self, severity: str) -> SLAPolicy | None:
        return self.db.scalar(select(SLAPolicy).where(SLAPolicy.severity == severity))

    def policies(self) -> list[SLAPolicy]:
        return list(self.db.scalars(select(SLAPolicy).order_by(SLAPolicy.ack_minutes)))

    def open_incident_slas(self) -> list[tuple[Incident, IncidentSLA]]:
        rows = self.db.execute(
            select(Incident, IncidentSLA)
            .join(IncidentSLA, IncidentSLA.incident_id == Incident.id)
            .where(Incident.status.in_(INCIDENT_OPEN_STATUSES))
            .order_by(Incident.id)
        )
        return [(i, s) for i, s in rows]

    def listing(
        self, user, *, sla_status: list[str], include_resolved: bool = False, escalated_only: bool = False
    ) -> Select:
        stmt = (
            select(Incident, IncidentSLA)
            .join(IncidentSLA, IncidentSLA.incident_id == Incident.id)
            .where(incident_visibility_clause(user), IncidentSLA.sla_status.in_(sla_status))
            .order_by(IncidentSLA.resolution_deadline.asc(), Incident.id)
        )
        if not include_resolved:
            stmt = stmt.where(Incident.status.notin_(INCIDENT_DONE_STATUSES))
        if escalated_only:
            stmt = stmt.where(IncidentSLA.escalation_status != "none")
        return stmt

    def history_stmt(self, incident_id: int) -> Select:
        return select(SLAHistory).where(SLAHistory.incident_id == incident_id).order_by(
            SLAHistory.timestamp.asc(), SLAHistory.id.asc()
        )
