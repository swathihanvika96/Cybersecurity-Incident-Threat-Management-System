from datetime import date, datetime

from sqlalchemy import Select, select

from app.core.constants import INCIDENT_OPEN_STATUSES, SEVERITY_RANK
from app.core.permissions import incident_visibility_clause
from app.models import (
    Asset,
    Incident,
    IncidentAlert,
    IncidentAssignment,
    IncidentHistory,
    IncidentRelation,
    InvestigationNote,
    SecurityAlert,
)
from app.repositories.base import BaseRepository
from app.utils.filtering import date_range, text_search
from app.utils.sorting import rank_case

SORT_MAP = {
    "created_at": Incident.created_at,
    "updated_at": Incident.updated_at,
    "severity": rank_case(Incident.severity, SEVERITY_RANK),
    "status": Incident.status,
    "title": Incident.title,
    "reference": Incident.reference,
}


class IncidentRepository(BaseRepository[Incident]):
    model = Incident
    label = "Incident"

    def filtered(
        self,
        user,
        *,
        q: str | None = None,
        reference: str | None = None,
        status: list[str] | None = None,
        severity: list[str] | None = None,
        category: str | None = None,
        asset_id: int | None = None,
        department_id: int | None = None,
        assigned_to_id: int | None = None,
        created_by_id: int | None = None,
        is_sensitive: bool | None = None,
        date_from: date | None = None,
        date_to: date | None = None,
    ) -> Select:
        stmt = select(Incident).where(incident_visibility_clause(user))
        stmt = text_search(stmt, q, Incident.title, Incident.description, Incident.reference)
        if reference:
            stmt = stmt.where(Incident.reference == reference.strip().upper())
        if status:
            stmt = stmt.where(Incident.status.in_(status))
        if severity:
            stmt = stmt.where(Incident.severity.in_(severity))
        if category:
            stmt = stmt.where(Incident.category == category)
        if asset_id is not None:
            stmt = stmt.where(Incident.asset_id == asset_id)
        if department_id is not None:
            stmt = stmt.where(Incident.asset_id.in_(select(Asset.id).where(Asset.department_id == department_id)))
        if assigned_to_id is not None:
            stmt = stmt.where(Incident.assigned_to_id == assigned_to_id)
        if created_by_id is not None:
            stmt = stmt.where(Incident.created_by_id == created_by_id)
        if is_sensitive is not None:
            stmt = stmt.where(Incident.is_sensitive.is_(is_sensitive))
        return date_range(stmt, Incident.created_at, date_from, date_to)

    def by_ids_list(self, ids: list[int]) -> list[Incident]:
        if not ids:
            return []
        return list(self.db.scalars(select(Incident).where(Incident.id.in_(ids))))

    def find_open_duplicates(self, asset_id: int, category: str, since: datetime) -> list[Incident]:
        """Business rule for duplicate incidents: an OPEN incident for the same asset and category created
        within the duplicate window."""
        return list(
            self.db.scalars(
                select(Incident)
                .where(
                    Incident.asset_id == asset_id,
                    Incident.category == category,
                    Incident.status.in_(INCIDENT_OPEN_STATUSES),
                    Incident.created_at >= since,
                )
                .order_by(Incident.created_at.desc())
            )
        )

    def alerts_already_linked(self, alert_ids: list[int]) -> dict[int, int]:
        """alert_id -> incident_id for alerts that already belong to an incident."""
        if not alert_ids:
            return {}
        rows = self.db.execute(
            select(IncidentAlert.alert_id, IncidentAlert.incident_id).where(IncidentAlert.alert_id.in_(alert_ids))
        )
        return {a: i for a, i in rows}

    def incident_of_alert(self, alert_id: int) -> Incident | None:
        return self.db.scalar(
            select(Incident).join(IncidentAlert, IncidentAlert.incident_id == Incident.id).where(
                IncidentAlert.alert_id == alert_id
            )
        )

    def linked_alerts(self, incident_id: int) -> list[SecurityAlert]:
        return list(
            self.db.scalars(
                select(SecurityAlert)
                .join(IncidentAlert, IncidentAlert.alert_id == SecurityAlert.id)
                .where(IncidentAlert.incident_id == incident_id)
                .order_by(SecurityAlert.detected_at)
            )
        )

    def history_stmt(self, incident_id: int) -> Select:
        return (
            select(IncidentHistory)
            .where(IncidentHistory.incident_id == incident_id)
            .order_by(IncidentHistory.timestamp.asc(), IncidentHistory.id.asc())
        )

    def notes_stmt(self, incident_id: int) -> Select:
        return (
            select(InvestigationNote)
            .where(InvestigationNote.incident_id == incident_id)
            .order_by(InvestigationNote.created_at.asc(), InvestigationNote.id.asc())
        )

    def assignments_stmt(self, incident_id: int) -> Select:
        return (
            select(IncidentAssignment)
            .where(IncidentAssignment.incident_id == incident_id)
            .order_by(IncidentAssignment.assigned_at.asc(), IncidentAssignment.id.asc())
        )

    def relations(self, incident_id: int) -> list[IncidentRelation]:
        return list(
            self.db.scalars(
                select(IncidentRelation).where(
                    (IncidentRelation.incident_id == incident_id)
                    | (IncidentRelation.related_incident_id == incident_id)
                )
            )
        )

    def get_relation(self, a: int, b: int) -> IncidentRelation | None:
        return self.db.scalar(
            select(IncidentRelation).where(
                ((IncidentRelation.incident_id == a) & (IncidentRelation.related_incident_id == b))
                | ((IncidentRelation.incident_id == b) & (IncidentRelation.related_incident_id == a))
            )
        )
