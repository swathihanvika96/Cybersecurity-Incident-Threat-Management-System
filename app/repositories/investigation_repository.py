from sqlalchemy import Select, and_, exists, not_, or_, select, true

from app.core.constants import P
from app.core.permissions import incident_visibility_clause
from app.models import (
    Incident,
    Investigation,
    InvestigationEvidence,
    InvestigationIncident,
    InvestigationNote,
)
from app.repositories.base import BaseRepository
from app.utils.filtering import text_search


class InvestigationRepository(BaseRepository[Investigation]):
    model = Investigation
    label = "Investigation"

    @staticmethod
    def access_clause(user):
        """Investigations linked to a sensitive incident are visible only to users who can see that incident,
        or to the investigation's owner/creator."""
        if user.has_permission(P.INCIDENT_SENSITIVE):
            return true()
        restricted = exists(
            select(InvestigationIncident.id)
            .join(Incident, Incident.id == InvestigationIncident.incident_id)
            .where(
                InvestigationIncident.investigation_id == Investigation.id,
                not_(incident_visibility_clause(user)),
            )
        )
        return or_(
            not_(restricted),
            Investigation.owner_id == user.id,
            Investigation.created_by_id == user.id,
        )

    def filtered(
        self,
        user,
        *,
        q: str | None = None,
        status: str | None = None,
        owner_id: int | None = None,
        incident_id: int | None = None,
    ) -> Select:
        stmt = select(Investigation).where(self.access_clause(user))
        stmt = text_search(stmt, q, Investigation.title, Investigation.reference, Investigation.description)
        if status:
            stmt = stmt.where(Investigation.status == status)
        if owner_id is not None:
            stmt = stmt.where(Investigation.owner_id == owner_id)
        if incident_id is not None:
            stmt = stmt.where(
                Investigation.id.in_(
                    select(InvestigationIncident.investigation_id).where(
                        InvestigationIncident.incident_id == incident_id
                    )
                )
            )
        return stmt.order_by(Investigation.created_at.desc(), Investigation.id.desc())

    def linked_incidents(self, investigation_id: int) -> list[Incident]:
        return list(
            self.db.scalars(
                select(Incident)
                .join(InvestigationIncident, InvestigationIncident.incident_id == Incident.id)
                .where(InvestigationIncident.investigation_id == investigation_id)
            )
        )

    def notes_stmt(self, investigation_id: int) -> Select:
        return (
            select(InvestigationNote)
            .where(InvestigationNote.investigation_id == investigation_id)
            .order_by(InvestigationNote.created_at.asc(), InvestigationNote.id.asc())
        )

    def evidence_stmt(self, investigation_id: int) -> Select:
        return (
            select(InvestigationEvidence)
            .where(InvestigationEvidence.investigation_id == investigation_id)
            .order_by(InvestigationEvidence.added_at.asc(), InvestigationEvidence.id.asc())
        )

    def get_evidence(self, investigation_id: int, evidence_id: int) -> InvestigationEvidence | None:
        return self.db.scalar(
            select(InvestigationEvidence).where(
                and_(InvestigationEvidence.investigation_id == investigation_id, InvestigationEvidence.id == evidence_id)
            )
        )
