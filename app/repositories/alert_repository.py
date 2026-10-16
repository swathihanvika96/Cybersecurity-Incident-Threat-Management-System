from datetime import date, datetime, timedelta

from sqlalchemy import Select, select

from app.core.constants import SEVERITY_RANK
from app.models import Asset, SecurityAlert
from app.repositories.base import BaseRepository
from app.utils.filtering import date_range, text_search
from app.utils.sorting import rank_case

SORT_MAP = {
    "detected_at": SecurityAlert.detected_at,
    "created_at": SecurityAlert.created_at,
    "updated_at": SecurityAlert.updated_at,
    "severity": rank_case(SecurityAlert.severity, SEVERITY_RANK),
    "status": SecurityAlert.status,
    "title": SecurityAlert.title,
    "category": SecurityAlert.category,
}


class AlertRepository(BaseRepository[SecurityAlert]):
    model = SecurityAlert
    label = "Alert"

    def filtered(
        self,
        *,
        q: str | None = None,
        severity: list[str] | None = None,
        status: list[str] | None = None,
        category: str | None = None,
        source: str | None = None,
        asset_id: int | None = None,
        department_id: int | None = None,
        assigned_to_id: int | None = None,
        is_duplicate: bool | None = None,
        correlation_id: int | None = None,
        date_from: date | None = None,
        date_to: date | None = None,
    ) -> Select:
        stmt = select(SecurityAlert)
        stmt = text_search(stmt, q, SecurityAlert.title, SecurityAlert.description,
                           SecurityAlert.reference, SecurityAlert.source)
        if severity:
            stmt = stmt.where(SecurityAlert.severity.in_(severity))
        if status:
            stmt = stmt.where(SecurityAlert.status.in_(status))
        if category:
            stmt = stmt.where(SecurityAlert.category == category)
        if source:
            stmt = stmt.where(SecurityAlert.source == source)
        if asset_id is not None:
            stmt = stmt.where(SecurityAlert.asset_id == asset_id)
        if department_id is not None:
            stmt = stmt.where(SecurityAlert.asset_id.in_(select(Asset.id).where(Asset.department_id == department_id)))
        if assigned_to_id is not None:
            stmt = stmt.where(SecurityAlert.assigned_to_id == assigned_to_id)
        if is_duplicate is not None:
            stmt = stmt.where(SecurityAlert.is_duplicate.is_(is_duplicate))
        if correlation_id is not None:
            stmt = stmt.where(SecurityAlert.correlation_id == correlation_id)
        return date_range(stmt, SecurityAlert.detected_at, date_from, date_to)

    def find_original(self, fingerprint: str, detected_at: datetime, window_minutes: int) -> SecurityAlert | None:
        """The earliest non-duplicate alert with the same fingerprint detected within the window."""
        window = timedelta(minutes=window_minutes)
        return self.db.scalar(
            select(SecurityAlert)
            .where(
                SecurityAlert.fingerprint == fingerprint,
                SecurityAlert.is_duplicate.is_(False),
                SecurityAlert.detected_at >= detected_at - window,
                SecurityAlert.detected_at <= detected_at + window,
            )
            .order_by(SecurityAlert.detected_at.asc(), SecurityAlert.id.asc())
            .limit(1)
        )

    def by_ids(self, ids: list[int]) -> list[SecurityAlert]:
        if not ids:
            return []
        return list(self.db.scalars(select(SecurityAlert).where(SecurityAlert.id.in_(ids))))

    def uncorrelated_since(self, since: datetime) -> list[SecurityAlert]:
        return list(
            self.db.scalars(
                select(SecurityAlert)
                .where(
                    SecurityAlert.correlation_id.is_(None),
                    SecurityAlert.status != "false_positive",
                    SecurityAlert.detected_at >= since,
                )
                .order_by(SecurityAlert.asset_id, SecurityAlert.category, SecurityAlert.detected_at, SecurityAlert.id)
            )
        )

    def all_since(self, since: datetime) -> list[SecurityAlert]:
        return list(
            self.db.scalars(
                select(SecurityAlert)
                .where(SecurityAlert.status != "false_positive", SecurityAlert.detected_at >= since)
                .order_by(SecurityAlert.asset_id, SecurityAlert.category, SecurityAlert.detected_at, SecurityAlert.id)
            )
        )
