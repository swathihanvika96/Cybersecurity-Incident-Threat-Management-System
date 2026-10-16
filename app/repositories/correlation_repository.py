from datetime import datetime

from sqlalchemy import Select, func, select

from app.models import AlertCorrelation, CorrelationHistory, SecurityAlert
from app.repositories.base import BaseRepository


class CorrelationRepository(BaseRepository[AlertCorrelation]):
    model = AlertCorrelation
    label = "Correlation"

    def filtered(
        self, *, asset_id: int | None = None, category: str | None = None, status: str | None = None
    ) -> Select:
        stmt = select(AlertCorrelation).order_by(AlertCorrelation.created_at.desc(), AlertCorrelation.id.desc())
        if asset_id is not None:
            stmt = stmt.where(AlertCorrelation.asset_id == asset_id)
        if category:
            stmt = stmt.where(AlertCorrelation.category == category)
        if status:
            stmt = stmt.where(AlertCorrelation.status == status)
        return stmt

    def open_for(self, asset_id: int, category: str, since: datetime) -> AlertCorrelation | None:
        """Open correlation for (asset, category) whose newest alert was detected at/after `since`."""
        latest = (
            select(func.max(SecurityAlert.detected_at))
            .where(SecurityAlert.correlation_id == AlertCorrelation.id)
            .scalar_subquery()
        )
        return self.db.scalar(
            select(AlertCorrelation)
            .where(
                AlertCorrelation.asset_id == asset_id,
                AlertCorrelation.category == category,
                AlertCorrelation.status == "open",
                AlertCorrelation.rule == "same_asset_category",
                latest >= since,
            )
            .order_by(AlertCorrelation.id.desc())
            .limit(1)
        )

    def history_stmt(self, correlation_id: int) -> Select:
        return (
            select(CorrelationHistory)
            .where(CorrelationHistory.correlation_id == correlation_id)
            .order_by(CorrelationHistory.timestamp.asc(), CorrelationHistory.id.asc())
        )
