from sqlalchemy import Select, func, select

from app.models import Asset, AssetVulnerability, RiskAcceptance, RiskAssessment
from app.repositories.base import BaseRepository


class RiskRepository(BaseRepository[RiskAssessment]):
    model = RiskAssessment
    label = "Risk assessment"

    def current(self, asset_id: int, vulnerability_id: int) -> RiskAssessment | None:
        return self.db.scalar(
            select(RiskAssessment).where(
                RiskAssessment.asset_id == asset_id,
                RiskAssessment.vulnerability_id == vulnerability_id,
                RiskAssessment.is_current.is_(True),
            )
        )

    def filtered(
        self,
        *,
        asset_id: int | None = None,
        vulnerability_id: int | None = None,
        risk_level: list[str] | None = None,
        current_only: bool = True,
    ) -> Select:
        stmt = select(RiskAssessment).order_by(RiskAssessment.assessed_at.desc(), RiskAssessment.id.desc())
        if asset_id is not None:
            stmt = stmt.where(RiskAssessment.asset_id == asset_id)
        if vulnerability_id is not None:
            stmt = stmt.where(RiskAssessment.vulnerability_id == vulnerability_id)
        if risk_level:
            stmt = stmt.where(RiskAssessment.risk_level.in_(risk_level))
        if current_only:
            stmt = stmt.where(RiskAssessment.is_current.is_(True))
        return stmt

    def asset_risk_rows(self, asset_id: int | None = None) -> list[tuple[int, float, int]]:
        """(asset_id, highest current score, open vulnerability count) for assets with open vulnerabilities."""
        stmt = (
            select(
                AssetVulnerability.asset_id,
                func.max(RiskAssessment.risk_score),
                func.count(AssetVulnerability.id),
            )
            .join(
                RiskAssessment,
                (RiskAssessment.asset_id == AssetVulnerability.asset_id)
                & (RiskAssessment.vulnerability_id == AssetVulnerability.vulnerability_id)
                & (RiskAssessment.is_current.is_(True)),
            )
            .where(AssetVulnerability.status == "open")
            .group_by(AssetVulnerability.asset_id)
            .order_by(func.max(RiskAssessment.risk_score).desc(), AssetVulnerability.asset_id)
        )
        if asset_id is not None:
            stmt = stmt.where(AssetVulnerability.asset_id == asset_id)
        return [(a, float(s), int(c)) for a, s, c in self.db.execute(stmt)]

    def accepted_counts(self) -> dict[int, int]:
        rows = self.db.execute(
            select(AssetVulnerability.asset_id, func.count(AssetVulnerability.id))
            .where(AssetVulnerability.status == "accepted_risk")
            .group_by(AssetVulnerability.asset_id)
        )
        return {a: int(c) for a, c in rows}

    def assets_by_ids(self, ids: list[int]) -> dict[int, Asset]:
        if not ids:
            return {}
        return {a.id: a for a in self.db.scalars(select(Asset).where(Asset.id.in_(ids)))}

    # ---- acceptances
    def get_acceptance(self, acceptance_id: int) -> RiskAcceptance | None:
        return self.db.get(RiskAcceptance, acceptance_id)

    def active_acceptance(self, asset_id: int, vulnerability_id: int) -> RiskAcceptance | None:
        return self.db.scalar(
            select(RiskAcceptance).where(
                RiskAcceptance.asset_id == asset_id,
                RiskAcceptance.vulnerability_id == vulnerability_id,
                RiskAcceptance.status == "active",
            )
        )

    def acceptances_stmt(
        self, *, status: str | None = None, asset_id: int | None = None, vulnerability_id: int | None = None
    ) -> Select:
        stmt = select(RiskAcceptance).order_by(RiskAcceptance.accepted_at.desc(), RiskAcceptance.id.desc())
        if status:
            stmt = stmt.where(RiskAcceptance.status == status)
        if asset_id is not None:
            stmt = stmt.where(RiskAcceptance.asset_id == asset_id)
        if vulnerability_id is not None:
            stmt = stmt.where(RiskAcceptance.vulnerability_id == vulnerability_id)
        return stmt
