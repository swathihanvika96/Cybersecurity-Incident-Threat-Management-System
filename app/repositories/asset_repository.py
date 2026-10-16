from sqlalchemy import Select, select

from app.core.constants import ASSET_CRITICALITY_RANK
from app.models import Asset, AssetHistory
from app.repositories.base import BaseRepository
from app.utils.filtering import text_search
from app.utils.sorting import rank_case

SORT_MAP = {
    "name": Asset.name,
    "created_at": Asset.created_at,
    "updated_at": Asset.updated_at,
    "criticality": rank_case(Asset.criticality, ASSET_CRITICALITY_RANK),
    "status": Asset.status,
    "asset_type": Asset.asset_type,
}


class AssetRepository(BaseRepository[Asset]):
    model = Asset
    label = "Asset"

    def get_by_name(self, organization_id: int, name: str) -> Asset | None:
        return self.db.scalar(select(Asset).where(Asset.organization_id == organization_id, Asset.name == name))

    def filtered(
        self,
        *,
        q: str | None = None,
        asset_type: str | None = None,
        criticality: str | None = None,
        status: str | None = None,
        organization_id: int | None = None,
        department_id: int | None = None,
        owner_id: int | None = None,
    ) -> Select:
        stmt = select(Asset)
        stmt = text_search(stmt, q, Asset.name, Asset.hostname, Asset.ip_address, Asset.description)
        for column, value in (
            (Asset.asset_type, asset_type),
            (Asset.criticality, criticality),
            (Asset.status, status),
            (Asset.organization_id, organization_id),
            (Asset.department_id, department_id),
            (Asset.owner_id, owner_id),
        ):
            if value is not None:
                stmt = stmt.where(column == value)
        return stmt

    def history_stmt(self, asset_id: int) -> Select:
        return select(AssetHistory).where(AssetHistory.asset_id == asset_id).order_by(
            AssetHistory.changed_at.desc(), AssetHistory.id.desc()
        )
