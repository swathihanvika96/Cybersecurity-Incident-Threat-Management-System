from pydantic import Field

from app.schemas.common import DT, DTIn, ORMModel, RequestModel


class RiskAcceptanceCreate(RequestModel):
    asset_id: int
    vulnerability_id: int
    justification: str = Field(min_length=10, description="Business justification for accepting the risk")
    expires_at: DTIn | None = Field(None, description="Acceptance lapses at this time (recommended)")


class RiskAcceptanceRevoke(RequestModel):
    reason: str = Field(min_length=3, max_length=1000)


class RiskAcceptanceOut(ORMModel):
    id: int
    asset_id: int
    vulnerability_id: int
    justification: str
    status: str
    accepted_by_id: int
    accepted_at: DT
    expires_at: DT | None = None
    revoked_by_id: int | None = None
    revoked_at: DT | None = None
    revoke_reason: str | None = None
