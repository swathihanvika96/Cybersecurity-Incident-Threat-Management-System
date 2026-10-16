from pydantic import Field

from app.core.constants import EvidenceType
from app.schemas.common import DT, ORMModel, RequestModel


class EvidenceCreate(RequestModel):
    title: str = Field(min_length=3, max_length=255)
    evidence_type: EvidenceType
    description: str | None = None
    reference: str = Field(min_length=3, max_length=500, description="Storage URI / path / ticket of the evidence")
    sha256: str | None = Field(None, pattern=r"^[A-Fa-f0-9]{64}$", description="Integrity hash of the evidence")


class EvidenceOut(ORMModel):
    id: int
    investigation_id: int
    title: str
    evidence_type: EvidenceType
    description: str | None = None
    reference: str
    sha256: str | None = None
    added_by_id: int | None = None
    added_at: DT
