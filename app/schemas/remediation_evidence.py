from typing import Literal

from pydantic import Field

from app.schemas.common import DT, ORMModel, RequestModel


class RemediationEvidenceCreate(RequestModel):
    description: str = Field(min_length=3, description="What was done / what the evidence shows")
    reference_type: Literal["patch", "config_change", "scan_report", "ticket", "screenshot", "other"] = "other"
    reference_url: str | None = Field(None, max_length=500, description="Link or storage path of the evidence")


class RemediationEvidenceOut(ORMModel):
    id: int
    task_id: int
    description: str
    reference_type: str | None = None
    reference_url: str | None = None
    added_by_id: int | None = None
    added_at: DT
