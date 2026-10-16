from pydantic import Field, model_validator

from app.core.constants import InvestigationStatus
from app.schemas.common import DT, ORMModel, RequestModel
from app.schemas.user import UserBrief


class InvestigationCreate(RequestModel):
    title: str = Field(min_length=3, max_length=255)
    description: str | None = None
    owner_id: int | None = Field(None, description="Defaults to the creator")
    incident_ids: list[int] = Field(default_factory=list)
    alert_ids: list[int] = Field(default_factory=list)
    asset_ids: list[int] = Field(default_factory=list)


class InvestigationUpdate(RequestModel):
    title: str | None = Field(None, min_length=3, max_length=255)
    description: str | None = None


class InvestigationLink(RequestModel):
    incident_ids: list[int] = Field(default_factory=list)
    alert_ids: list[int] = Field(default_factory=list)
    asset_ids: list[int] = Field(default_factory=list)

    @model_validator(mode="after")
    def _not_empty(self):
        if not (self.incident_ids or self.alert_ids or self.asset_ids):
            raise ValueError("Provide at least one incident, alert or asset to link")
        return self


class OwnerChange(RequestModel):
    owner_id: int


class InvestigationComplete(RequestModel):
    summary: str = Field(min_length=10, description="Findings and conclusion of the investigation")


class InvestigationOut(ORMModel):
    id: int
    reference: str | None = None
    title: str
    description: str | None = None
    status: InvestigationStatus
    owner: UserBrief | None = None
    created_by_id: int | None = None
    summary: str | None = None
    completed_at: DT | None = None
    incident_ids: list[int]
    alert_ids: list[int]
    asset_ids: list[int]
    created_at: DT
    updated_at: DT
