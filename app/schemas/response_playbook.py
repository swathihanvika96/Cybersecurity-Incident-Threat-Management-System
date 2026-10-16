from pydantic import Field

from app.core.constants import PlaybookStepType, SecurityCategory
from app.schemas.common import DT, ORMModel, RequestModel


class PlaybookStepIn(RequestModel):
    title: str = Field(min_length=3, max_length=255)
    description: str | None = None
    step_type: PlaybookStepType
    is_sensitive: bool = Field(False, description="Completion requires approval by a different user")
    simulated_action: str | None = Field(
        None, max_length=255, description="Action that is SIMULATED when the step is completed (never executed)"
    )


class PlaybookCreate(RequestModel):
    name: str = Field(min_length=3, max_length=200)
    description: str | None = None
    incident_category: SecurityCategory | None = Field(None, description="Null = usable for any incident category")
    steps: list[PlaybookStepIn] = Field(min_length=1, max_length=50, description="Ordered steps (list order)")


class PlaybookUpdate(RequestModel):
    name: str | None = Field(None, min_length=3, max_length=200)
    description: str | None = None
    incident_category: SecurityCategory | None = None
    is_active: bool | None = None


class PlaybookStepsReplace(RequestModel):
    steps: list[PlaybookStepIn] = Field(min_length=1, max_length=50)


class PlaybookStepOut(ORMModel):
    id: int
    step_order: int
    title: str
    description: str | None = None
    step_type: PlaybookStepType
    is_sensitive: bool
    simulated_action: str | None = None


class PlaybookOut(ORMModel):
    id: int
    name: str
    description: str | None = None
    incident_category: SecurityCategory | None = None
    is_active: bool
    steps: list[PlaybookStepOut]
    created_at: DT
    updated_at: DT
