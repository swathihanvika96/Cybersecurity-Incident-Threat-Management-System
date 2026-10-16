from pydantic import Field

from app.schemas.common import DT, ORMModel, RequestModel


class DepartmentCreate(RequestModel):
    organization_id: int
    name: str = Field(min_length=2, max_length=150)
    description: str | None = None


class DepartmentUpdate(RequestModel):
    name: str | None = Field(None, min_length=2, max_length=150)
    description: str | None = None
    is_active: bool | None = None


class DepartmentBrief(ORMModel):
    id: int
    name: str


class DepartmentOut(ORMModel):
    id: int
    organization_id: int
    name: str
    description: str | None = None
    is_active: bool
    created_at: DT
