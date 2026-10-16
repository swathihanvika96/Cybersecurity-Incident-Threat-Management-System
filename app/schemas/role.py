from pydantic import Field, field_validator

from app.schemas.common import DT, ORMModel, RequestModel


class RoleBrief(ORMModel):
    id: int
    name: str


class RoleOut(ORMModel):
    id: int
    name: str
    description: str | None = None
    is_system: bool
    permissions: list[str]
    created_at: DT

    @field_validator("permissions", mode="before")
    @classmethod
    def _names(cls, value):
        return sorted(getattr(p, "name", p) for p in value)


class RoleCreate(RequestModel):
    name: str = Field(min_length=3, max_length=60, pattern=r"^[a-z][a-z0-9_]*$")
    description: str | None = Field(None, max_length=255)
    permissions: list[str] = Field(default_factory=list)


class RolePermissionsUpdate(RequestModel):
    permissions: list[str] = Field(description="Complete new permission set for the role")
