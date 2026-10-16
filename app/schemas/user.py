from pydantic import EmailStr, Field, field_validator

from app.schemas.auth import Password
from app.schemas.common import DT, ORMModel, Phone, RequestModel
from app.schemas.role import RoleBrief


class UserBrief(ORMModel):
    id: int
    full_name: str
    email: str


class UserOut(ORMModel):
    id: int
    email: str
    full_name: str
    phone: str | None = None
    role: RoleBrief | None = None
    organization_id: int | None = None
    department_id: int | None = None
    is_active: bool
    last_login_at: DT | None = None
    created_at: DT


class UserMe(UserOut):
    permissions: list[str] = Field(validation_alias="permission_names", description="Effective permissions")

    @field_validator("permissions", mode="before")
    @classmethod
    def _sorted(cls, value):
        return sorted(value)


class UserCreate(RequestModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=150)
    phone: Phone | None = Field(None, description="Contact number, 7-15 digits, optional leading +")
    password: Password
    role_id: int | None = None
    organization_id: int | None = None
    department_id: int | None = None
    is_active: bool = True

    @field_validator("email")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.lower()


class UserUpdate(RequestModel):
    full_name: str | None = Field(None, min_length=2, max_length=150)
    phone: Phone | None = None
    role_id: int | None = None
    organization_id: int | None = None
    department_id: int | None = None


class StatusChange(RequestModel):
    reason: str | None = Field(None, max_length=500)


class RoleAssign(RequestModel):
    role_id: int | None = Field(description="Role to assign (null removes the role and therefore all permissions)")
