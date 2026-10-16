from pydantic import EmailStr, Field

from app.schemas.common import DT, ORMModel, Phone, RequestModel


class OrganizationCreate(RequestModel):
    name: str = Field(min_length=2, max_length=200)
    description: str | None = None
    industry: str | None = Field(None, max_length=100)
    contact_email: EmailStr | None = None
    contact_phone: Phone | None = None


class OrganizationUpdate(RequestModel):
    name: str | None = Field(None, min_length=2, max_length=200)
    description: str | None = None
    industry: str | None = Field(None, max_length=100)
    contact_email: EmailStr | None = None
    contact_phone: Phone | None = None
    is_active: bool | None = None


class OrganizationOut(ORMModel):
    id: int
    name: str
    description: str | None = None
    industry: str | None = None
    contact_email: str | None = None
    contact_phone: str | None = None
    is_active: bool
    created_at: DT
