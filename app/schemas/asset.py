import ipaddress

from pydantic import Field, field_validator

from app.core.constants import AssetCriticality, AssetStatus, AssetType
from app.schemas.common import DT, ORMModel, RequestModel
from app.schemas.department import DepartmentBrief
from app.schemas.user import UserBrief


def _check_ip(value: str | None) -> str | None:
    if value is None:
        return value
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ValueError("ip_address must be a valid IPv4/IPv6 address") from None


class AssetCreate(RequestModel):
    name: str = Field(min_length=2, max_length=200)
    asset_type: AssetType
    criticality: AssetCriticality
    status: AssetStatus = AssetStatus.ACTIVE
    hostname: str | None = Field(None, max_length=255)
    ip_address: str | None = None
    location: str | None = Field(None, max_length=200)
    description: str | None = None
    organization_id: int
    department_id: int | None = None
    owner_id: int | None = None

    _ip = field_validator("ip_address")(_check_ip)


class AssetUpdate(RequestModel):
    name: str | None = Field(None, min_length=2, max_length=200)
    asset_type: AssetType | None = None
    criticality: AssetCriticality | None = None
    hostname: str | None = Field(None, max_length=255)
    ip_address: str | None = None
    location: str | None = Field(None, max_length=200)
    description: str | None = None
    department_id: int | None = None

    _ip = field_validator("ip_address")(_check_ip)


class AssetStatusUpdate(RequestModel):
    status: AssetStatus
    reason: str | None = Field(None, max_length=500)


class AssetOwnerAssign(RequestModel):
    owner_id: int | None = Field(description="User id of the new owner (null clears the owner)")


class AssetBrief(ORMModel):
    id: int
    name: str
    asset_type: AssetType
    criticality: AssetCriticality


class AssetOut(ORMModel):
    id: int
    name: str
    asset_type: AssetType
    criticality: AssetCriticality
    status: AssetStatus
    hostname: str | None = None
    ip_address: str | None = None
    location: str | None = None
    description: str | None = None
    organization_id: int
    department: DepartmentBrief | None = None
    owner: UserBrief | None = None
    created_at: DT
    updated_at: DT


class AssetHistoryOut(ORMModel):
    id: int
    asset_id: int
    changed_by_id: int | None = None
    action: str
    field_name: str | None = None
    old_value: str | None = None
    new_value: str | None = None
    changed_at: DT
