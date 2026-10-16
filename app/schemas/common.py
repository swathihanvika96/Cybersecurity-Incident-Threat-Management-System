"""Shared schema building blocks."""
import re
from datetime import datetime
from typing import Annotated, Any, Generic, TypeVar

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from app.utils.date_utils import attach_utc, to_naive_utc

T = TypeVar("T")

# Output datetimes are serialized as UTC ("...Z"); input datetimes (with or without offset) are normalised to UTC.
DT = Annotated[datetime, AfterValidator(attach_utc)]
DTIn = Annotated[datetime, AfterValidator(to_naive_utc)]


def _check_phone(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.replace(" ", "").replace("-", "")
    if not re.fullmatch(r"\+?[0-9]{7,15}", cleaned):
        raise ValueError("phone must contain 7-15 digits, optionally starting with +")
    return cleaned


Phone = Annotated[str, AfterValidator(_check_phone)]


class ORMModel(BaseModel):
    """Base for response models built from SQLAlchemy objects."""

    model_config = ConfigDict(from_attributes=True)


class RequestModel(BaseModel):
    """Base for request bodies: unknown fields are rejected (mass-assignment protection)."""

    model_config = ConfigDict(use_enum_values=True, extra="forbid", str_strip_whitespace=True)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int = Field(description="Total number of matching records")
    page: int = Field(description="Current page (1-based)")
    size: int = Field(description="Page size")
    pages: int = Field(description="Total number of pages")


class MessageResponse(BaseModel):
    message: str


class ErrorBody(BaseModel):
    code: str
    message: str
    details: Any | None = None


class ErrorResponse(BaseModel):
    success: bool = False
    error: ErrorBody
    request_id: str | None = None


COMMON_RESPONSES: dict[int | str, dict[str, Any]] = {
    400: {"model": ErrorResponse, "description": "Bad request / business rule violated"},
    401: {"model": ErrorResponse, "description": "Missing, invalid or expired credentials"},
    403: {"model": ErrorResponse, "description": "Authenticated but not permitted"},
    404: {"model": ErrorResponse, "description": "Resource not found"},
    409: {"model": ErrorResponse, "description": "Conflict with current state"},
}
