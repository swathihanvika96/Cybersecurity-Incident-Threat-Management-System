from typing import Annotated

from pydantic import AfterValidator, BaseModel, EmailStr, Field, field_validator

from app.core.security import BCRYPT_MAX_BYTES
from app.schemas.common import Phone, RequestModel


def check_password_strength(value: str) -> str:
    if len(value.encode()) > BCRYPT_MAX_BYTES:
        raise ValueError("Password must be at most 72 bytes")
    if not (any(c.islower() for c in value) and any(c.isupper() for c in value) and any(c.isdigit() for c in value)):
        raise ValueError("Password must contain upper-case, lower-case and numeric characters")
    return value


Password = Annotated[str, Field(min_length=8, max_length=72), AfterValidator(check_password_strength)]


class _EmailMixin(RequestModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.lower()


class RegisterRequest(_EmailMixin):
    full_name: str = Field(min_length=2, max_length=150)
    phone: Phone | None = Field(None, description="Contact number, 7-15 digits, optional leading +")
    password: Password


class LoginRequest(_EmailMixin):
    password: str = Field(min_length=1, max_length=128)


class RefreshRequest(RequestModel):
    refresh_token: str


class LogoutRequest(RequestModel):
    all_sessions: bool = Field(False, description="Also revoke every other session of this user")


class PasswordResetRequest(_EmailMixin):
    pass


class PasswordResetConfirm(RequestModel):
    token: str = Field(min_length=10)
    new_password: Password


class PasswordChange(RequestModel):
    current_password: str
    new_password: Password


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Access-token lifetime in seconds")


class PasswordResetResponse(BaseModel):
    message: str
    reset_token: str | None = Field(None, description="Only present when EXPOSE_RESET_TOKEN=true (development)")
