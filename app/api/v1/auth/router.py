from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from fastapi.security import OAuth2PasswordRequestForm

from app.api.deps import CurrentUser, DbSession
from app.core.config import settings
from app.schemas.auth import (
    LoginRequest,
    LogoutRequest,
    PasswordChange,
    PasswordResetConfirm,
    PasswordResetRequest,
    PasswordResetResponse,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
)
from app.schemas.common import COMMON_RESPONSES, MessageResponse
from app.schemas.user import UserMe, UserOut
from app.services import auth_service

router = APIRouter(prefix="/auth", tags=["Authentication"], responses=COMMON_RESPONSES)


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED, summary="Register an account")
def register(data: RegisterRequest, db: DbSession):
    """Self-registration. The account has **no role** and is **inactive** until an administrator activates it and
    assigns a role (unless `REGISTRATION_AUTO_ACTIVATE=true`)."""
    return auth_service.register(db, data)


@router.post("/login", response_model=TokenResponse, summary="Log in (JSON)")
def login(data: LoginRequest, request: Request, db: DbSession):
    """Returns a short-lived **access token** and a long-lived **refresh token**."""
    return auth_service.login(db, data.email, data.password, request.headers.get("user-agent"))


@router.post("/token", response_model=TokenResponse, summary="Log in (OAuth2 form, used by Swagger 'Authorize')")
def login_form(form: Annotated[OAuth2PasswordRequestForm, Depends()], request: Request, db: DbSession):
    """OAuth2 password flow: send the e-mail address as `username`."""
    return auth_service.login(db, form.username, form.password, request.headers.get("user-agent"))


@router.post("/refresh", response_model=TokenResponse, summary="Rotate tokens with a refresh token")
def refresh(data: RefreshRequest, request: Request, db: DbSession):
    """Each refresh token can be used **once**. Re-using a rotated token revokes every session of the user."""
    return auth_service.refresh(db, data.refresh_token, request.headers.get("user-agent"))


@router.post("/logout", response_model=MessageResponse, summary="Log out and invalidate the tokens")
def logout(user: CurrentUser, db: DbSession, data: LogoutRequest | None = None):
    """Revokes the current session: both its access and refresh token stop working immediately."""
    auth_service.logout(db, user, getattr(user, "session_id", None), bool(data and data.all_sessions))
    return {"message": "Logged out"}


@router.get("/me", response_model=UserMe, summary="Current user")
def me(user: CurrentUser):
    """The authenticated user with role and effective permissions."""
    return user


@router.post("/password-reset/request", response_model=PasswordResetResponse, summary="Request a password reset")
def password_reset_request(data: PasswordResetRequest, db: DbSession):
    """Always answers the same way, whether or not the e-mail exists. The token is delivered by e-mail
    (simulated); it is only returned in the response when `EXPOSE_RESET_TOKEN=true` (development)."""
    token = auth_service.request_password_reset(db, data.email)
    return {
        "message": "If the account exists and is active, password reset instructions have been sent",
        "reset_token": token if settings.EXPOSE_RESET_TOKEN else None,
    }


@router.post("/password-reset/confirm", response_model=MessageResponse, summary="Set a new password with a reset token")
def password_reset_confirm(data: PasswordResetConfirm, db: DbSession):
    """Single-use token. Success revokes every existing session of the user."""
    auth_service.confirm_password_reset(db, data.token, data.new_password)
    return {"message": "Password has been reset. Please log in again."}


@router.post("/change-password", response_model=MessageResponse, summary="Change own password")
def change_password(data: PasswordChange, user: CurrentUser, db: DbSession):
    """Other sessions are revoked; the current one stays valid."""
    auth_service.change_password(db, user, data.current_password, data.new_password, getattr(user, "session_id", None))
    return {"message": "Password changed"}
