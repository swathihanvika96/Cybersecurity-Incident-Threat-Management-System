"""Shared FastAPI dependencies: DB session, authentication and permission guards."""
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import ForbiddenError, UnauthorizedError
from app.core.security import decode_token
from app.db.session import get_db
from app.models import User
from app.services import auth_service

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_PREFIX}/auth/token",
    scheme_name="OAuth2PasswordBearer",
    description="Log in with your e-mail (as *username*) and password. "
                "Or call `POST /auth/login` and paste the `access_token` here.",
    auto_error=False,
)

DbSession = Annotated[Session, Depends(get_db)]


def get_current_user(request: Request, db: DbSession, token: Annotated[str | None, Depends(oauth2_scheme)]) -> User:
    if not token:
        raise UnauthorizedError("Not authenticated")
    payload = decode_token(token, "access")
    auth_service.validate_access_session(db, payload["sid"])  # logout / deactivation / password change revoke it
    user = db.get(User, int(payload["sub"]))
    if user is None:
        raise UnauthorizedError("User no longer exists")
    if not user.is_active:
        raise ForbiddenError("This account is not active")
    user.session_id = payload["sid"]  # transient attribute used by logout / change-password
    request.state.user_id = user.id
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_permission(*permissions: str):
    """Dependency factory: the caller must hold ALL given permissions."""

    def checker(user: CurrentUser) -> User:
        missing = [p for p in permissions if not user.has_permission(p)]
        if missing:
            raise ForbiddenError("Missing required permission: " + ", ".join(missing))
        return user

    return checker


def require_any_permission(*permissions: str):
    """Dependency factory: the caller must hold AT LEAST ONE of the given permissions."""

    def checker(user: CurrentUser) -> User:
        if not any(user.has_permission(p) for p in permissions):
            raise ForbiddenError("Missing required permission: one of " + ", ".join(permissions))
        return user

    return checker
