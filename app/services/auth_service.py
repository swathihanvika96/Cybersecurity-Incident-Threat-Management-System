"""Registration, login, token lifecycle (rotation + reuse detection), logout and password reset."""
import uuid
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import ConflictError, ForbiddenError, UnauthorizedError, BadRequestError
from app.core.logging import client_ip_var, get_logger
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_reset_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.models import PasswordResetToken, RefreshToken, User
from app.repositories.user_repository import UserRepository
from app.schemas.auth import RegisterRequest
from app.services import audit_service
from app.utils.date_utils import utcnow

logger = get_logger("app.auth")


# --------------------------------------------------------------------------- sessions / tokens
def _issue_session(db: Session, user: User, user_agent: str | None) -> dict:
    now = utcnow()
    session_id = str(uuid.uuid4())
    db.add(
        RefreshToken(
            id=session_id,
            user_id=user.id,
            expires_at=now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            user_agent=(user_agent or "")[:255] or None,
            ip_address=client_ip_var.get(),
        )
    )
    return {
        "access_token": create_access_token(user.id, session_id, user.role_name),
        "refresh_token": create_refresh_token(user.id, session_id),
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "_session_id": session_id,
    }


def revoke_session(db: Session, session_id: str, replaced_by: str | None = None) -> None:
    session = db.get(RefreshToken, session_id)
    if session and not session.revoked:
        session.revoked = True
        session.revoked_at = utcnow()
        session.replaced_by = replaced_by


def revoke_all_sessions(db: Session, user_id: int, except_session_id: str | None = None) -> int:
    stmt = (
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked.is_(False))
        .values(revoked=True, revoked_at=utcnow())
    )
    if except_session_id:
        stmt = stmt.where(RefreshToken.id != except_session_id)
    return db.execute(stmt).rowcount or 0


def validate_access_session(db: Session, session_id: str) -> RefreshToken:
    session = db.get(RefreshToken, session_id)
    if session is None or session.revoked or session.expires_at < utcnow():
        raise UnauthorizedError("Session is no longer valid; please log in again")
    return session


# --------------------------------------------------------------------------- registration / login
def register(db: Session, data: RegisterRequest) -> User:
    repo = UserRepository(db)
    if repo.get_by_email(data.email):
        raise ConflictError("A user with this email already exists")
    user = User(
        email=data.email,
        full_name=data.full_name,
        phone=data.phone,
        hashed_password=hash_password(data.password),
        is_active=settings.REGISTRATION_AUTO_ACTIVATE,
    )
    repo.add(user)
    audit_service.record(
        db, user_id=user.id, action="user.register", entity_type="user", entity_id=user.id,
        new={"email": user.email, "is_active": user.is_active},
    )
    db.commit()
    return user


def login(db: Session, email: str, password: str, user_agent: str | None = None) -> dict:
    user = UserRepository(db).get_by_email(email)
    password_ok = verify_password(password, user.hashed_password if user else None)
    if not user or not password_ok:
        audit_service.record(
            db, user_id=user.id if user else None, action="auth.login_failed", entity_type="user",
            entity_id=user.id if user else None, new={"email": email.strip().lower()},
        )
        db.commit()  # persist the failed attempt even though we raise
        raise UnauthorizedError("Incorrect email or password")
    if not user.is_active:
        audit_service.record(db, user_id=user.id, action="auth.login_blocked_inactive", entity_type="user",
                             entity_id=user.id)
        db.commit()
        raise ForbiddenError("This account is not active. Contact an administrator.")
    tokens = _issue_session(db, user, user_agent)
    user.last_login_at = utcnow()
    audit_service.record(db, user_id=user.id, action="auth.login", entity_type="user", entity_id=user.id,
                         new={"session_id": tokens["_session_id"]})
    db.commit()
    tokens.pop("_session_id")
    return tokens


def refresh(db: Session, refresh_token: str, user_agent: str | None = None) -> dict:
    payload = decode_token(refresh_token, "refresh")
    session = db.get(RefreshToken, payload["sid"])
    if session is None or session.user_id != int(payload["sub"]):
        raise UnauthorizedError("Invalid refresh token")
    if session.revoked:
        if session.replaced_by:
            # a rotated-out refresh token was presented again: assume theft and kill every session
            revoke_all_sessions(db, session.user_id)
            audit_service.record(db, user_id=session.user_id, action="auth.refresh_token_reuse_detected",
                                 entity_type="user", entity_id=session.user_id)
            db.commit()
        raise UnauthorizedError("Refresh token has been revoked")
    if session.expires_at < utcnow():
        raise UnauthorizedError("Refresh token has expired")
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise UnauthorizedError("Account is not active")
    tokens = _issue_session(db, user, user_agent)
    revoke_session(db, session.id, replaced_by=tokens.pop("_session_id"))
    audit_service.record(db, user_id=user.id, action="auth.token_refresh", entity_type="user", entity_id=user.id)
    db.commit()
    return tokens


def logout(db: Session, user: User, session_id: str | None, all_sessions: bool = False) -> None:
    if all_sessions:
        revoke_all_sessions(db, user.id)
    elif session_id:
        revoke_session(db, session_id)
    audit_service.record(db, user_id=user.id, action="auth.logout", entity_type="user", entity_id=user.id,
                         new={"all_sessions": all_sessions})
    db.commit()


# --------------------------------------------------------------------------- passwords
def request_password_reset(db: Session, email: str) -> str | None:
    """Returns the raw token only to the caller (the router decides whether to expose it). Always behaves the same
    for unknown/inactive accounts so the endpoint cannot be used to enumerate users."""
    user = UserRepository(db).get_by_email(email)
    if user is None or not user.is_active:
        return None
    for old in db.scalars(
        select(PasswordResetToken).where(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None))
    ):
        old.used_at = utcnow()  # invalidate earlier outstanding tokens
    raw, hashed = generate_reset_token()
    db.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=hashed,
            expires_at=utcnow() + timedelta(minutes=settings.RESET_TOKEN_EXPIRE_MINUTES),
        )
    )
    audit_service.record(db, user_id=user.id, action="auth.password_reset_requested", entity_type="user",
                         entity_id=user.id)
    db.commit()
    send_reset_email(user.email, raw)
    return raw


def send_reset_email(email: str, token: str) -> None:
    """Simulated e-mail delivery. Replace with SMTP/provider integration; the token is deliberately not logged."""
    logger.info("password reset e-mail dispatched (simulated)", extra={"recipient": email})


def confirm_password_reset(db: Session, token: str, new_password: str) -> None:
    row = db.scalar(select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_token(token)))
    if row is None or row.used_at is not None or row.expires_at < utcnow():
        raise BadRequestError("Reset token is invalid or has expired")
    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        raise BadRequestError("Reset token is invalid or has expired")
    user.hashed_password = hash_password(new_password)
    row.used_at = utcnow()
    revoke_all_sessions(db, user.id)
    audit_service.record(db, user_id=user.id, action="auth.password_reset_completed", entity_type="user",
                         entity_id=user.id)
    db.commit()


def change_password(db: Session, user: User, current_password: str, new_password: str,
                    keep_session_id: str | None) -> None:
    if not verify_password(current_password, user.hashed_password):
        raise BadRequestError("Current password is incorrect")
    if verify_password(new_password, user.hashed_password):
        raise BadRequestError("New password must differ from the current password")
    user.hashed_password = hash_password(new_password)
    revoke_all_sessions(db, user.id, except_session_id=keep_session_id)
    audit_service.record(db, user_id=user.id, action="auth.password_changed", entity_type="user", entity_id=user.id)
    db.commit()
