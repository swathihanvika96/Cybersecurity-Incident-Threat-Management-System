"""Password hashing (bcrypt), JWT creation/verification and one-time token helpers."""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.core.config import settings
from app.core.exceptions import UnauthorizedError

_DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt(rounds=settings.BCRYPT_ROUNDS)).decode()
BCRYPT_MAX_BYTES = 72


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=settings.BCRYPT_ROUNDS)).decode()


def verify_password(password: str, hashed: str | None) -> bool:
    """Constant-ish time: always performs one bcrypt comparison, even for unknown users."""
    candidate = password.encode()
    if len(candidate) > BCRYPT_MAX_BYTES:
        return False
    try:
        ok = bcrypt.checkpw(candidate, (hashed or _DUMMY_HASH).encode())
    except ValueError:
        return False
    return ok and hashed is not None


def _encode(user_id: int, session_id: str, token_type: str, expires: timedelta, extra: dict | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user_id), "sid": session_id, "type": token_type, "iat": now, "exp": now + expires}
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_access_token(user_id: int, session_id: str, role: str | None) -> str:
    return _encode(user_id, session_id, "access", timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
                   {"role": role})


def create_refresh_token(user_id: int, session_id: str) -> str:
    return _encode(user_id, session_id, "refresh", timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))


def decode_token(token: str, expected_type: str) -> dict:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM],
                             options={"require": ["exp", "sub", "sid", "type"]})
    except jwt.ExpiredSignatureError:
        raise UnauthorizedError("Token has expired") from None
    except jwt.PyJWTError:
        raise UnauthorizedError("Could not validate credentials") from None
    if payload.get("type") != expected_type:
        raise UnauthorizedError(f"Invalid token type: expected {expected_type} token")
    return payload


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_reset_token() -> tuple[str, str]:
    """Returns (raw_token, sha256_hash). Only the hash is stored."""
    raw = secrets.token_urlsafe(32)
    return raw, hash_token(raw)
