import jwt
import pytest

from app.core.config import settings
from app.core.exceptions import UnauthorizedError
from app.core.security import (create_access_token, create_refresh_token, decode_token, generate_reset_token,
                               hash_password, hash_token, verify_password)
from app.schemas.auth import RegisterRequest
from app.utils.csv_export import rows_to_csv


def test_password_hash_roundtrip():
    hashed = hash_password("Str0ng!Passw0rd")
    assert hashed != "Str0ng!Passw0rd" and verify_password("Str0ng!Passw0rd", hashed)
    assert not verify_password("wrong", hashed) and not verify_password("x", None)


def test_access_and_refresh_tokens_are_not_interchangeable():
    access, refresh = create_access_token(1, "sid", "auditor"), create_refresh_token(1, "sid")
    assert decode_token(access, "access")["sub"] == "1"
    with pytest.raises(UnauthorizedError):
        decode_token(refresh, "access")
    with pytest.raises(UnauthorizedError):
        decode_token(access, "refresh")


def test_tampered_or_garbage_token_rejected():
    with pytest.raises(UnauthorizedError):
        decode_token(create_access_token(1, "sid", None) + "x", "access")
    with pytest.raises(UnauthorizedError):
        decode_token("garbage", "access")
    forged = jwt.encode({"sub": "1", "sid": "s", "type": "access"}, "other-secret-other-secret-other-secret!",
                        algorithm=settings.ALGORITHM)
    with pytest.raises(UnauthorizedError):
        decode_token(forged, "access")


def test_reset_token_is_stored_hashed():
    raw, hashed = generate_reset_token()
    assert raw != hashed and hash_token(raw) == hashed


@pytest.mark.parametrize("pw", ["Sh0rt", "alllowercase1!", "ALLUPPERCASE1!", "NoDigitsHere!", "x" * 80])
def test_weak_passwords_rejected(pw):
    with pytest.raises(ValueError):
        RegisterRequest(email="a@b.co", full_name="Test User", password=pw)


def test_csv_formula_injection_neutralised():
    out = rows_to_csv([{"a": "=CMD()", "b": "+1", "c": "@x", "d": "safe", "e": True, "f": None}], list("abcdef"))
    row = out.splitlines()[1]
    assert row == "'=CMD(),'+1,'@x,safe,true,"
