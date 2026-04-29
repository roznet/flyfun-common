"""JWT token creation and validation."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import jwt

JWT_ALGORITHM = "HS256"

# Defaults — overridable via env vars for operational tuning.
_DEFAULT_EXPIRY_DAYS = 30
_DEFAULT_REFRESH_THRESHOLD_DAYS = 15


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def get_jwt_expiry_days() -> int:
    """Absolute cookie/token lifetime in days. Rolling refresh caps here."""
    return _int_env("JWT_EXPIRY_DAYS", _DEFAULT_EXPIRY_DAYS)


def get_jwt_refresh_threshold_days() -> int:
    """Refresh the cookie when remaining lifetime drops below this many days."""
    return _int_env("JWT_REFRESH_THRESHOLD_DAYS", _DEFAULT_REFRESH_THRESHOLD_DAYS)


def get_jwt_cookie_max_age() -> int:
    """Cookie max_age in seconds, matching the JWT expiry."""
    return get_jwt_expiry_days() * 24 * 3600


def create_token(user_id: str, email: str, name: str, secret: str) -> str:
    """Create a signed JWT with user claims and the configured expiry."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "email": email,
        "name": name,
        "iat": now,
        "exp": now + timedelta(days=get_jwt_expiry_days()),
    }
    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)


def decode_token(token: str, secret: str) -> dict:
    """Decode and validate a JWT."""
    return jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
