"""JWT token creation and validation."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import jwt

JWT_ALGORITHM = "HS256"

# Defaults — overridable via env vars for operational tuning.
_DEFAULT_EXPIRY_DAYS = 30
_DEFAULT_REFRESH_THRESHOLD_DAYS = 15

# Short-lived, signed authorization code for the native "auth code" deep-link
# flow (see designs/oauth-deeplink-hardening.md). The code is a signed JWT —
# never the session token — carrying only the user id and the client-generated
# ``state`` nonce, with a very short TTL. The app exchanges it for the real
# session JWT over an HTTPS POST (``/auth/exchange``). Because it is signed with
# JWT_SECRET a forged code can't be exchanged; because it is bound to ``state``
# an injected callback can't authenticate the victim.
#
# NOTE: this is a *stateless* code, deliberately NOT single-use — there is no
# server-side used-code store. The short TTL bounds the replay window rather
# than eliminating it: a code+state callback URL that leaks (e.g. proxy/302
# logs) within the TTL can be replayed to mint the user's session. Accepted
# residual — the callback is captured privately by ASWebAuthenticationSession
# (not broadcast to other apps) and the window is short.
EXCHANGE_CODE_TTL_SECONDS = 60
_EXCHANGE_CODE_PURPOSE = "oauth_exchange"


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


def create_exchange_code(
    user_id: str,
    state: str,
    secret: str,
    ttl_seconds: int = EXCHANGE_CODE_TTL_SECONDS,
) -> str:
    """Mint a short-TTL, signed authorization code for the deep-link exchange.

    Carries the user id and the client's ``state`` nonce — NOT the session
    token. Verified and traded for the session JWT at ``/auth/exchange``.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "purpose": _EXCHANGE_CODE_PURPOSE,
        "uid": user_id,
        "state": state or "",
        "iat": now,
        "exp": now + timedelta(seconds=ttl_seconds),
    }
    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)


def decode_exchange_code(code: str, secret: str) -> dict:
    """Decode/validate an exchange code (signature + expiry + purpose).

    Raises ``jwt.InvalidTokenError`` (or a subclass) if the code is forged,
    expired, or is a normal session token rather than an exchange code.
    """
    claims = jwt.decode(code, secret, algorithms=[JWT_ALGORITHM])
    if claims.get("purpose") != _EXCHANGE_CODE_PURPOSE:
        raise jwt.InvalidTokenError("not an exchange code")
    return claims
