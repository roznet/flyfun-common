"""FastAPI dependencies: DB session and auth.

Supports three auth methods (in priority order):
1. Dev mode bypass → DEV_USER_ID
2. JWT cookie (set by OAuth login)
3. Bearer token: JWT or hashed API token (ff_ prefix)
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Generator
from datetime import datetime, timezone

import jwt
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from flyfun_common.auth.config import COOKIE_NAME, get_jwt_secret
from flyfun_common.auth.jwt_utils import decode_token
from flyfun_common.db.engine import DEV_USER_ID, SessionLocal, is_dev_mode
from flyfun_common.db.models import ApiTokenRow, UserRow

TOKEN_PREFIX = "ff_"
_LEGACY_TOKEN_PREFIX = "wb_"  # accept old tokens during migration

# ---------------------------------------------------------------------------
# OAuth scope enforcement (least-privilege for scoped access tokens)
#
# A token's ``scope`` is space-delimited. NULL/empty scope means UNRESTRICTED —
# cookie sessions, JWTs, manually-created API tokens, and legacy/pre-scope OAuth
# tokens all carry no scope and keep full access.
#
# Only scopes registered here via ``register_scope_paths`` are "limited": a token
# whose granted scopes are *all* limited may reach ONLY the (method, path)
# endpoints registered for those scopes — everything else is 403
# insufficient_scope (default-deny). A token that also carries an unregistered
# scope (e.g. the broad ``mcp`` connector scope) is treated as full access, so
# adding ``flights:read`` does not retroactively cage existing connectors.
# ---------------------------------------------------------------------------
_SCOPE_ALLOWLIST: dict[str, list[tuple[str, re.Pattern[str]]]] = {}


def register_scope_paths(scope: str, rules: list[tuple[str, str]]) -> None:
    """Register the endpoints a limited ``scope`` is allowed to reach.

    ``rules`` is a list of ``(method, path_regex)`` pairs; ``method`` may be
    ``"*"`` to match any verb. The regex is matched against ``request.url.path``
    with ``re.fullmatch`` semantics (anchor explicitly if you use ``.*``).
    Idempotent — re-registering a scope replaces its rules.
    """
    _SCOPE_ALLOWLIST[scope] = [(m.upper(), re.compile(p)) for m, p in rules]


def _enforce_scope(request: Request, scope: str | None) -> None:
    """Raise 403 if a limited-scope token may not reach this (method, path).

    No-op for unrestricted tokens (no scope) and for tokens carrying any
    scope that isn't in the limited registry (e.g. ``mcp`` → full access).
    """
    if not scope:
        return
    granted = scope.split()
    limited = [s for s in granted if s in _SCOPE_ALLOWLIST]
    if len(limited) != len(granted):
        # Carries at least one unregistered (broad) scope → full access.
        return
    method = request.method.upper()
    path = request.url.path
    for s in limited:
        for allowed_method, pattern in _SCOPE_ALLOWLIST[s]:
            if allowed_method in (method, "*") and pattern.fullmatch(path):
                return
    raise HTTPException(
        status_code=403,
        detail="insufficient_scope",
        headers={
            "WWW-Authenticate": (
                'Bearer error="insufficient_scope", '
                f'scope="{" ".join(limited)}"'
            )
        },
    )


def get_db() -> Generator[Session, None, None]:
    """Yield a SQLAlchemy session, committing on success or rolling back on error."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _is_api_token(token: str) -> bool:
    """Check if a bearer token is an API token (vs a JWT)."""
    return token.startswith(TOKEN_PREFIX) or token.startswith(_LEGACY_TOKEN_PREFIX)


def _authenticate_bearer_token(token: str, db: Session) -> tuple[str, str | None]:
    """Validate a hashed API token; return ``(user_id, scope)``.

    ``scope`` is the space-delimited OAuth scope stored on the token, or
    ``None`` for unscoped (manually-created / legacy / pre-scope) tokens.
    """
    if not _is_api_token(token):
        raise HTTPException(status_code=401, detail="Invalid token format")

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    row = (
        db.query(ApiTokenRow)
        .filter(ApiTokenRow.token_hash == token_hash)
        .first()
    )
    if not row:
        raise HTTPException(status_code=401, detail="Invalid token")
    if row.revoked:
        raise HTTPException(status_code=401, detail="Token revoked")
    if row.expires_at:
        expires = row.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="Token expired")

    row.last_used_at = datetime.now(timezone.utc)
    db.flush()
    return row.user_id, row.scope


def _decode_user_id(
    request: Request, db: Session
) -> tuple[str, int | None, str | None]:
    """Extract (user_id, token_iat, scope) from a JWT cookie or Bearer token.

    ``token_iat`` is the JWT ``iat`` (epoch seconds) for cookie/Bearer-JWT
    auth, used by the session-epoch revocation check. It is ``None`` for
    dev-mode and ``ff_`` API-token auth, which the epoch check does not
    apply to (API tokens are revoked individually via the api_tokens table).

    ``scope`` is the OAuth scope of an ``ff_`` API token, or ``None`` for
    every full-access path (dev mode, cookie, Bearer-JWT, unscoped tokens).

    Priority: dev mode → cookie → Bearer (JWT or API token).
    """
    if is_dev_mode():
        return DEV_USER_ID, None, None

    secret = get_jwt_secret()

    # Try JWT cookie
    cookie = request.cookies.get(COOKIE_NAME)
    if cookie:
        try:
            payload = decode_token(cookie, secret)
            return payload["sub"], payload.get("iat"), None
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Session expired")
        except (jwt.InvalidTokenError, KeyError):
            raise HTTPException(status_code=401, detail="Invalid session")

    # Try Bearer token
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        bearer_token = auth_header[7:]
        if not _is_api_token(bearer_token):
            try:
                payload = decode_token(bearer_token, secret)
                return payload["sub"], payload.get("iat"), None
            except jwt.ExpiredSignatureError:
                raise HTTPException(status_code=401, detail="Token expired")
            except (jwt.InvalidTokenError, KeyError):
                raise HTTPException(status_code=401, detail="Invalid token")
        user_id, scope = _authenticate_bearer_token(bearer_token, db)
        return user_id, None, scope

    raise HTTPException(status_code=401, detail="Not authenticated")


def _is_session_revoked(user: UserRow, token_iat: int | None) -> bool:
    """True if a JWT issued at ``token_iat`` predates the user's revocation
    epoch (set on "log out everywhere" / suspected compromise)."""
    if token_iat is None or user.tokens_valid_after is None:
        return False
    valid_after = user.tokens_valid_after
    if valid_after.tzinfo is None:
        valid_after = valid_after.replace(tzinfo=timezone.utc)
    return token_iat < valid_after.timestamp()


def current_user_id(
    request: Request,
    db: Session = Depends(get_db),
) -> str:
    """Return the authenticated user ID. Raises 401/403 on failure."""
    user_id, token_iat, scope = _decode_user_id(request, db)
    _enforce_scope(request, scope)

    if is_dev_mode():
        return user_id

    user = db.query(UserRow).filter(UserRow.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if not user.approved:
        raise HTTPException(status_code=403, detail="Account suspended")
    if _is_session_revoked(user, token_iat):
        raise HTTPException(
            status_code=401, detail="Session revoked, please sign in again"
        )

    return user_id


def optional_user_id(
    request: Request,
    db: Session = Depends(get_db),
) -> str | None:
    """Return the authenticated user ID, or None if not authenticated.

    A successfully-authenticated token whose scope forbids this endpoint still
    raises 403 ``insufficient_scope`` (it is authenticated, just not authorized) —
    only unauthenticated requests fall through to ``None``.
    """
    try:
        user_id, token_iat, scope = _decode_user_id(request, db)
    except HTTPException:
        return None

    _enforce_scope(request, scope)

    if is_dev_mode():
        return user_id

    user = db.query(UserRow).filter(UserRow.id == user_id).first()
    if not user or not user.approved:
        return None
    if _is_session_revoked(user, token_iat):
        return None

    return user_id
