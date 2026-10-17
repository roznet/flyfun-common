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
from flyfun_common.auth.middleware import mark_session_authenticated
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
# A token carrying a *broad* scope (``mcp`` by default, see
# ``register_broad_scope``) has full access. Every other scope is limited and
# DEFAULT-DENY: it may reach only the (method, path) endpoints this process
# registered for it via ``register_scope_paths``; everything else is 403
# insufficient_scope. The registry is per process while ``api_tokens`` is
# shared across apps, so a scope one app issues (e.g. weather's
# ``flights:read``) reaches nothing on an app that never registered it.
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


_BROAD_SCOPES: set[str] = {"mcp"}


def register_broad_scope(scope: str) -> None:
    """Mark ``scope`` as broad: a token carrying it has full access.

    ``mcp`` is broad by default (the claude.ai/Cowork connector scope). The
    registry is per process, like the scope allowlist: broad applies only in
    the app that registers it. Only use it for scopes whose consent screen
    already promises full account access.
    """
    _BROAD_SCOPES.add(scope)


def _enforce_scope(request: Request, scope: str | None) -> None:
    """Raise 403 if a scoped token may not reach this (method, path).

    No-op for unrestricted tokens (no scope) and for tokens carrying a broad
    scope. Any other scope is allowed only on the endpoints registered for it
    in this process; an unregistered scope reaches nothing.
    """
    if not scope:
        return
    granted = scope.split()
    if any(s in _BROAD_SCOPES for s in granted):
        return
    method = request.method.upper()
    path = request.url.path
    for s in granted:
        for allowed_method, pattern in _SCOPE_ALLOWLIST.get(s, ()):
            if allowed_method in (method, "*") and pattern.fullmatch(path):
                return
    raise HTTPException(
        status_code=403,
        detail="insufficient_scope",
        headers={
            "WWW-Authenticate": (
                'Bearer error="insufficient_scope", '
                f'scope="{" ".join(granted)}"'
            )
        },
    )


def get_db() -> Generator[Session, None, None]:
    """Yield a SQLAlchemy session, committing on success or rolling back on error.

    Declare it as ``Depends(get_db, scope="function")``. The default
    ("request") scope runs the commit after the response has been sent, so a
    client's immediate follow-up request can read the pre-write state, and a
    failed commit is never reported to the client. ``"function"`` commits after
    the endpoint and its response serialization, before anything is sent.

    Every dependency in this library uses ``"function"``, and FastAPI caches
    a dependency per (callable, scope): an app that mixes in a bare
    ``Depends(get_db)`` gets a second session in the same request. Check an
    app with ``find_request_scoped_db``.
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def find_request_scoped_db(app) -> list[str]:
    """List the routes of ``app`` that resolve ``get_db`` without ``scope="function"``.

    Each entry is ``"METHODS path"``. Meant for an app's test suite:
    ``assert find_request_scoped_db(app) == []``. It matches ``get_db``
    itself: a wrapper generator (``yield from get_db()``) is not seen, and
    needs ``scope="function"`` on its own ``Depends``.
    """

    def _uses_request_scope(dependant) -> bool:
        for sub in dependant.dependencies:
            # ``scope`` is what FastAPI checks to pick the function exit stack.
            if sub.call is get_db and sub.scope != "function":
                return True
            if _uses_request_scope(sub):
                return True
        return False

    return [
        label
        for label, dependant in _iter_route_dependants(app.routes)
        if _uses_request_scope(dependant)
    ]


def _iter_route_dependants(routes, prefix: str = ""):
    """Yield ``("METHODS path", dependant)`` for every route, mounts included.

    FastAPI >= 0.140 keeps an included router as one lazy entry whose
    effective contexts carry each route's dependant with the include-level
    dependencies merged in. Older releases flatten into ``APIRoute``s.
    """
    for route in routes:
        contexts = getattr(route, "effective_route_contexts", None)
        if callable(contexts):
            for context in contexts():
                if getattr(context, "dependant", None) is not None:
                    yield from _iter_route_dependants([context], prefix)
                else:
                    yield from _iter_route_dependants(
                        [context.starlette_route or context.original_route], prefix
                    )
            continue
        dependant = getattr(route, "dependant", None)
        if dependant is not None:
            methods = ",".join(sorted(getattr(route, "methods", None) or ["WS"]))
            yield f"{methods} {prefix}{route.path}", dependant
            continue
        sub_routes = getattr(getattr(route, "app", None), "routes", None)
        if sub_routes is not None:
            yield from _iter_route_dependants(sub_routes, prefix + getattr(route, "path", ""))


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


def _mark_if_session(request: Request, user_id: str, token_iat: int | None) -> None:
    """Allow SlidingSessionMiddleware to renew this request's session JWT.

    Only for JWT auth (``token_iat`` set); ``ff_`` API tokens are never
    renewed. Called only after every check above has passed.
    """
    if token_iat is not None:
        mark_session_authenticated(request, user_id)


def current_user_id(
    request: Request,
    db: Session = Depends(get_db, scope="function"),
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

    _mark_if_session(request, user_id, token_iat)
    return user_id


def optional_user_id(
    request: Request,
    db: Session = Depends(get_db, scope="function"),
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

    _mark_if_session(request, user_id, token_iat)
    return user_id
