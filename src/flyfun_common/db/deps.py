"""FastAPI dependencies: DB session and auth.

Supports three auth methods (in priority order):
1. Dev mode bypass → DEV_USER_ID
2. JWT cookie (set by OAuth login)
3. Bearer token: JWT or hashed API token (ff_ prefix)
"""

from __future__ import annotations

import hashlib
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


def _authenticate_bearer_token(token: str, db: Session) -> str:
    """Validate a hashed API token against the api_tokens table."""
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
    return row.user_id


def _decode_user_id(request: Request, db: Session) -> str:
    """Extract user ID from JWT cookie or Bearer token.

    Priority: dev mode → cookie → Bearer (JWT or API token).
    """
    if is_dev_mode():
        return DEV_USER_ID

    secret = get_jwt_secret()

    # Try JWT cookie
    cookie = request.cookies.get(COOKIE_NAME)
    if cookie:
        try:
            payload = decode_token(cookie, secret)
            return payload["sub"]
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
                return payload["sub"]
            except jwt.ExpiredSignatureError:
                raise HTTPException(status_code=401, detail="Token expired")
            except (jwt.InvalidTokenError, KeyError):
                raise HTTPException(status_code=401, detail="Invalid token")
        return _authenticate_bearer_token(bearer_token, db)

    raise HTTPException(status_code=401, detail="Not authenticated")


def current_user_id(
    request: Request,
    db: Session = Depends(get_db),
) -> str:
    """Return the authenticated user ID. Raises 401/403 on failure."""
    user_id = _decode_user_id(request, db)

    if is_dev_mode():
        return user_id

    user = db.query(UserRow).filter(UserRow.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if not user.approved:
        raise HTTPException(status_code=403, detail="Account suspended")

    return user_id


def optional_user_id(
    request: Request,
    db: Session = Depends(get_db),
) -> str | None:
    """Return the authenticated user ID, or None if not authenticated."""
    try:
        user_id = _decode_user_id(request, db)
    except HTTPException:
        return None

    if is_dev_mode():
        return user_id

    user = db.query(UserRow).filter(UserRow.id == user_id).first()
    if not user or not user.approved:
        return None

    return user_id
