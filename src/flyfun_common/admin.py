"""Admin helper utilities: token generation, HMAC verification, user management."""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import secrets
import time
import uuid
from base64 import urlsafe_b64encode

from fastapi import HTTPException
from sqlalchemy.orm import Session

from flyfun_common.db.models import ApiTokenRow, UserPreferencesRow, UserRow

TOKEN_PREFIX = "ff_"


def generate_api_token(prefix: str = TOKEN_PREFIX) -> str:
    """Generate a random API token with the given prefix (~48 chars total)."""
    return prefix + urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")


def hash_token(token: str) -> str:
    """SHA-256 hash a plaintext token for storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def verify_approval_hmac(
    user_id: str, ts: str, sig: str, secret: str, expiry: int
) -> None:
    """Verify an HMAC-signed approval link. Raises HTTPException on failure."""
    expected = hmac_mod.new(
        secret.encode(), f"approve:{user_id}:{ts}".encode(), hashlib.sha256
    ).hexdigest()

    if not hmac_mod.compare_digest(sig, expected):
        raise HTTPException(status_code=403, detail="Invalid approval link")

    try:
        link_time = int(ts)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid timestamp")

    age = time.time() - link_time
    if age > expiry:
        raise HTTPException(status_code=410, detail="Approval link expired")
    if age < 0:
        raise HTTPException(status_code=400, detail="Invalid timestamp")


def create_agent_user(
    db: Session, name: str, prefix: str = TOKEN_PREFIX
) -> tuple[UserRow, str]:
    """Create a bot/agent user with an initial API token.

    Returns (user, plaintext_token). The plaintext token cannot be retrieved later.
    """
    user_id = f"agent-{uuid.uuid4().hex[:12]}"
    user = UserRow(
        id=user_id,
        provider="api_token",
        provider_sub=uuid.uuid4().hex,
        email="",
        display_name=name,
        approved=True,
    )
    db.add(user)
    db.flush()
    db.add(UserPreferencesRow(user_id=user_id))

    plaintext = generate_api_token(prefix)
    db.add(
        ApiTokenRow(
            user_id=user_id,
            token_hash=hash_token(plaintext),
            name=name,
        )
    )
    db.flush()
    return user, plaintext


def approve_user(db: Session, user_id: str) -> UserRow:
    """Approve a user account. Raises HTTPException if not found."""
    user = db.query(UserRow).filter(UserRow.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.approved = True
    db.flush()
    return user
