"""Tests for admin helper utilities."""

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from flyfun_common.admin import (
    approve_user,
    create_agent_user,
    generate_api_token,
    hash_token,
    verify_approval_hmac,
)
from flyfun_common.db.models import ApiTokenRow, Base, UserRow


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )

    @event.listens_for(engine, "connect")
    def _fk(conn, _):
        conn.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()
    engine.dispose()


def test_generate_token():
    token = generate_api_token()
    assert token.startswith("ff_")
    assert len(token) > 10


def test_hash_token():
    h = hash_token("ff_test123")
    assert len(h) == 64  # SHA-256 hex


def test_create_agent_user(db):
    user, token = create_agent_user(db, "Test Bot")
    assert user.provider == "api_token"
    assert user.display_name == "Test Bot"
    assert user.approved is True
    assert token.startswith("ff_")

    # Verify token is stored hashed
    row = db.query(ApiTokenRow).filter(ApiTokenRow.user_id == user.id).first()
    assert row is not None
    assert row.token_hash == hash_token(token)


def test_approve_user(db):
    db.add(UserRow(id="u1", approved=False))
    db.flush()

    user = approve_user(db, "u1")
    assert user.approved is True


def test_approve_user_not_found(db):
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        approve_user(db, "nonexistent")
    assert exc_info.value.status_code == 404


def test_verify_approval_hmac():
    import hashlib
    import hmac
    import time

    secret = "test-secret"
    user_id = "u1"
    ts = str(int(time.time()))
    sig = hmac.new(
        secret.encode(), f"approve:{user_id}:{ts}".encode(), hashlib.sha256
    ).hexdigest()

    # Should not raise
    verify_approval_hmac(user_id, ts, sig, secret, expiry=300)


def test_verify_approval_hmac_invalid_sig():
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        verify_approval_hmac("u1", "12345", "bad-sig", "secret", 300)
    assert exc_info.value.status_code == 403
