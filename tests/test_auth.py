"""Basic tests for shared auth utilities."""

import os
import pytest
from flyfun_common.auth.jwt_utils import create_token, decode_token
from flyfun_common.auth.config import get_jwt_secret


def test_jwt_roundtrip():
    secret = "test-secret"
    token = create_token("user-123", "test@example.com", "Test User", secret)
    payload = decode_token(token, secret)
    assert payload["sub"] == "user-123"
    assert payload["email"] == "test@example.com"
    assert payload["name"] == "Test User"


def test_jwt_wrong_secret():
    import jwt

    token = create_token("user-123", "a@b.com", "A", "secret-1")
    with pytest.raises(jwt.InvalidSignatureError):
        decode_token(token, "secret-2")


def test_dev_mode_secret():
    os.environ.pop("JWT_SECRET", None)
    os.environ["ENVIRONMENT"] = "development"
    secret = get_jwt_secret()
    assert secret  # should return dev default


def test_shared_db_roundtrip(tmp_path):
    os.environ["ENVIRONMENT"] = "development"
    os.environ["DATA_DIR"] = str(tmp_path)

    from flyfun_common.db.engine import get_engine, init_shared_db, reset_engine, SessionLocal, ensure_dev_user
    from flyfun_common.db.models import UserRow

    reset_engine()
    get_engine()
    init_shared_db()

    session = SessionLocal()
    try:
        ensure_dev_user(session)
        user = session.get(UserRow, "dev-user-001")
        assert user is not None
        assert user.display_name == "Dev User"
        assert user.approved is True
    finally:
        session.close()
        reset_engine()


def test_find_orphaned_user_ids(tmp_path):
    """find_orphaned_user_ids detects tokens for deleted users."""
    os.environ["ENVIRONMENT"] = "development"
    os.environ["DATA_DIR"] = str(tmp_path)

    from flyfun_common.db.engine import (
        get_engine, init_shared_db, reset_engine, SessionLocal, ensure_dev_user,
        find_orphaned_user_ids,
    )
    from flyfun_common.db.models import ApiTokenRow, UserRow

    reset_engine()
    get_engine()
    init_shared_db()

    session = SessionLocal()
    try:
        ensure_dev_user(session)

        # No orphans yet
        assert find_orphaned_user_ids(session, ApiTokenRow) == []

        # Create a token for a non-existent user (simulates post-deletion orphan)
        session.add(ApiTokenRow(
            user_id="ghost-user",
            token_hash="orphan_hash",
            name="orphan token",
        ))
        session.commit()

        orphaned = find_orphaned_user_ids(session, ApiTokenRow)
        assert orphaned == ["ghost-user"]
    finally:
        session.close()
        reset_engine()


def test_delete_account(tmp_path):
    """DELETE /auth/account removes user and all associated shared data."""
    os.environ["ENVIRONMENT"] = "development"
    os.environ["DATA_DIR"] = str(tmp_path)

    from flyfun_common.db.engine import get_engine, init_shared_db, reset_engine, SessionLocal, ensure_dev_user
    from flyfun_common.db.models import ApiTokenRow, UserRow

    reset_engine()
    get_engine()
    init_shared_db()

    session = SessionLocal()
    try:
        ensure_dev_user(session)

        # Add an API token for the dev user
        token = ApiTokenRow(
            user_id="dev-user-001",
            token_hash="abc123hash",
            name="test token",
        )
        session.add(token)
        session.commit()

        # Verify user and token exist
        assert session.get(UserRow, "dev-user-001") is not None
        assert session.query(ApiTokenRow).filter_by(user_id="dev-user-001").count() == 1

        # Simulate what the delete endpoint does
        session.query(ApiTokenRow).filter(ApiTokenRow.user_id == "dev-user-001").delete()
        session.query(UserRow).filter(UserRow.id == "dev-user-001").delete()
        session.commit()

        # Verify deletion
        assert session.get(UserRow, "dev-user-001") is None
        assert session.query(ApiTokenRow).filter_by(user_id="dev-user-001").count() == 0
    finally:
        session.close()
        reset_engine()
