"""Tests for encrypted credential helpers."""

import os

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from flyfun_common.credentials import (
    clear_encrypted_creds,
    load_encrypted_creds,
    save_encrypted_creds,
)
from flyfun_common.db.models import Base, UserPreferencesRow, UserRow


@pytest.fixture(autouse=True)
def _dev_env(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("CREDENTIAL_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("JWT_SECRET", raising=False)


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
    session.add(UserRow(id="u1", approved=True))
    session.flush()
    yield session
    session.close()
    engine.dispose()


def test_save_and_load(db):
    creds = {"username": "foo", "password": "bar"}
    save_encrypted_creds(db, "u1", creds)

    loaded = load_encrypted_creds(db, "u1")
    assert loaded == creds


def test_save_creates_prefs_row(db):
    # No prefs row exists yet
    assert db.get(UserPreferencesRow, "u1") is None

    save_encrypted_creds(db, "u1", {"key": "value"})
    row = db.get(UserPreferencesRow, "u1")
    assert row is not None
    assert row.encrypted_creds_json != ""


def test_load_nonexistent(db):
    assert load_encrypted_creds(db, "u1") is None


def test_clear(db):
    save_encrypted_creds(db, "u1", {"key": "val"})
    clear_encrypted_creds(db, "u1")
    assert load_encrypted_creds(db, "u1") is None
