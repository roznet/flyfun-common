"""Tests for OAuth scope enforcement in db.deps (least-privilege tokens).

Covers the #274 Phase 2 contract:
- unscoped tokens (manual/legacy) and broad scopes (mcp) keep full access
- a token scoped only to ``flights:read`` reaches only its registered endpoints
  and is 403 ``insufficient_scope`` everywhere else
"""

import os

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from flyfun_common.admin import generate_api_token, hash_token
from flyfun_common.db import deps
from flyfun_common.db.deps import current_user_id, get_db, register_scope_paths
from flyfun_common.db.models import ApiTokenRow, Base, UserRow


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(UserRow(id="u1", email="u1@example.com", display_name="U1", approved=True))
    session.commit()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def client(db_session, monkeypatch):
    # Not dev mode — exercise the real bearer-token path.
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("JWT_SECRET", "test-secret")
    deps._SCOPE_ALLOWLIST.clear()
    register_scope_paths(
        "flights:read",
        [("GET", r"/api/flights"), ("GET", r"/api/flights/[^/]+/export")],
    )

    app = FastAPI()

    @app.get("/api/flights")
    def list_flights(uid: str = Depends(current_user_id)):
        return {"uid": uid}

    @app.get("/api/flights/{flight_id}/export")
    def export_flight(flight_id: str, uid: str = Depends(current_user_id)):
        return {"uid": uid, "flight_id": flight_id}

    @app.get("/api/flights/{flight_id}")
    def get_flight(flight_id: str, uid: str = Depends(current_user_id)):
        return {"uid": uid, "flight_id": flight_id}

    @app.post("/api/flights")
    def create_flight(uid: str = Depends(current_user_id)):
        return {"uid": uid}

    @app.get("/auth/me")
    def me(uid: str = Depends(current_user_id)):
        return {"uid": uid}

    def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    return TestClient(app)


def _make_token(db_session, scope):
    plain = generate_api_token()
    db_session.add(
        ApiTokenRow(user_id="u1", token_hash=hash_token(plain), name="t", scope=scope)
    )
    db_session.commit()
    return {"Authorization": f"Bearer {plain}"}


def test_unscoped_token_has_full_access(client, db_session):
    h = _make_token(db_session, None)
    assert client.get("/api/flights", headers=h).status_code == 200
    assert client.post("/api/flights", headers=h).status_code == 200
    assert client.get("/auth/me", headers=h).status_code == 200


def test_mcp_scope_has_full_access(client, db_session):
    # mcp is not a registered (limited) scope → broad/full access.
    h = _make_token(db_session, "mcp")
    assert client.post("/api/flights", headers=h).status_code == 200
    assert client.get("/auth/me", headers=h).status_code == 200


def test_flights_read_allowed_on_flight_reads(client, db_session):
    h = _make_token(db_session, "flights:read")
    assert client.get("/api/flights", headers=h).status_code == 200
    assert client.get("/api/flights/abc/export", headers=h).status_code == 200


def test_flights_read_denied_elsewhere(client, db_session):
    h = _make_token(db_session, "flights:read")
    # mutating
    r = client.post("/api/flights", headers=h)
    assert r.status_code == 403
    assert r.json()["detail"] == "insufficient_scope"
    # flight detail (deliberately not in the allowlist)
    assert client.get("/api/flights/abc", headers=h).status_code == 403
    # unrelated endpoint
    assert client.get("/auth/me", headers=h).status_code == 403
