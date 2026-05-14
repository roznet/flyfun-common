"""Tests for the magic-link auth path."""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.sessions import SessionMiddleware


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@pytest.fixture
def dev_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.delenv("JWT_SECRET", raising=False)
    # Bust import-time caches between tests.
    from flyfun_common.db.engine import reset_engine, get_engine, init_shared_db

    reset_engine()
    get_engine()
    init_shared_db()
    yield
    reset_engine()


@pytest.fixture
def prod_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("JWT_SECRET", "test-prod-secret")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/prod.db")
    from flyfun_common.db.engine import reset_engine, get_engine, init_shared_db

    reset_engine()
    get_engine()
    init_shared_db()
    yield
    reset_engine()


def _build_app(*, send_callback=None, on_new_user=None):
    from flyfun_common.auth.router import create_auth_router

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test")
    app.include_router(
        create_auth_router(
            on_new_user=on_new_user,
            send_magic_link_email=send_callback,
        )
    )
    return app


# --- /auth/providers ---------------------------------------------------------


def test_email_provider_listed_only_when_callback_wired(dev_env):
    app = _build_app(send_callback=lambda *a, **k: None)
    client = TestClient(app)
    resp = client.get("/auth/providers")
    assert resp.status_code == 200
    assert "email" in resp.json()["providers"]


def test_email_provider_omitted_without_callback(dev_env):
    app = _build_app(send_callback=None)
    client = TestClient(app)
    resp = client.get("/auth/providers")
    assert "email" not in resp.json()["providers"]


# --- /auth/magic-link/request -----------------------------------------------


def test_request_returns_200_and_invokes_callback(dev_env):
    captured = {}

    def cb(email, link, code, ip):
        captured["email"] = email
        captured["link"] = link
        captured["code"] = code
        captured["ip"] = ip

    app = _build_app(send_callback=cb)
    client = TestClient(app)
    resp = client.post(
        "/auth/magic-link/request",
        json={"email": "ALICE@example.com"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert captured["email"] == "alice@example.com"  # normalized
    assert captured["code"].isdigit() and len(captured["code"]) == 6
    assert "/auth/verify?token=" in captured["link"]


def test_request_apple_private_relay_rejected(dev_env):
    app = _build_app(send_callback=lambda *a, **k: None)
    client = TestClient(app)
    resp = client.post(
        "/auth/magic-link/request",
        json={"email": "user@privaterelay.appleid.com"},
    )
    assert resp.status_code == 400
    assert "Sign in with Apple" in resp.json()["detail"]


def test_request_503_when_no_callback(dev_env):
    # Endpoint is only mounted when callback is wired, so the 503 path
    # is exercised by mounting with a callback and then forcing it None
    # via a temporary build_magic_link_router instance.
    from flyfun_common.auth.magic_link import build_magic_link_router

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test")
    app.include_router(
        build_magic_link_router(send_magic_link_email=None, on_new_user=None),
        prefix="/auth",
    )
    client = TestClient(app)
    resp = client.post("/auth/magic-link/request", json={"email": "x@y.com"})
    assert resp.status_code == 503


def test_next_propagates_into_verify_link(dev_env):
    captured = {}
    app = _build_app(
        send_callback=lambda email, link, code, ip: captured.update(link=link)
    )
    client = TestClient(app)
    resp = client.post(
        "/auth/magic-link/request",
        json={"email": "a@b.com", "next": "/flight.html?id=abc"},
    )
    assert resp.status_code == 200
    assert "next=" in captured["link"]


def test_next_unsafe_path_dropped(dev_env):
    captured = {}
    app = _build_app(
        send_callback=lambda email, link, code, ip: captured.update(link=link)
    )
    client = TestClient(app)
    resp = client.post(
        "/auth/magic-link/request",
        json={"email": "a@b.com", "next": "//evil.example/x"},
    )
    assert resp.status_code == 200
    assert "next=" not in captured["link"]


# --- GET /auth/verify --------------------------------------------------------


def test_verify_does_not_consume_token(dev_env):
    """Corp scanners pre-click links. Burning the token on GET would
    silently break legitimate users."""
    from flyfun_common.db.engine import SessionLocal
    from flyfun_common.db.models import MagicLinkTokenRow

    captured = {}
    app = _build_app(send_callback=lambda *a, **k: captured.update(args=a))
    client = TestClient(app)
    client.post("/auth/magic-link/request", json={"email": "a@b.com"})

    # Pull the raw token from the link our callback recorded.
    link = captured["args"][1]
    raw_token = link.split("token=", 1)[1].split("&", 1)[0]

    resp = client.get(
        f"/auth/verify?token={raw_token}", follow_redirects=False
    )
    assert resp.status_code == 302
    assert "/auth-verify.html" in resp.headers["location"]
    assert f"token={raw_token}" in resp.headers["location"]

    session = SessionLocal()
    try:
        row = (
            session.query(MagicLinkTokenRow)
            .filter_by(token_hash=_sha256(raw_token))
            .one()
        )
        assert row.used_at is None
    finally:
        session.close()


def test_verify_preserves_safe_next(dev_env):
    app = _build_app(send_callback=lambda *a, **k: None)
    client = TestClient(app)
    resp = client.get(
        "/auth/verify?token=abc&next=/foo", follow_redirects=False
    )
    assert resp.status_code == 302
    assert "next=%2Ffoo" in resp.headers["location"]


def test_verify_drops_unsafe_next(dev_env):
    app = _build_app(send_callback=lambda *a, **k: None)
    client = TestClient(app)
    resp = client.get(
        "/auth/verify?token=abc&next=//evil", follow_redirects=False
    )
    assert "next=" not in resp.headers["location"]


# --- /auth/magic-link/consume (web) ------------------------------------------


def _seed_token(email: str, *, ttl_min: int = 15, used: bool = False) -> str:
    """Insert a fresh token row directly and return the raw token."""
    from flyfun_common.db.engine import SessionLocal
    from flyfun_common.db.models import MagicLinkTokenRow

    raw_token = uuid.uuid4().hex  # any opaque string works
    raw_code = "123456"
    now = datetime.now(timezone.utc)
    session = SessionLocal()
    try:
        session.add(
            MagicLinkTokenRow(
                id=str(uuid.uuid4()),
                email=email,
                token_hash=_sha256(raw_token),
                otp_code_hash=_sha256(raw_code),
                created_at=now,
                expires_at=now + timedelta(minutes=ttl_min),
                used_at=now if used else None,
            )
        )
        session.commit()
    finally:
        session.close()
    return raw_token


def test_consume_brand_new_email_creates_user(dev_env):
    app = _build_app(send_callback=lambda *a, **k: None)
    client = TestClient(app)
    raw = _seed_token("new@example.com")

    resp = client.post(
        "/auth/magic-link/consume",
        json={"token": raw},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/"
    assert "flyfun_auth=" in resp.headers.get("set-cookie", "")

    from flyfun_common.db.engine import SessionLocal
    from flyfun_common.db.models import UserRow

    session = SessionLocal()
    try:
        user = (
            session.query(UserRow).filter_by(email="new@example.com").one()
        )
        assert user.provider == "email"
        assert user.approved is True
    finally:
        session.close()


def test_consume_existing_google_user_keeps_google_provider(dev_env):
    """Existing Google user verifying via magic-link should keep
    provider='google' — only the lookup path differs."""
    from flyfun_common.db.engine import SessionLocal
    from flyfun_common.db.models import UserRow

    session = SessionLocal()
    try:
        session.add(
            UserRow(
                id="u1",
                provider="google",
                provider_sub="google-123",
                email="g@example.com",
                display_name="G User",
                approved=True,
            )
        )
        session.commit()
    finally:
        session.close()

    app = _build_app(send_callback=lambda *a, **k: None)
    client = TestClient(app)
    raw = _seed_token("g@example.com")
    resp = client.post(
        "/auth/magic-link/consume",
        json={"token": raw},
        follow_redirects=False,
    )
    assert resp.status_code == 302

    session = SessionLocal()
    try:
        user = session.get(UserRow, "u1")
        assert user.provider == "google"
    finally:
        session.close()


def test_consume_existing_apple_user_keeps_apple_provider(dev_env):
    from flyfun_common.db.engine import SessionLocal
    from flyfun_common.db.models import UserRow

    session = SessionLocal()
    try:
        session.add(
            UserRow(
                id="u2",
                provider="apple",
                provider_sub="apple-xyz",
                email="ap@example.com",
                display_name="Apple User",
                approved=True,
            )
        )
        session.commit()
    finally:
        session.close()

    app = _build_app(send_callback=lambda *a, **k: None)
    client = TestClient(app)
    raw = _seed_token("ap@example.com")
    resp = client.post(
        "/auth/magic-link/consume", json={"token": raw}, follow_redirects=False
    )
    assert resp.status_code == 302

    session = SessionLocal()
    try:
        assert session.get(UserRow, "u2").provider == "apple"
    finally:
        session.close()


def test_consume_expired_token_400(dev_env):
    app = _build_app(send_callback=lambda *a, **k: None)
    client = TestClient(app)
    raw = _seed_token("x@y.com", ttl_min=-1)  # already expired
    resp = client.post("/auth/magic-link/consume", json={"token": raw})
    assert resp.status_code == 400


def test_consume_already_used_token_400(dev_env):
    app = _build_app(send_callback=lambda *a, **k: None)
    client = TestClient(app)
    raw = _seed_token("x@y.com", used=True)
    resp = client.post("/auth/magic-link/consume", json={"token": raw})
    assert resp.status_code == 400


def test_consume_unapproved_user_redirects_pending(dev_env):
    from flyfun_common.db.engine import SessionLocal
    from flyfun_common.db.models import UserRow

    session = SessionLocal()
    try:
        session.add(
            UserRow(
                id="pending-1",
                provider="email",
                provider_sub="p@p.com",
                email="p@p.com",
                display_name="p",
                approved=False,
            )
        )
        session.commit()
    finally:
        session.close()

    app = _build_app(send_callback=lambda *a, **k: None)
    client = TestClient(app)
    raw = _seed_token("p@p.com")
    resp = client.post(
        "/auth/magic-link/consume", json={"token": raw}, follow_redirects=False
    )
    assert resp.status_code == 302
    assert "status=pending" in resp.headers["location"]
    # cookie NOT set
    assert "set-cookie" not in resp.headers or "flyfun_auth=" not in resp.headers.get("set-cookie", "")


def test_consume_honors_safe_next(dev_env):
    app = _build_app(send_callback=lambda *a, **k: None)
    client = TestClient(app)
    raw = _seed_token("nx@example.com")
    resp = client.post(
        "/auth/magic-link/consume",
        json={"token": raw, "next": "/flight.html?id=abc"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/flight.html?id=abc"


# --- /auth/magic-link/consume-code (iOS) -------------------------------------


def test_consume_code_returns_jwt(dev_env):
    app = _build_app(send_callback=lambda *a, **k: None)
    client = TestClient(app)
    _seed_token("ios@example.com")  # OTP fixed at 123456 by _seed_token

    resp = client.post(
        "/auth/magic-link/consume-code",
        json={"email": "ios@example.com", "code": "123456"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token"]
    assert body["user_id"]
    # no cookie on iOS flow
    assert "flyfun_auth=" not in resp.headers.get("set-cookie", "")


def test_consume_code_wrong_code_400(dev_env):
    app = _build_app(send_callback=lambda *a, **k: None)
    client = TestClient(app)
    _seed_token("ios@example.com")
    resp = client.post(
        "/auth/magic-link/consume-code",
        json={"email": "ios@example.com", "code": "000000"},
    )
    assert resp.status_code == 400


# --- rate limiting (production-mode) -----------------------------------------


def test_rate_limit_per_email(prod_env):
    app = _build_app(send_callback=lambda *a, **k: None)
    client = TestClient(app)
    for _ in range(3):
        r = client.post("/auth/magic-link/request", json={"email": "rl@x.com"})
        assert r.status_code == 200
    r = client.post("/auth/magic-link/request", json={"email": "rl@x.com"})
    assert r.status_code == 429


def test_rate_limit_per_ip(prod_env):
    app = _build_app(send_callback=lambda *a, **k: None)
    client = TestClient(app)
    # 10 distinct emails from the same IP -> 11th hits IP limit
    for i in range(10):
        r = client.post(
            "/auth/magic-link/request", json={"email": f"a{i}@x.com"}
        )
        assert r.status_code == 200
    r = client.post("/auth/magic-link/request", json={"email": "a11@x.com"})
    assert r.status_code == 429


def test_rate_limits_skipped_in_dev_mode(dev_env):
    app = _build_app(send_callback=lambda *a, **k: None)
    client = TestClient(app)
    for _ in range(10):
        r = client.post("/auth/magic-link/request", json={"email": "x@y.com"})
        assert r.status_code == 200


# --- purge helper ------------------------------------------------------------


def test_purge_expired_magic_link_tokens(dev_env):
    from flyfun_common.auth.magic_link import purge_expired_magic_link_tokens
    from flyfun_common.db.engine import SessionLocal
    from flyfun_common.db.models import (
        MagicLinkConsumeAttemptRow,
        MagicLinkTokenRow,
    )

    now = datetime.now(timezone.utc)
    session = SessionLocal()
    try:
        # Old expired row -> should be purged
        session.add(
            MagicLinkTokenRow(
                id="old",
                email="o@x.com",
                token_hash="h1",
                created_at=now - timedelta(hours=48),
                expires_at=now - timedelta(hours=47),
            )
        )
        # Recent expired row -> still within retention window, kept
        session.add(
            MagicLinkTokenRow(
                id="recent",
                email="r@x.com",
                token_hash="h2",
                created_at=now - timedelta(hours=1),
                expires_at=now - timedelta(minutes=30),
            )
        )
        # Old consume attempt -> purged
        session.add(
            MagicLinkConsumeAttemptRow(
                ip="1.2.3.4", attempted_at=now - timedelta(hours=48)
            )
        )
        session.commit()
        deleted = purge_expired_magic_link_tokens(session, older_than_hours=24)
        session.commit()
        assert deleted == 1
        assert session.get(MagicLinkTokenRow, "old") is None
        assert session.get(MagicLinkTokenRow, "recent") is not None
        assert session.query(MagicLinkConsumeAttemptRow).count() == 0
    finally:
        session.close()
