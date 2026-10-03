"""Tests for the native auth-code deep-link flow (H8 hardening).

Covers the exchange-code helpers and the POST /auth/exchange endpoint:
single-use signed code, state binding (login-CSRF defense), expiry, forged
codes, and the exact-scheme allowlist on /auth/login.
"""

import os

import jwt as pyjwt
import pytest


def _fresh_app(tmp_path):
    """Build an app + seeded dev user + TestClient, mirroring test_auth."""
    os.environ["ENVIRONMENT"] = "development"
    os.environ["DATA_DIR"] = str(tmp_path)

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from starlette.middleware.sessions import SessionMiddleware

    from flyfun_common.auth.router import create_auth_router
    from flyfun_common.db.engine import (
        SessionLocal,
        ensure_dev_user,
        get_engine,
        init_shared_db,
        reset_engine,
    )

    reset_engine()
    get_engine()
    init_shared_db()

    session = SessionLocal()
    ensure_dev_user(session)
    session.commit()

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test")
    app.include_router(create_auth_router())
    return app, TestClient(app), session


# --- exchange-code helpers ---------------------------------------------------


def test_exchange_code_roundtrip():
    from flyfun_common.auth.jwt_utils import (
        create_exchange_code,
        decode_exchange_code,
    )

    code = create_exchange_code("user-1", "state-abc", "secret")
    claims = decode_exchange_code(code, "secret")
    assert claims["uid"] == "user-1"
    assert claims["state"] == "state-abc"
    assert claims["purpose"] == "oauth_exchange"


def test_decode_exchange_code_rejects_session_token():
    """A normal session JWT must not be accepted as an exchange code."""
    from flyfun_common.auth.jwt_utils import create_token, decode_exchange_code

    token = create_token("user-1", "a@b.com", "A", "secret")
    with pytest.raises(pyjwt.InvalidTokenError):
        decode_exchange_code(token, "secret")


def test_decode_exchange_code_rejects_expired():
    from flyfun_common.auth.jwt_utils import (
        create_exchange_code,
        decode_exchange_code,
    )

    code = create_exchange_code("user-1", "s", "secret", ttl_seconds=-1)
    with pytest.raises(pyjwt.ExpiredSignatureError):
        decode_exchange_code(code, "secret")


# --- POST /auth/exchange -----------------------------------------------------


def test_exchange_happy_path(tmp_path):
    from flyfun_common.auth.config import get_jwt_secret
    from flyfun_common.auth.jwt_utils import create_exchange_code, decode_token

    app, client, session = _fresh_app(tmp_path)
    try:
        code = create_exchange_code("dev-user-001", "state-1", get_jwt_secret())
        resp = client.post("/auth/exchange", json={"code": code, "state": "state-1"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["user_id"] == "dev-user-001"
        # The returned token is a valid session JWT for the user.
        claims = decode_token(body["token"], get_jwt_secret())
        assert claims["sub"] == "dev-user-001"
    finally:
        session.close()
        from flyfun_common.db.engine import reset_engine

        reset_engine()


def test_exchange_state_mismatch_rejected(tmp_path):
    """The login-CSRF regression test: wrong state must not authenticate."""
    from flyfun_common.auth.config import get_jwt_secret
    from flyfun_common.auth.jwt_utils import create_exchange_code

    app, client, session = _fresh_app(tmp_path)
    try:
        code = create_exchange_code("dev-user-001", "real-state", get_jwt_secret())
        resp = client.post(
            "/auth/exchange", json={"code": code, "state": "attacker-state"}
        )
        assert resp.status_code == 400
    finally:
        session.close()
        from flyfun_common.db.engine import reset_engine

        reset_engine()


def test_exchange_forged_code_rejected(tmp_path):
    """A code signed with the wrong secret must 400 (never authenticate)."""
    from flyfun_common.auth.jwt_utils import create_exchange_code

    app, client, session = _fresh_app(tmp_path)
    try:
        forged = create_exchange_code("dev-user-001", "s", "not-the-server-secret")
        resp = client.post("/auth/exchange", json={"code": forged, "state": "s"})
        assert resp.status_code == 400
    finally:
        session.close()
        from flyfun_common.db.engine import reset_engine

        reset_engine()


def test_exchange_expired_code_rejected(tmp_path):
    from flyfun_common.auth.config import get_jwt_secret
    from flyfun_common.auth.jwt_utils import create_exchange_code

    app, client, session = _fresh_app(tmp_path)
    try:
        code = create_exchange_code(
            "dev-user-001", "s", get_jwt_secret(), ttl_seconds=-1
        )
        resp = client.post("/auth/exchange", json={"code": code, "state": "s"})
        assert resp.status_code == 400
    finally:
        session.close()
        from flyfun_common.db.engine import reset_engine

        reset_engine()


# --- scheme allowlist --------------------------------------------------------


def test_scheme_allowlist(monkeypatch):
    from flyfun_common.auth.config import get_allowed_callback_schemes

    monkeypatch.delenv("OAUTH_ALLOWED_SCHEMES", raising=False)
    schemes = get_allowed_callback_schemes()
    assert "flyfunweather" in schemes
    assert "flyfunmalicious" not in schemes

    monkeypatch.setenv("OAUTH_ALLOWED_SCHEMES", "flyfunweather, flyfunnew")
    schemes = get_allowed_callback_schemes()
    assert schemes == frozenset({"flyfunweather", "flyfunnew"})


def test_login_rejects_unknown_scheme(tmp_path):
    """/auth/login with a non-allowlisted scheme is a 400 before any redirect."""
    app, client, session = _fresh_app(tmp_path)
    try:
        # Disable redirect-following so a would-be 302 is visible as != 400.
        resp = client.get(
            "/auth/login/google",
            params={"platform": "ios", "scheme": "evilapp"},
            follow_redirects=False,
        )
        assert resp.status_code == 400
    finally:
        session.close()
        from flyfun_common.db.engine import reset_engine

        reset_engine()


# --- PKCE (RFC 7636) on the native flow ---------------------------------------


def _pkce_pair():
    import hashlib
    import secrets
    from base64 import urlsafe_b64encode

    verifier = secrets.token_urlsafe(48)
    challenge = (
        urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


@pytest.mark.parametrize(
    "verifier_kind, expected",
    [("right", 200), ("wrong", 400), ("missing", 400)],
)
def test_exchange_requires_verifier_when_code_has_challenge(tmp_path, verifier_kind, expected):
    """A code bound to a challenge can only be redeemed with its verifier, so
    an app that intercepts the callback (code + state) gets nothing."""
    from flyfun_common.auth.config import get_jwt_secret
    from flyfun_common.auth.jwt_utils import create_exchange_code

    app, client, session = _fresh_app(tmp_path)
    try:
        verifier, challenge = _pkce_pair()
        code = create_exchange_code(
            "dev-user-001", "state-1", get_jwt_secret(), code_challenge=challenge
        )
        body = {"code": code, "state": "state-1"}
        if verifier_kind == "right":
            body["code_verifier"] = verifier
        elif verifier_kind == "wrong":
            body["code_verifier"] = _pkce_pair()[0]
        resp = client.post("/auth/exchange", json=body)
        assert resp.status_code == expected
        if expected != 200:
            assert "token" not in resp.json()
    finally:
        session.close()
        from flyfun_common.db.engine import reset_engine

        reset_engine()


def test_exchange_without_challenge_ignores_verifier(tmp_path):
    """Clients that never sent a challenge keep working unchanged."""
    from flyfun_common.auth.config import get_jwt_secret
    from flyfun_common.auth.jwt_utils import create_exchange_code

    app, client, session = _fresh_app(tmp_path)
    try:
        code = create_exchange_code("dev-user-001", "state-1", get_jwt_secret())
        resp = client.post(
            "/auth/exchange",
            json={"code": code, "state": "state-1", "code_verifier": _pkce_pair()[0]},
        )
        assert resp.status_code == 200
    finally:
        session.close()
        from flyfun_common.db.engine import reset_engine

        reset_engine()


@pytest.mark.parametrize(
    "params",
    [
        {"code_challenge": "x" * 43},  # method missing (RFC default "plain")
        {"code_challenge": "x" * 43, "code_challenge_method": "plain"},
        {"code_challenge": "too-short", "code_challenge_method": "S256"},
        {"code_challenge": "x" * 42 + "!", "code_challenge_method": "S256"},
    ],
)
def test_login_rejects_bad_code_challenge(tmp_path, params):
    app, client, session = _fresh_app(tmp_path)
    try:
        resp = client.get(
            "/auth/login/google",
            params={"platform": "ios", "scheme": "flyfunforms", "state": "state-123", **params},
            follow_redirects=False,
        )
        assert resp.status_code == 400
    finally:
        session.close()
        from flyfun_common.db.engine import reset_engine

        reset_engine()
