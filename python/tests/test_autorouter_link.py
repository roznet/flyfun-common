"""Tests for Autorouter account linking: the native-app ticket flow and where
the OAuth callback sends the pilot afterwards (app scheme, web ``next``, or
the default settings page)."""

import os
from urllib.parse import parse_qs, urlsplit

import jwt as pyjwt
import pytest


@pytest.fixture
def linking(tmp_path, monkeypatch):
    """App with the autorouter router, a seeded dev user and a fake token endpoint."""
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.delenv("CREDENTIAL_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("AUTOROUTER_CLIENT_ID", "flyfun_test")
    monkeypatch.setenv("AUTOROUTER_CLIENT_SECRET", "secret")

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from starlette.middleware.sessions import SessionMiddleware

    from flyfun_common import autorouter
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
    session.close()

    class _FakeResponse:
        status_code = 200
        text = ""

        def json(self):
            return {"access_token": "ar-token", "token_type": "bearer"}

    class _FakeAsyncClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, data=None):
            return _FakeResponse()

    monkeypatch.setattr(autorouter.httpx, "AsyncClient", _FakeAsyncClient)

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test")
    app.include_router(autorouter.create_autorouter_router())
    return TestClient(app)


def _state_from_authorize(resp) -> str:
    assert resp.status_code == 302, resp.text
    location = resp.headers["location"]
    assert location.startswith("https://www.autorouter.aero/authorize")
    return parse_qs(urlsplit(location).query)["state"][0]


def _ticket_url(client, scheme="flyfunweather") -> str:
    resp = client.post("/autorouter/link-ticket", json={"scheme": scheme})
    assert resp.status_code == 200, resp.text
    return resp.json()["url"]


# --- ticket helpers ----------------------------------------------------------


def test_link_ticket_roundtrip():
    from flyfun_common.autorouter import create_link_ticket, decode_link_ticket

    claims = decode_link_ticket(create_link_ticket("u1", "flyfunweather", "s"), "s")
    assert claims["uid"] == "u1"
    assert claims["scheme"] == "flyfunweather"


def test_session_token_is_not_a_link_ticket():
    from flyfun_common.auth.jwt_utils import create_token
    from flyfun_common.autorouter import decode_link_ticket

    with pytest.raises(pyjwt.InvalidTokenError):
        decode_link_ticket(create_token("u1", "a@b.c", "A", "s"), "s")


# --- native app flow ---------------------------------------------------------


def test_app_flow_links_and_returns_to_app_scheme(linking):
    url = _ticket_url(linking)
    assert "/autorouter/link?ticket=" in url

    state = _state_from_authorize(linking.get(url, follow_redirects=False))
    resp = linking.get(
        f"/auth/callback/autorouter?code=abc&state={state}", follow_redirects=False
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == "flyfunweather://autorouter/callback?status=linked"

    status = linking.get("/autorouter/status").json()
    assert status["linked"] is True


def test_link_ticket_rejects_unknown_scheme(linking):
    resp = linking.post("/autorouter/link-ticket", json={"scheme": "evilapp"})
    assert resp.status_code == 400


def test_declined_consent_returns_to_app_with_reason(linking):
    state = _state_from_authorize(linking.get(_ticket_url(linking), follow_redirects=False))
    resp = linking.get(
        f"/auth/callback/autorouter?error=access_denied&state={state}",
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["location"] == (
        "flyfunweather://autorouter/callback?status=error&reason=denied"
    )
    assert linking.get("/autorouter/status").json()["linked"] is False


def test_expired_ticket_returns_to_app(linking):
    from datetime import datetime, timedelta, timezone

    from flyfun_common.auth.config import get_jwt_secret
    from flyfun_common.auth.jwt_utils import JWT_ALGORITHM

    past = datetime.now(timezone.utc) - timedelta(minutes=10)
    ticket = pyjwt.encode(
        {
            "purpose": "autorouter_link",
            "uid": "dev-user-001",
            "scheme": "flyfunweather",
            "iat": past,
            "exp": past + timedelta(seconds=120),
        },
        get_jwt_secret(),
        algorithm=JWT_ALGORITHM,
    )
    resp = linking.get(f"/autorouter/link?ticket={ticket}", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == (
        "flyfunweather://autorouter/callback?status=error&reason=expired"
    )


def test_forged_ticket_is_rejected(linking):
    from flyfun_common.autorouter import create_link_ticket

    forged = create_link_ticket("dev-user-001", "flyfunweather", "not-the-secret")
    resp = linking.get(f"/autorouter/link?ticket={forged}", follow_redirects=False)
    assert resp.status_code == 401


# --- web flow ----------------------------------------------------------------


def test_web_flow_without_next_uses_success_redirect(linking):
    state = _state_from_authorize(linking.get("/autorouter/link", follow_redirects=False))
    resp = linking.get(
        f"/auth/callback/autorouter?code=abc&state={state}", follow_redirects=False
    )
    assert resp.headers["location"] == "/settings.html?autorouter=linked"


def test_web_flow_returns_to_safe_next(linking):
    resp = linking.get("/autorouter/link?next=/flights.html%3Fnew%3D1", follow_redirects=False)
    state = _state_from_authorize(resp)
    resp = linking.get(
        f"/auth/callback/autorouter?code=abc&state={state}", follow_redirects=False
    )
    assert resp.headers["location"] == "/flights.html?new=1&autorouter=linked"


@pytest.mark.parametrize("bad_next", ["https://evil.example/x", "//evil.example", "flights.html"])
def test_web_flow_drops_unsafe_next(linking, bad_next):
    state = _state_from_authorize(
        linking.get("/autorouter/link", params={"next": bad_next}, follow_redirects=False)
    )
    resp = linking.get(
        f"/auth/callback/autorouter?code=abc&state={state}", follow_redirects=False
    )
    assert resp.headers["location"] == "/settings.html?autorouter=linked"


def test_web_flow_errors_stay_http_errors(linking):
    linking.get("/autorouter/link", follow_redirects=False)
    resp = linking.get("/auth/callback/autorouter?code=abc&state=wrong", follow_redirects=False)
    assert resp.status_code == 400
