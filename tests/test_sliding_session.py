"""Tests for rolling JWT sessions and post-login redirect.

Covers:
  * SlidingSessionMiddleware — refresh threshold, expiry, bearer-token no-op.
  * _is_safe_relative_path — open-redirect validation.
  * Login + callback end-to-end with a stub OAuth client.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie

import jwt as pyjwt
import pytest
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.testclient import TestClient
from starlette.middleware.sessions import SessionMiddleware

from flyfun_common.auth import router as auth_router
from flyfun_common.auth.config import COOKIE_NAME
from flyfun_common.auth.jwt_utils import JWT_ALGORITHM
from flyfun_common.auth.middleware import SlidingSessionMiddleware
from flyfun_common.auth.router import _is_safe_relative_path, create_auth_router


# ---------- helpers ----------

def _forge_token(secret: str, *, exp_in: timedelta, sub: str = "u1") -> str:
    """Mint a JWT with a caller-chosen exp — bypasses create_token for ageing."""
    now = datetime.now(timezone.utc)
    return pyjwt.encode(
        {
            "sub": sub,
            "email": "u@example.com",
            "name": "U",
            "iat": now,
            "exp": now + exp_in,
        },
        secret,
        algorithm=JWT_ALGORITHM,
    )


def _set_session_cookie_in_response(value: str) -> RedirectResponse:
    """A response that itself sets flyfun_auth — middleware must not clobber it."""
    resp = RedirectResponse(url="/", status_code=302)
    resp.set_cookie(COOKIE_NAME, value, path="/")
    return resp


def _session_cookie_from(response) -> str | None:
    """Pull the flyfun_auth value from the response's Set-Cookie headers, if any."""
    cookies = response.headers.get_list("set-cookie")
    for raw in cookies:
        jar = SimpleCookie()
        jar.load(raw)
        if COOKIE_NAME in jar:
            return jar[COOKIE_NAME].value
    return None


# ---------- _is_safe_relative_path ----------

@pytest.mark.parametrize(
    "value",
    [
        "/",
        "/flight.html",
        "/flight.html?id=abc&pack=xyz",
        "/path/with/segments",
        "/a?x=/https://ok",  # query string may contain anything
    ],
)
def test_safe_relative_path_accepts(value):
    assert _is_safe_relative_path(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "",
        None,
        "relative/path",           # must start with /
        "//evil.com",              # protocol-relative
        "//evil.com/path",
        "/\\evil.com",             # backslash trick
        "https://evil.com",        # absolute url
        "http://evil.com",
        "javascript:alert(1)",     # scheme injection
        "mailto:x@y.z",
    ],
)
def test_safe_relative_path_rejects(value):
    assert _is_safe_relative_path(value) is False


# ---------- SlidingSessionMiddleware ----------

def _app_with_middleware(secret: str) -> FastAPI:
    os.environ["JWT_SECRET"] = secret
    os.environ["ENVIRONMENT"] = "development"
    app = FastAPI()
    app.add_middleware(SlidingSessionMiddleware)

    @app.get("/echo")
    def echo():
        return {"ok": True}

    @app.get("/logout-like")
    def logout_like():
        # Simulate a response that clears the session cookie.
        resp = RedirectResponse(url="/login.html", status_code=302)
        resp.delete_cookie(COOKIE_NAME, path="/")
        return resp

    return app


def test_middleware_skips_fresh_cookie():
    secret = "test-secret-fresh"
    app = _app_with_middleware(secret)
    client = TestClient(app)
    token = _forge_token(secret, exp_in=timedelta(days=25))  # > 15-day threshold
    client.cookies.set(COOKIE_NAME, token)
    resp = client.get("/echo")
    assert resp.status_code == 200
    assert _session_cookie_from(resp) is None


def test_middleware_refreshes_near_expiry():
    secret = "test-secret-near"
    app = _app_with_middleware(secret)
    client = TestClient(app)
    token = _forge_token(secret, exp_in=timedelta(days=5))  # < 15-day threshold
    client.cookies.set(COOKIE_NAME, token)
    resp = client.get("/echo")
    assert resp.status_code == 200
    new_cookie = _session_cookie_from(resp)
    assert new_cookie is not None
    assert new_cookie != token
    # Fresh token must decode and have a later exp than the old one.
    old_payload = pyjwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
    new_payload = pyjwt.decode(new_cookie, secret, algorithms=[JWT_ALGORITHM])
    assert new_payload["sub"] == old_payload["sub"]
    assert new_payload["exp"] > old_payload["exp"]


def test_middleware_ignores_expired_cookie():
    secret = "test-secret-expired"
    app = _app_with_middleware(secret)
    client = TestClient(app)
    token = _forge_token(secret, exp_in=timedelta(seconds=-60))
    client.cookies.set(COOKIE_NAME, token)
    resp = client.get("/echo")
    # Endpoint itself has no auth dependency → 200; middleware must not refresh.
    assert resp.status_code == 200
    assert _session_cookie_from(resp) is None


def test_middleware_no_cookie_no_refresh():
    secret = "test-secret-nocookie"
    app = _app_with_middleware(secret)
    client = TestClient(app)
    # Simulate bearer-token call: no cookie, just an Authorization header.
    resp = client.get("/echo", headers={"Authorization": "Bearer ff_does_not_matter"})
    assert resp.status_code == 200
    assert _session_cookie_from(resp) is None


def test_middleware_does_not_overwrite_response_cookie():
    """If the endpoint itself sets/clears flyfun_auth, middleware must not clobber."""
    secret = "test-secret-nooverwrite"
    app = _app_with_middleware(secret)
    client = TestClient(app)
    token = _forge_token(secret, exp_in=timedelta(days=1))  # near expiry
    client.cookies.set(COOKIE_NAME, token)
    resp = client.get("/logout-like", follow_redirects=False)
    # Only one Set-Cookie for flyfun_auth — the one from the endpoint (Max-Age=0).
    session_cookies = [
        c for c in resp.headers.get_list("set-cookie") if c.startswith(f"{COOKIE_NAME}=")
    ]
    assert len(session_cookies) == 1
    assert "Max-Age=0" in session_cookies[0] or 'max-age=0' in session_cookies[0].lower()


# ---------- Login + callback with stub OAuth client ----------

class _StubOAuthClient:
    """Minimal double for an authlib Starlette OAuth client."""

    def __init__(self, userinfo: dict) -> None:
        self._userinfo = userinfo
        self.last_redirect_uri: str | None = None

    async def authorize_redirect(self, request, redirect_uri):
        self.last_redirect_uri = str(redirect_uri)
        return RedirectResponse(url="/__fake_provider__", status_code=302)

    async def authorize_access_token(self, request):
        return {"userinfo": self._userinfo}


class _StubOAuth:
    """Registry-like stand-in for authlib's OAuth object."""

    def __init__(self, client: _StubOAuthClient) -> None:
        self.google = client


@pytest.fixture
def callback_app(tmp_path, monkeypatch):
    """App with auth router mounted and a stub OAuth client for google."""
    from flyfun_common.db.engine import (
        ensure_dev_user, get_engine, init_shared_db, reset_engine,
    )

    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("JWT_SECRET", "test-secret-callback")

    reset_engine()
    get_engine()
    init_shared_db()
    from flyfun_common.db.engine import SessionLocal
    s = SessionLocal()
    try:
        ensure_dev_user(s)
    finally:
        s.close()

    stub_client = _StubOAuthClient(
        {"sub": "google-stub-1", "email": "stub@example.com", "name": "Stub User"}
    )
    monkeypatch.setattr(auth_router, "create_oauth", lambda: _StubOAuth(stub_client))

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test-session-secret")
    app.include_router(create_auth_router())

    yield app, stub_client

    reset_engine()


def test_callback_redirects_to_next_when_safe(callback_app):
    app, _ = callback_app
    client = TestClient(app)
    # login stashes post_login_redirect, then redirects to the (stubbed) provider
    r1 = client.get(
        "/auth/login/google",
        params={"next": "/flight.html?id=abc&pack=xyz"},
        follow_redirects=False,
    )
    assert r1.status_code == 302

    # Callback reads post_login_redirect from the signed session cookie.
    r2 = client.get("/auth/callback/google", follow_redirects=False)
    assert r2.status_code == 302
    assert r2.headers["location"] == "/flight.html?id=abc&pack=xyz"
    assert _session_cookie_from(r2) is not None


def test_callback_drops_unsafe_next(callback_app):
    app, _ = callback_app
    client = TestClient(app)
    # Protocol-relative — must be dropped at stash time.
    client.get(
        "/auth/login/google",
        params={"next": "//evil.com/phish"},
        follow_redirects=False,
    )
    r2 = client.get("/auth/callback/google", follow_redirects=False)
    assert r2.status_code == 302
    assert r2.headers["location"] == "/"


def test_callback_drops_absolute_next(callback_app):
    app, _ = callback_app
    client = TestClient(app)
    client.get(
        "/auth/login/google",
        params={"next": "https://evil.com"},
        follow_redirects=False,
    )
    r2 = client.get("/auth/callback/google", follow_redirects=False)
    assert r2.status_code == 302
    assert r2.headers["location"] == "/"


def test_callback_ignores_next_for_ios(callback_app):
    app, _ = callback_app
    client = TestClient(app)
    client.get(
        "/auth/login/google",
        params={"platform": "ios", "next": "/path"},
        follow_redirects=False,
    )
    r2 = client.get("/auth/callback/google", follow_redirects=False)
    assert r2.status_code == 302
    # iOS flow goes to the custom scheme, not the next path.
    assert r2.headers["location"].startswith("flyfun://auth/callback?token=")


def test_callback_no_next_redirects_home(callback_app):
    app, _ = callback_app
    client = TestClient(app)
    client.get("/auth/login/google", follow_redirects=False)
    r2 = client.get("/auth/callback/google", follow_redirects=False)
    assert r2.status_code == 302
    assert r2.headers["location"] == "/"
