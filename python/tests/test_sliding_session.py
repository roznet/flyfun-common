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
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.testclient import TestClient
from starlette.middleware.sessions import SessionMiddleware

from flyfun_common.auth import router as auth_router
from flyfun_common.auth.config import COOKIE_NAME
from flyfun_common.auth.jwt_utils import JWT_ALGORITHM
from flyfun_common.auth.middleware import (
    SlidingSessionMiddleware,
    mark_session_authenticated,
)
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


def _renewed_token_from(response) -> str | None:
    """Pull the X-Renewed-Token header from a response, if any."""
    return response.headers.get("x-renewed-token")


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
    def echo(request: Request):
        # Stands in for a route guarded by current_user_id: mark the token's
        # user as authenticated (cookie first, like the real dependency).
        token = request.cookies.get(COOKIE_NAME)
        if not token:
            auth = request.headers.get("authorization", "")
            token = auth[7:] if auth.startswith("Bearer ") else None
        try:
            sub = pyjwt.decode(token, secret, algorithms=[JWT_ALGORITHM])["sub"]
        except Exception:
            sub = None
        if sub:
            mark_session_authenticated(request, sub)
        return {"ok": True}

    @app.get("/public")
    def public():
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
    # Garbage Bearer that can't be decoded → middleware is a no-op.
    resp = client.get("/echo", headers={"Authorization": "Bearer ff_does_not_matter"})
    assert resp.status_code == 200
    assert _session_cookie_from(resp) is None
    assert _renewed_token_from(resp) is None


def test_middleware_refreshes_bearer_near_expiry():
    secret = "test-secret-bearer-near"
    app = _app_with_middleware(secret)
    client = TestClient(app)
    token = _forge_token(secret, exp_in=timedelta(days=5))  # < 15-day threshold
    resp = client.get("/echo", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    new_token = _renewed_token_from(resp)
    assert new_token is not None
    assert new_token != token
    old_payload = pyjwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
    new_payload = pyjwt.decode(new_token, secret, algorithms=[JWT_ALGORITHM])
    assert new_payload["sub"] == old_payload["sub"]
    assert new_payload["exp"] > old_payload["exp"]
    # Bearer flow must not also emit a session cookie.
    assert _session_cookie_from(resp) is None


def test_middleware_skips_fresh_bearer():
    secret = "test-secret-bearer-fresh"
    app = _app_with_middleware(secret)
    client = TestClient(app)
    token = _forge_token(secret, exp_in=timedelta(days=25))  # > 15-day threshold
    resp = client.get("/echo", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert _renewed_token_from(resp) is None


def test_middleware_ignores_expired_bearer():
    secret = "test-secret-bearer-expired"
    app = _app_with_middleware(secret)
    client = TestClient(app)
    token = _forge_token(secret, exp_in=timedelta(seconds=-60))
    resp = client.get("/echo", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert _renewed_token_from(resp) is None


def test_middleware_cookie_takes_precedence_over_bearer():
    """If a request carries both, the cookie path wins (browser flow owns cookies)."""
    secret = "test-secret-both"
    app = _app_with_middleware(secret)
    client = TestClient(app)
    cookie_token = _forge_token(secret, exp_in=timedelta(days=5), sub="cookie-user")
    bearer_token = _forge_token(secret, exp_in=timedelta(days=5), sub="bearer-user")
    client.cookies.set(COOKIE_NAME, cookie_token)
    resp = client.get("/echo", headers={"Authorization": f"Bearer {bearer_token}"})
    assert resp.status_code == 200
    assert _session_cookie_from(resp) is not None
    assert _renewed_token_from(resp) is None


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


def test_callback_ios_with_state_emits_code(callback_app):
    """Native sign-in (scheme + `state`) → auth-code flow: custom scheme with a
    code+state, never a token, and it ignores `next`."""
    app, _ = callback_app
    client = TestClient(app)
    client.get(
        "/auth/login/google",
        params={
            "platform": "ios",
            "scheme": "flyfunforms",
            "state": "teststate123",
            "next": "/path",
        },
        follow_redirects=False,
    )
    r2 = client.get("/auth/callback/google", follow_redirects=False)
    assert r2.status_code == 302
    loc = r2.headers["location"]
    assert loc.startswith("flyfunforms://auth/callback?code=")
    assert "state=teststate123" in loc
    assert "token=" not in loc  # the session JWT never travels in a URL


@pytest.mark.parametrize(
    "params",
    [
        {"platform": "ios", "scheme": "flyfunforms"},  # no state (legacy client)
        {"platform": "ios", "state": "teststate123"},  # no scheme
        {"platform": "ios"},
    ],
)
def test_login_native_without_scheme_and_state_rejected(callback_app, params):
    """The legacy branch that returned the session JWT in the custom-scheme
    URL is gone: a native sign-in must name its scheme and send a state."""
    app, _ = callback_app
    client = TestClient(app)
    r1 = client.get("/auth/login/google", params=params, follow_redirects=False)
    assert r1.status_code == 400


def test_callback_native_without_session_values_rejected(callback_app):
    """If the session lost scheme/state between login and callback, the
    callback refuses rather than falling back to a default scheme."""
    from starlette.requests import Request

    app, _ = callback_app

    @app.get("/test/mark-native")
    def mark_native(request: Request):
        request.session["oauth_platform"] = "ios"
        return {}

    client = TestClient(app)
    client.get("/test/mark-native")
    r2 = client.get("/auth/callback/google", follow_redirects=False)
    assert r2.status_code == 400
    assert "token=" not in r2.headers.get("location", "")


def test_callback_no_next_redirects_home(callback_app):
    app, _ = callback_app
    client = TestClient(app)
    client.get("/auth/login/google", follow_redirects=False)
    r2 = client.get("/auth/callback/google", follow_redirects=False)
    assert r2.status_code == 302
    assert r2.headers["location"] == "/"


# ---------- Session-epoch revocation (tokens_valid_after) ----------

@pytest.fixture
def epoch_app(tmp_path, monkeypatch):
    """Production-mode app with one approved user and a current_user_id-gated
    endpoint, for exercising the session-epoch revocation check."""
    from fastapi import Depends

    from flyfun_common.db.deps import current_user_id
    from flyfun_common.db.engine import (
        get_engine, init_shared_db, reset_engine, SessionLocal,
    )
    from flyfun_common.db.models import UserRow

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("JWT_SECRET", "epoch-secret")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/epoch.db")
    reset_engine()
    get_engine()
    init_shared_db()

    s = SessionLocal()
    try:
        s.add(UserRow(
            id="u1", provider="email", provider_sub="u@e.com",
            email="u@e.com", display_name="U", approved=True,
        ))
        s.commit()
    finally:
        s.close()

    app = FastAPI()

    @app.get("/protected")
    def protected(user_id: str = Depends(current_user_id)):
        return {"user_id": user_id}

    yield app
    reset_engine()


def _set_epoch(offset: timedelta) -> None:
    from flyfun_common.db.engine import SessionLocal
    from flyfun_common.db.models import UserRow

    s = SessionLocal()
    try:
        s.get(UserRow, "u1").tokens_valid_after = (
            datetime.now(timezone.utc) + offset
        )
        s.commit()
    finally:
        s.close()


def test_session_epoch_revokes_pre_epoch_token(epoch_app):
    client = TestClient(epoch_app)
    token = _forge_token("epoch-secret", exp_in=timedelta(days=20), sub="u1")
    client.cookies.set(COOKIE_NAME, token)
    assert client.get("/protected").status_code == 200

    # "Log out everywhere": epoch moves ahead of the token's iat.
    _set_epoch(timedelta(seconds=5))
    assert client.get("/protected").status_code == 401


def test_session_epoch_allows_post_epoch_token(epoch_app):
    # Epoch set in the past; a token issued now is after it → still valid.
    _set_epoch(timedelta(hours=-1))
    client = TestClient(epoch_app)
    token = _forge_token("epoch-secret", exp_in=timedelta(days=20), sub="u1")
    client.cookies.set(COOKIE_NAME, token)
    assert client.get("/protected").status_code == 200


def test_middleware_does_not_refresh_on_rejected_response():
    """A near-expiry token on a 401 response must NOT be rolled forward —
    otherwise revocation could be defeated by the refresh in its window."""
    from fastapi import HTTPException

    secret = "test-secret-reject"
    app = _app_with_middleware(secret)

    @app.get("/needs-auth")
    def needs_auth():
        raise HTTPException(status_code=401, detail="nope")

    client = TestClient(app)
    token = _forge_token(secret, exp_in=timedelta(days=5))  # in refresh window
    client.cookies.set(COOKIE_NAME, token)
    resp = client.get("/needs-auth")
    assert resp.status_code == 401
    assert _session_cookie_from(resp) is None


def test_logout_all_bumps_epoch(tmp_path, monkeypatch):
    from flyfun_common.auth.router import create_auth_router
    from flyfun_common.db.engine import (
        ensure_dev_user, get_engine, init_shared_db, reset_engine, SessionLocal,
    )
    from flyfun_common.db.models import UserRow
    from starlette.middleware.sessions import SessionMiddleware

    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    reset_engine()
    get_engine()
    init_shared_db()
    s = SessionLocal()
    try:
        ensure_dev_user(s)
    finally:
        s.close()

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test")
    app.include_router(create_auth_router())
    client = TestClient(app)

    resp = client.post("/auth/logout-all", follow_redirects=False)
    assert resp.status_code == 302
    assert "flyfun_auth" in resp.headers.get("set-cookie", "")

    s = SessionLocal()
    try:
        assert s.get(UserRow, "dev-user-001").tokens_valid_after is not None
    finally:
        s.close()
        reset_engine()


# ---------- renewal only for requests that authenticated (N6) ----------


@pytest.mark.parametrize("transport", ["cookie", "bearer"])
def test_middleware_does_not_renew_on_unauthenticated_route(transport):
    """Decoding a near-expiry token is not enough: a route that never checked
    it (and so never checked revocation) must not renew it."""
    secret = "test-secret-public"
    client = TestClient(_app_with_middleware(secret))
    token = _forge_token(secret, exp_in=timedelta(days=5))
    headers = {}
    if transport == "cookie":
        client.cookies.set(COOKIE_NAME, token)
    else:
        headers["Authorization"] = f"Bearer {token}"
    resp = client.get("/public", headers=headers)
    assert resp.status_code == 200
    assert _session_cookie_from(resp) is None
    assert _renewed_token_from(resp) is None


def test_middleware_does_not_renew_when_other_user_authenticated():
    secret = "test-secret-other"
    app = _app_with_middleware(secret)

    @app.get("/marks-someone-else")
    def marks_someone_else(request: Request):
        mark_session_authenticated(request, "someone-else")
        return {"ok": True}

    client = TestClient(app)
    client.cookies.set(COOKIE_NAME, _forge_token(secret, exp_in=timedelta(days=5)))
    assert _session_cookie_from(client.get("/marks-someone-else")) is None


def _epoch_app_with_routes(epoch_app):
    from fastapi import Depends

    from flyfun_common.db.deps import optional_user_id

    epoch_app.add_middleware(SlidingSessionMiddleware)

    @epoch_app.get("/health")
    def health():
        return {"ok": True}

    @epoch_app.get("/maybe")
    def maybe(user_id: str | None = Depends(optional_user_id)):
        return {"user_id": user_id}

    return TestClient(epoch_app)


def test_revoked_token_not_renewed_anywhere(epoch_app):
    """After "log out everywhere", a stolen token in its refresh window gets no
    successor from a public route, an optional-auth route or a protected one."""
    client = _epoch_app_with_routes(epoch_app)
    token = _forge_token("epoch-secret", exp_in=timedelta(days=5), sub="u1")
    _set_epoch(timedelta(seconds=5))
    for path in ["/health", "/maybe", "/protected"]:
        resp = client.get(path, headers={"Authorization": f"Bearer {token}"})
        assert _renewed_token_from(resp) is None, path
    assert client.get("/maybe", headers={"Authorization": f"Bearer {token}"}).json() == {
        "user_id": None
    }


def test_suspended_user_not_renewed(epoch_app):
    from flyfun_common.db.engine import SessionLocal
    from flyfun_common.db.models import UserRow

    client = _epoch_app_with_routes(epoch_app)
    s = SessionLocal()
    try:
        s.get(UserRow, "u1").approved = False
        s.commit()
    finally:
        s.close()
    token = _forge_token("epoch-secret", exp_in=timedelta(days=5), sub="u1")
    resp = client.get("/maybe", headers={"Authorization": f"Bearer {token}"})
    assert _renewed_token_from(resp) is None


@pytest.mark.parametrize("path", ["/protected", "/maybe"])
def test_valid_token_renewed_on_authenticated_routes(epoch_app, path):
    client = _epoch_app_with_routes(epoch_app)
    token = _forge_token("epoch-secret", exp_in=timedelta(days=5), sub="u1")
    resp = client.get(path, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    renewed = _renewed_token_from(resp)
    assert renewed and renewed != token
    # And the successor works.
    assert client.get("/protected", headers={"Authorization": f"Bearer {renewed}"}).status_code == 200


def test_valid_token_not_renewed_on_public_route(epoch_app):
    client = _epoch_app_with_routes(epoch_app)
    token = _forge_token("epoch-secret", exp_in=timedelta(days=5), sub="u1")
    resp = client.get("/health", headers={"Authorization": f"Bearer {token}"})
    assert _renewed_token_from(resp) is None


def test_native_pkce_end_to_end(callback_app):
    """login(code_challenge) -> callback code -> exchange needs the verifier."""
    import hashlib
    import secrets
    from base64 import urlsafe_b64encode
    from urllib.parse import parse_qs, urlparse

    app, _ = callback_app
    client = TestClient(app)
    verifier = secrets.token_urlsafe(48)
    challenge = (
        urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    client.get(
        "/auth/login/google",
        params={
            "platform": "ios",
            "scheme": "flyfunforms",
            "state": "teststate123",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    loc = client.get("/auth/callback/google", follow_redirects=False).headers["location"]
    q = parse_qs(urlparse(loc).query)
    code, state = q["code"][0], q["state"][0]

    # What an intercepting app holds: code + state, no verifier.
    assert client.post("/auth/exchange", json={"code": code, "state": state}).status_code == 400
    ok = client.post(
        "/auth/exchange", json={"code": code, "state": state, "code_verifier": verifier}
    )
    assert ok.status_code == 200 and ok.json()["token"]


def test_stale_challenge_not_applied_to_next_signin(callback_app):
    """A challenge from an abandoned sign-in must not bind the next one."""
    from urllib.parse import parse_qs, urlparse

    app, _ = callback_app
    client = TestClient(app)
    base = {"platform": "ios", "scheme": "flyfunforms", "state": "teststate123"}
    client.get(
        "/auth/login/google",
        params={**base, "code_challenge": "A" * 43, "code_challenge_method": "S256"},
        follow_redirects=False,
    )
    # Abandoned; a new sign-in from a client without PKCE.
    client.get("/auth/login/google", params=base, follow_redirects=False)
    loc = client.get("/auth/callback/google", follow_redirects=False).headers["location"]
    q = parse_qs(urlparse(loc).query)
    resp = client.post("/auth/exchange", json={"code": q["code"][0], "state": q["state"][0]})
    assert resp.status_code == 200
