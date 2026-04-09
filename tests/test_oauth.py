"""Tests for OAuth 2.1 authorization server module."""

import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.middleware.sessions import SessionMiddleware

from flyfun_common.admin import generate_api_token, hash_token
from flyfun_common.db.deps import get_db
from flyfun_common.db.models import ApiTokenRow, Base, UserRow
from flyfun_common.oauth.models import (
    OAuthAuthorizationCodeRow,
    OAuthClientRow,
    OAuthRefreshTokenRow,
)
from flyfun_common.oauth.pkce import verify_pkce_s256
from flyfun_common.oauth.router import create_oauth_router


# --- Fixtures ---


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )

    @event.listens_for(engine, "connect")
    def _fk(conn, _):
        conn.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Create a test user
    session.add(UserRow(id="test-user-001", email="test@example.com", display_name="Test User"))
    session.commit()

    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def client(db_session):
    """FastAPI test client with OAuth router mounted, running in dev mode."""
    os.environ["ENVIRONMENT"] = "development"

    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test-session-secret")
    app.include_router(create_oauth_router(app_name="Test App"))

    def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    return TestClient(app, follow_redirects=False)


# --- PKCE Unit Tests ---

# RFC 7636 Appendix B test vector
_RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
_RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_pkce_s256_verify():
    assert verify_pkce_s256(_RFC_VERIFIER, _RFC_CHALLENGE) is True


def test_pkce_s256_reject_bad_verifier():
    assert verify_pkce_s256("wrong-verifier-that-is-long-enough-to-pass-length-check", _RFC_CHALLENGE) is False


def test_pkce_s256_reject_short_verifier():
    assert verify_pkce_s256("tooshort", _RFC_CHALLENGE) is False


# --- Client Registration Tests ---


def test_register_client(client):
    resp = client.post("/oauth/register", json={
        "client_name": "Test Client",
        "redirect_uris": ["https://example.com/callback"],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["client_id"].startswith("mcp_")
    assert "client_secret" in data
    assert data["client_name"] == "Test Client"
    assert data["redirect_uris"] == ["https://example.com/callback"]


def test_register_client_invalid_redirect_uri(client):
    resp = client.post("/oauth/register", json={
        "client_name": "Bad Client",
        "redirect_uris": ["http://evil.com/callback"],
    })
    assert resp.status_code == 400
    assert "HTTPS" in resp.json()["detail"]


def test_register_client_localhost_allowed(client):
    resp = client.post("/oauth/register", json={
        "client_name": "Dev Client",
        "redirect_uris": ["http://localhost:3000/callback"],
    })
    assert resp.status_code == 200


def test_register_client_invalid_grant_type(client):
    resp = client.post("/oauth/register", json={
        "client_name": "Bad Client",
        "redirect_uris": ["https://example.com/callback"],
        "grant_types": ["implicit"],
    })
    assert resp.status_code == 400


# --- Authorization Tests ---


def _register_client(test_client, redirect_uri="https://example.com/callback"):
    """Helper to register a client and return (client_id, client_secret)."""
    resp = test_client.post("/oauth/register", json={
        "client_name": "Test Client",
        "redirect_uris": [redirect_uri],
    })
    data = resp.json()
    return data["client_id"], data["client_secret"]


def _make_challenge():
    """Generate a PKCE verifier and challenge pair."""
    import hashlib
    from base64 import urlsafe_b64encode

    verifier = secrets.token_urlsafe(32)
    challenge = urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _get_csrf_token(test_client, client_id, challenge, redirect_uri="https://example.com/callback"):
    """GET the consent page and extract the CSRF token from the HTML."""
    resp = test_client.get("/oauth/authorize", params={
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "s",
        "scope": "mcp",
    })
    assert resp.status_code == 200
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', resp.text)
    assert match, "CSRF token not found in consent page"
    return match.group(1)


def test_authorize_shows_consent_in_dev_mode(client):
    """In dev mode, user is auto-authenticated → consent page shown."""
    client_id, _ = _register_client(client)
    _, challenge = _make_challenge()

    resp = client.get("/oauth/authorize", params={
        "client_id": client_id,
        "redirect_uri": "https://example.com/callback",
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "test-state",
    })
    assert resp.status_code == 200
    assert "Test Client" in resp.text
    assert "Authorize" in resp.text


def test_authorize_rejects_unknown_client(client):
    _, challenge = _make_challenge()

    resp = client.get("/oauth/authorize", params={
        "client_id": "mcp_nonexistent",
        "redirect_uri": "https://example.com/callback",
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    assert resp.status_code == 400


def test_authorize_rejects_bad_redirect_uri(client):
    client_id, _ = _register_client(client)
    _, challenge = _make_challenge()

    resp = client.get("/oauth/authorize", params={
        "client_id": client_id,
        "redirect_uri": "https://evil.com/callback",
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    assert resp.status_code == 400


def test_authorize_approve(client):
    client_id, _ = _register_client(client)
    _, challenge = _make_challenge()
    csrf = _get_csrf_token(client, client_id, challenge)

    resp = client.post("/oauth/authorize", data={
        "action": "approve",
        "client_id": client_id,
        "redirect_uri": "https://example.com/callback",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "mystate",
        "scope": "mcp",
        "csrf_token": csrf,
    })
    assert resp.status_code == 302
    location = resp.headers["location"]
    parsed = urlparse(location)
    params = parse_qs(parsed.query)
    assert "code" in params
    assert params["state"] == ["mystate"]
    assert parsed.netloc == "example.com"


def test_authorize_deny(client):
    client_id, _ = _register_client(client)
    _, challenge = _make_challenge()
    csrf = _get_csrf_token(client, client_id, challenge)

    resp = client.post("/oauth/authorize", data={
        "action": "deny",
        "client_id": client_id,
        "redirect_uri": "https://example.com/callback",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "mystate",
        "csrf_token": csrf,
    })
    assert resp.status_code == 302
    location = resp.headers["location"]
    params = parse_qs(urlparse(location).query)
    assert params["error"] == ["access_denied"]
    assert params["state"] == ["mystate"]


def test_authorize_rejects_missing_csrf(client):
    """POST without CSRF token is rejected."""
    client_id, _ = _register_client(client)
    _, challenge = _make_challenge()

    resp = client.post("/oauth/authorize", data={
        "action": "approve",
        "client_id": client_id,
        "redirect_uri": "https://example.com/callback",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "csrf_token": "forged-token",
    })
    assert resp.status_code == 403


def test_authorize_rejects_invalid_scope(client):
    """Requesting an unsupported scope returns an error redirect."""
    client_id, _ = _register_client(client)
    _, challenge = _make_challenge()

    resp = client.get("/oauth/authorize", params={
        "client_id": client_id,
        "redirect_uri": "https://example.com/callback",
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "scope": "admin",
    })
    assert resp.status_code == 302
    params = parse_qs(urlparse(resp.headers["location"]).query)
    assert params["error"] == ["invalid_scope"]


# --- Token Exchange Tests ---


def _approve_and_get_code(test_client, client_id, challenge, redirect_uri="https://example.com/callback"):
    """GET consent page (sets CSRF), approve, and extract the code from the redirect."""
    csrf = _get_csrf_token(test_client, client_id, challenge, redirect_uri)
    resp = test_client.post("/oauth/authorize", data={
        "action": "approve",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "s",
        "scope": "mcp",
        "csrf_token": csrf,
    })
    location = resp.headers["location"]
    params = parse_qs(urlparse(location).query)
    return params["code"][0]


def test_token_exchange_success(client):
    client_id, client_secret = _register_client(client)
    verifier, challenge = _make_challenge()
    code = _approve_and_get_code(client, client_id, challenge)

    resp = client.post("/oauth/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://example.com/callback",
        "code_verifier": verifier,
        "client_id": client_id,
        "client_secret": client_secret,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["access_token"].startswith("ff_")
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 7 * 86400
    assert data["refresh_token"].startswith("ffr_")


def test_token_exchange_bad_pkce(client):
    client_id, client_secret = _register_client(client)
    _, challenge = _make_challenge()
    code = _approve_and_get_code(client, client_id, challenge)

    resp = client.post("/oauth/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://example.com/callback",
        "code_verifier": "wrong-verifier-that-is-long-enough-to-pass-length-check",
        "client_id": client_id,
        "client_secret": client_secret,
    })
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"


def test_token_exchange_used_code(client):
    client_id, client_secret = _register_client(client)
    verifier, challenge = _make_challenge()
    code = _approve_and_get_code(client, client_id, challenge)

    # First exchange succeeds
    client.post("/oauth/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://example.com/callback",
        "code_verifier": verifier,
        "client_id": client_id,
        "client_secret": client_secret,
    })

    # Second exchange with same code fails
    resp = client.post("/oauth/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://example.com/callback",
        "code_verifier": verifier,
        "client_id": client_id,
        "client_secret": client_secret,
    })
    assert resp.status_code == 400
    assert "already used" in resp.json()["error_description"]


def test_token_exchange_wrong_redirect_uri(client):
    client_id, client_secret = _register_client(client)
    verifier, challenge = _make_challenge()
    code = _approve_and_get_code(client, client_id, challenge)

    resp = client.post("/oauth/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://other.com/callback",
        "code_verifier": verifier,
        "client_id": client_id,
        "client_secret": client_secret,
    })
    assert resp.status_code == 400
    assert "redirect_uri" in resp.json()["error_description"]


def test_token_exchange_expired_code(client, db_session):
    client_id, client_secret = _register_client(client)
    verifier, challenge = _make_challenge()
    code = _approve_and_get_code(client, client_id, challenge)

    # Manually expire the code
    row = db_session.query(OAuthAuthorizationCodeRow).filter_by(code=code).first()
    row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    row.used = False  # Reset used flag since approve already set it... actually no, approve doesn't set used
    db_session.flush()

    resp = client.post("/oauth/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://example.com/callback",
        "code_verifier": verifier,
        "client_id": client_id,
        "client_secret": client_secret,
    })
    assert resp.status_code == 400
    assert "expired" in resp.json()["error_description"]


def test_token_exchange_bad_client_secret(client):
    client_id, _ = _register_client(client)
    verifier, challenge = _make_challenge()
    code = _approve_and_get_code(client, client_id, challenge)

    resp = client.post("/oauth/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://example.com/callback",
        "code_verifier": verifier,
        "client_id": client_id,
        "client_secret": "wrong_secret",
    })
    assert resp.status_code == 401


# --- Refresh Token Tests ---


def test_refresh_token_flow(client, db_session):
    client_id, client_secret = _register_client(client)
    verifier, challenge = _make_challenge()
    code = _approve_and_get_code(client, client_id, challenge)

    # Get initial tokens
    resp = client.post("/oauth/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://example.com/callback",
        "code_verifier": verifier,
        "client_id": client_id,
        "client_secret": client_secret,
    })
    tokens = resp.json()

    # Refresh
    resp = client.post("/oauth/token", data={
        "grant_type": "refresh_token",
        "refresh_token": tokens["refresh_token"],
        "client_id": client_id,
        "client_secret": client_secret,
    })
    assert resp.status_code == 200
    new_tokens = resp.json()
    assert new_tokens["access_token"].startswith("ff_")
    assert new_tokens["refresh_token"].startswith("ffr_")
    assert new_tokens["access_token"] != tokens["access_token"]
    assert new_tokens["refresh_token"] != tokens["refresh_token"]

    # Old refresh token should now be revoked
    resp = client.post("/oauth/token", data={
        "grant_type": "refresh_token",
        "refresh_token": tokens["refresh_token"],
        "client_id": client_id,
        "client_secret": client_secret,
    })
    assert resp.status_code == 400

    # Old access token should be revoked
    old_hash = hash_token(tokens["access_token"])
    old_row = db_session.query(ApiTokenRow).filter_by(token_hash=old_hash).first()
    assert old_row.revoked is True


def test_refresh_token_wrong_client(client, db_session):
    """Refresh token bound to one client can't be used by another."""
    client_id_1, client_secret_1 = _register_client(client)
    client_id_2, client_secret_2 = _register_client(client)
    verifier, challenge = _make_challenge()
    code = _approve_and_get_code(client, client_id_1, challenge)

    resp = client.post("/oauth/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://example.com/callback",
        "code_verifier": verifier,
        "client_id": client_id_1,
        "client_secret": client_secret_1,
    })
    tokens = resp.json()

    # Try to use client_1's refresh token with client_2's credentials
    resp = client.post("/oauth/token", data={
        "grant_type": "refresh_token",
        "refresh_token": tokens["refresh_token"],
        "client_id": client_id_2,
        "client_secret": client_secret_2,
    })
    assert resp.status_code == 400
    assert "Client mismatch" in resp.json()["error_description"]


def test_code_replay_revokes_tokens(client, db_session):
    """Replaying a used auth code revokes all tokens issued from it (RFC 6749 §10.5)."""
    client_id, client_secret = _register_client(client)
    verifier, challenge = _make_challenge()
    code = _approve_and_get_code(client, client_id, challenge)

    # First exchange succeeds
    resp = client.post("/oauth/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://example.com/callback",
        "code_verifier": verifier,
        "client_id": client_id,
        "client_secret": client_secret,
    })
    assert resp.status_code == 200
    tokens = resp.json()

    # Replay the code
    resp = client.post("/oauth/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://example.com/callback",
        "code_verifier": verifier,
        "client_id": client_id,
        "client_secret": client_secret,
    })
    assert resp.status_code == 400

    # Access token should now be revoked
    at_hash = hash_token(tokens["access_token"])
    at_row = db_session.query(ApiTokenRow).filter_by(token_hash=at_hash).first()
    assert at_row.revoked is True

    # Refresh token should now be revoked
    rt_hash = hash_token(tokens["refresh_token"])
    rt_row = db_session.query(OAuthRefreshTokenRow).filter_by(token_hash=rt_hash).first()
    assert rt_row.revoked is True


def test_refresh_token_expired(client, db_session):
    """Expired refresh tokens are rejected."""
    client_id, client_secret = _register_client(client)
    verifier, challenge = _make_challenge()
    code = _approve_and_get_code(client, client_id, challenge)

    resp = client.post("/oauth/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://example.com/callback",
        "code_verifier": verifier,
        "client_id": client_id,
        "client_secret": client_secret,
    })
    tokens = resp.json()

    # Manually expire the refresh token
    rt_hash = hash_token(tokens["refresh_token"])
    rt_row = db_session.query(OAuthRefreshTokenRow).filter_by(token_hash=rt_hash).first()
    rt_row.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    db_session.flush()

    resp = client.post("/oauth/token", data={
        "grant_type": "refresh_token",
        "refresh_token": tokens["refresh_token"],
        "client_id": client_id,
        "client_secret": client_secret,
    })
    assert resp.status_code == 400
    assert "expired" in resp.json()["error_description"].lower()
