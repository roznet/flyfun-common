"""OAuth sign-in links to an existing account with the same verified email.

One person who signed up by magic-link and later taps "Sign in with Google"
(or Apple) must land on the same user row, not a new empty one.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.sessions import SessionMiddleware


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.delenv("JWT_SECRET", raising=False)
    from flyfun_common.db.engine import (
        SessionLocal,
        get_engine,
        init_shared_db,
        reset_engine,
    )

    reset_engine()
    get_engine()
    init_shared_db()
    session = SessionLocal()
    yield session
    session.close()
    reset_engine()


def _add_user(db, user_id, provider, provider_sub, email, name="Existing"):
    from flyfun_common.db.models import UserRow

    db.add(
        UserRow(
            id=user_id,
            provider=provider,
            provider_sub=provider_sub,
            email=email,
            display_name=name,
            approved=True,
        )
    )
    db.commit()


def _all_users(db):
    from flyfun_common.db.models import UserRow

    return db.query(UserRow).all()


def _sign_in(db, provider, sub, email, name="Pilot Name", on_new_user=None,
             link=True):
    """Sign in; ``link`` stands for a provider-authoritative verified email
    (``_linkable_email`` returned it), which is what the routes pass."""
    from flyfun_common.auth.router import _find_or_create_user

    user = _find_or_create_user(
        db, provider, sub, email, name,
        on_new_user=on_new_user, request=object() if on_new_user else None,
        link_email=email if link else "",
    )
    db.commit()
    return user


# --- _linkable_email: when a provider's email is proof of the mailbox -------

V = {"email_verified": True}


@pytest.mark.parametrize(
    "provider, claims, email, linkable",
    [
        ("google", V, "pilot@gmail.com", True),
        ("google", V, "Pilot@GoogleMail.com", True),
        ("google", {"email_verified": "true"}, "pilot@gmail.com", True),
        # Workspace: Google manages the domain, hd says so.
        ("google", {**V, "hd": "acme.aero"}, "pilot@acme.aero", True),
        ("google", {**V, "hd": "other.aero"}, "pilot@acme.aero", False),
        # Consumer Google account on someone else's mailbox: verified once,
        # maybe reassigned since.
        ("google", V, "pilot@acme.aero", False),
        ("google", V, "pilot@icloud.com", False),
        ("apple", V, "pilot@icloud.com", True),
        ("apple", {"email_verified": "true"}, "pilot@me.com", True),
        ("apple", V, "pilot@mac.com", True),
        ("apple", V, "pilot@gmail.com", False),
        ("apple", V, "abc123@privaterelay.appleid.com", False),
        # The claim must be present and true.
        ("google", {}, "pilot@gmail.com", False),
        ("google", {"email_verified": False}, "pilot@gmail.com", False),
        ("apple", {"email_verified": "false"}, "pilot@icloud.com", False),
        # No Unicode case-folding onto an ASCII row (U+212A Kelvin sign).
        ("google", V, "\u212aate@gmail.com", False),
        ("google", V, "", False),
        ("email", V, "pilot@gmail.com", False),
    ],
)
def test_linkable_email(provider, claims, email, linkable):
    from flyfun_common.auth.router import _linkable_email

    assert _linkable_email(provider, claims, email) == (email if linkable else "")


# --- _find_or_create_user with a linkable email ------------------------------


def test_google_sign_in_links_to_magic_link_account(db):
    _add_user(db, "u-email", "email", "pilot@gmail.com", "pilot@gmail.com",
              name="pilot@gmail.com")
    created = []

    user = _sign_in(db, "google", "g-1", "pilot@gmail.com",
                    on_new_user=lambda u, r, d: created.append(u.id))

    assert user.id == "u-email"
    assert len(_all_users(db)) == 1
    assert created == []  # not a new user: no welcome email / provisioning
    # The row keeps its identity; only the display name improves.
    assert (user.provider, user.provider_sub) == ("email", "pilot@gmail.com")
    assert user.display_name == "Pilot Name"
    assert user.last_login_at is not None


def test_linked_provider_relinks_on_every_sign_in(db):
    _add_user(db, "u-email", "email", "pilot@gmail.com", "pilot@gmail.com")

    assert _sign_in(db, "google", "g-1", "pilot@gmail.com").id == "u-email"
    assert _sign_in(db, "google", "g-1", "pilot@gmail.com").id == "u-email"
    assert len(_all_users(db)) == 1


def test_apple_sign_in_links_to_google_account(db):
    _add_user(db, "u-google", "google", "g-1", "pilot@icloud.com")

    assert _sign_in(db, "apple", "a-1", "pilot@icloud.com").id == "u-google"
    assert len(_all_users(db)) == 1


def test_link_matches_email_case_insensitively(db):
    _add_user(db, "u-google", "google", "g-1", "Pilot@iCloud.com")

    assert _sign_in(db, "apple", "a-1", "pilot@icloud.com").id == "u-google"


def test_unlinkable_email_creates_new_user(db):
    """Same address, but the provider is not authoritative for it."""
    _add_user(db, "u-email", "email", "pilot@acme.aero", "pilot@acme.aero")

    user = _sign_in(db, "google", "g-1", "pilot@acme.aero", link=False)

    assert user.id != "u-email"
    assert len(_all_users(db)) == 2


def test_existing_provider_identity_wins_over_email(db):
    """A returning Google user stays on their own row even if another row
    now carries the same email."""
    _add_user(db, "u-email", "email", "pilot@gmail.com", "pilot@gmail.com")
    _add_user(db, "u-google", "google", "g-1", "pilot@gmail.com")

    assert _sign_in(db, "google", "g-1", "pilot@gmail.com").id == "u-google"


def test_same_provider_different_sub_is_not_linked(db):
    """A second Google account with the address (recreated account, recycled
    Workspace address) may be someone else: new user, not the old row."""
    _add_user(db, "u-google", "google", "g-old", "pilot@gmail.com")

    user = _sign_in(db, "google", "g-new", "pilot@gmail.com")

    assert user.id != "u-google"
    assert len(_all_users(db)) == 2


def _set_created(db, days: dict) -> None:
    from datetime import datetime, timezone
    from flyfun_common.db.models import UserRow

    for uid, day in days.items():
        db.get(UserRow, uid).created_at = datetime(2026, 1, day, tzinfo=timezone.utc)
    db.commit()


def test_duplicates_link_in_magic_link_order(db):
    """Rows sharing an email (pre-linking duplicates): skip the same
    provider, then the row magic-link would pick (by id, not by age)."""
    _add_user(db, "a-google-old", "google", "g-old", "pilot@gmail.com")
    _add_user(db, "b-email", "email", "pilot@gmail.com", "pilot@gmail.com")
    _add_user(db, "c-apple", "apple", "a-1", "pilot@gmail.com")
    _set_created(db, {"a-google-old": 2, "b-email": 3, "c-apple": 1})

    assert _sign_in(db, "google", "g-new", "pilot@gmail.com").id == "b-email"


def test_magic_link_pick_is_by_id_not_age(db):
    """The magic-link account choice among duplicates is unchanged by the
    explicit ordering: exact-case first, then id (MySQL's scan order)."""
    from flyfun_common.auth.users import user_with_email as _user_with_email

    _add_user(db, "a-newer", "google", "g-1", "pilot@gmail.com")
    _add_user(db, "b-older", "email", "pilot@gmail.com", "pilot@gmail.com")
    _add_user(db, "0-mixed-case", "apple", "a-1", "Pilot@gmail.com")
    _set_created(db, {"a-newer": 9, "b-older": 1, "0-mixed-case": 1})

    assert _user_with_email(db, "pilot@gmail.com").id == "a-newer"


def test_no_email_never_links(db):
    """"" must never match anything, including a row stored with email ""."""
    _add_user(db, "u-blank", "apple", "a-old", "")

    user = _sign_in(db, "google", "g-1", "")

    assert user.id != "u-blank"
    assert len(_all_users(db)) == 2


def test_lookalike_email_does_not_link(db):
    """Same rules as magic-link: no wildcard, no accent folding."""
    _add_user(db, "u-email", "email", "pilot@gmail.com", "pilot@gmail.com")

    for i, email in enumerate(["pilot%@gmail.com", "pil_t@gmail.com",
                               "pilot@gmäil.com"]):
        assert _sign_in(db, "google", f"g-{i}", email).id != "u-email"


# --- End to end through the iOS endpoint ---------------------------------------


def _apple_token(monkeypatch_db, claims, body=None):
    """POST /auth/apple/token with Apple's signature check stubbed to
    return ``claims``. The stubs live in their own MonkeyPatch so undoing
    them leaves the db fixture's environment alone."""
    from flyfun_common.auth import router as router_mod

    class _Key:
        key = "unused"

    class _Jwks:
        def get_signing_key_from_jwt(self, token):
            return _Key()

    monkeypatch_db.setenv("APPLE_APP_IDS", "aero.flyfun.test")
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test")
    app.include_router(router_mod.create_auth_router())
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(router_mod, "_get_apple_jwks_client", lambda: _Jwks())
        mp.setattr(router_mod.pyjwt, "decode", lambda *a, **k: claims)
        return TestClient(app).post(
            "/auth/apple/token", json=body or {"identity_token": "x"}
        )


def test_native_apple_token_links_to_magic_link_account(db, monkeypatch):
    from flyfun_common.auth.config import get_jwt_secret
    from flyfun_common.auth.jwt_utils import decode_token

    _add_user(db, "u-email", "email", "pilot@icloud.com", "pilot@icloud.com")

    resp = _apple_token(
        monkeypatch,
        {"sub": "a-1", "email": "pilot@icloud.com", "email_verified": "true"},
        {"identity_token": "x", "first_name": "Pilot", "last_name": "Name"},
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["user_id"] == "u-email"
    assert decode_token(resp.json()["token"], get_jwt_secret())["sub"] == "u-email"
    db.expire_all()
    assert len(_all_users(db)) == 1


def test_native_apple_token_missing_verified_claim_does_not_link(db, monkeypatch):
    _add_user(db, "u-email", "email", "pilot@icloud.com", "pilot@icloud.com")

    resp = _apple_token(monkeypatch, {"sub": "a-1", "email": "pilot@icloud.com"})

    assert resp.status_code == 200, resp.text
    assert resp.json()["user_id"] != "u-email"


def test_native_apple_token_linked_suspended_user_is_refused(db, monkeypatch):
    """Linking reaches the existing row, approval flag and all: a suspended
    user can't dodge it by signing in with another provider."""
    from flyfun_common.db.models import UserRow

    _add_user(db, "u-email", "email", "pilot@icloud.com", "pilot@icloud.com")
    db.get(UserRow, "u-email").approved = False
    db.commit()

    resp = _apple_token(
        monkeypatch,
        {"sub": "a-1", "email": "pilot@icloud.com", "email_verified": True},
    )

    assert resp.status_code == 403
    db.expire_all()
    assert len(_all_users(db)) == 1


# --- End to end through the web callback (the Google path) -------------------


@pytest.fixture
def google_callback(db, monkeypatch):
    """Drive /auth/login/google + /auth/callback/google with a stub provider
    returning ``userinfo``; return the signed-in user id."""
    from flyfun_common.auth import router as router_mod
    from flyfun_common.auth.config import COOKIE_NAME, get_jwt_secret
    from flyfun_common.auth.jwt_utils import decode_token
    from tests.test_sliding_session import _StubOAuth, _StubOAuthClient

    def sign_in(userinfo: dict) -> str:
        monkeypatch.setattr(
            router_mod, "create_oauth", lambda: _StubOAuth(_StubOAuthClient(userinfo))
        )
        app = FastAPI()
        app.add_middleware(SessionMiddleware, secret_key="test")
        app.include_router(router_mod.create_auth_router())
        client = TestClient(app)
        assert client.get("/auth/login/google", follow_redirects=False).status_code == 302
        r = client.get("/auth/callback/google", follow_redirects=False)
        assert r.status_code == 302, r.text
        token = r.cookies.get(COOKIE_NAME) or client.cookies.get(COOKIE_NAME)
        return decode_token(token, get_jwt_secret())["sub"]

    return sign_in


def test_google_callback_links_to_magic_link_account(db, google_callback):
    _add_user(db, "u-email", "email", "pilot@gmail.com", "pilot@gmail.com")

    user_id = google_callback(
        {"sub": "g-1", "email": "pilot@gmail.com", "email_verified": True,
         "name": "Pilot Name"}
    )

    assert user_id == "u-email"
    db.expire_all()
    assert len(_all_users(db)) == 1


def test_google_callback_without_verified_claim_does_not_link(db, google_callback):
    _add_user(db, "u-email", "email", "pilot@gmail.com", "pilot@gmail.com")

    user_id = google_callback({"sub": "g-1", "email": "pilot@gmail.com", "name": "P"})

    assert user_id != "u-email"
    db.expire_all()
    assert len(_all_users(db)) == 2
