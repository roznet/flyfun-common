"""Shared auth configuration: cookie, JWT secret, OAuth."""

from __future__ import annotations

import os

from authlib.integrations.starlette_client import OAuth

# Unified cookie name — same across all flyfun services
COOKIE_NAME = "flyfun_auth"

# Cookie domain — set to .flyfun.aero in prod for cross-subdomain SSO
COOKIE_DOMAIN: str | None = None  # computed at runtime

_DEV_JWT_SECRET = "dev-insecure-jwt-secret-do-not-use-in-production"


def is_dev_mode() -> bool:
    return os.environ.get("ENVIRONMENT", "development") != "production"


def get_cookie_domain() -> str | None:
    """Return .flyfun.aero in production (enables SSO), None in dev."""
    if is_dev_mode():
        return None
    return os.environ.get("COOKIE_DOMAIN", ".flyfun.aero")


def get_jwt_secret() -> str:
    secret = os.environ.get("JWT_SECRET")
    if secret:
        if not is_dev_mode() and secret == _DEV_JWT_SECRET:
            raise ValueError(
                "Production must use a unique JWT_SECRET, not the dev default"
            )
        return secret
    if is_dev_mode():
        return _DEV_JWT_SECRET
    raise ValueError("JWT_SECRET environment variable must be set in production")


def create_oauth() -> OAuth:
    """Create OAuth registry with Google provider."""
    oauth = OAuth()
    oauth.register(
        name="google",
        client_id=os.environ.get("GOOGLE_CLIENT_ID", ""),
        client_secret=os.environ.get("GOOGLE_CLIENT_SECRET", ""),
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )
    return oauth
