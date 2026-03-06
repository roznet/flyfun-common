"""Shared auth configuration: cookie, JWT secret, OAuth providers."""

from __future__ import annotations

import os

from authlib.integrations.starlette_client import OAuth

# Unified cookie name — same across all flyfun services
COOKIE_NAME = "flyfun_auth"

# Cookie domain — set to .flyfun.aero in prod for cross-subdomain SSO
COOKIE_DOMAIN: str | None = None  # computed at runtime

_DEV_JWT_SECRET = "dev-insecure-jwt-secret-do-not-use-in-production"

# Providers that can be registered
SUPPORTED_PROVIDERS = ("google", "apple")


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


def _apple_client_secret() -> str:
    """Generate a short-lived JWT client_secret for Sign in with Apple.

    Apple requires the client_secret to be an ES256-signed JWT containing:
    - iss: Team ID
    - sub: Client ID (Service ID)
    - aud: https://appleid.apple.com
    - iat/exp: issued/expiry (max 180 days)

    Signed with the private key from Apple Developer Console.
    """
    import time

    import jwt  # PyJWT

    team_id = os.environ.get("APPLE_TEAM_ID", "")
    key_id = os.environ.get("APPLE_KEY_ID", "")
    client_id = os.environ.get("APPLE_CLIENT_ID", "")
    private_key = os.environ.get("APPLE_PRIVATE_KEY", "")

    if not all([team_id, key_id, client_id, private_key]):
        raise ValueError(
            "Apple Sign In requires APPLE_TEAM_ID, APPLE_KEY_ID, "
            "APPLE_CLIENT_ID, and APPLE_PRIVATE_KEY environment variables"
        )

    # Replace literal \n with actual newlines (env vars can't contain real newlines)
    private_key = private_key.replace("\\n", "\n")

    now = int(time.time())
    payload = {
        "iss": team_id,
        "sub": client_id,
        "aud": "https://appleid.apple.com",
        "iat": now,
        "exp": now + 86400 * 180,  # 180 days (Apple's max)
    }
    return jwt.encode(payload, private_key, algorithm="ES256", headers={"kid": key_id})


def create_oauth() -> OAuth:
    """Create OAuth registry with available providers.

    Providers are registered only if their client_id env var is set.
    """
    oauth = OAuth()

    # Google
    if os.environ.get("GOOGLE_CLIENT_ID"):
        oauth.register(
            name="google",
            client_id=os.environ.get("GOOGLE_CLIENT_ID"),
            client_secret=os.environ.get("GOOGLE_CLIENT_SECRET", ""),
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    # Apple — Sign in with Apple (OIDC)
    if os.environ.get("APPLE_CLIENT_ID"):
        oauth.register(
            name="apple",
            client_id=os.environ.get("APPLE_CLIENT_ID"),
            client_secret=_apple_client_secret(),
            server_metadata_url="https://appleid.apple.com/.well-known/openid-configuration",
            client_kwargs={
                "scope": "openid email name",
                "response_mode": "form_post",
            },
        )

    return oauth


def get_registered_providers(oauth: OAuth) -> list[str]:
    """Return the list of provider names that were registered."""
    return [p for p in SUPPORTED_PROVIDERS if hasattr(oauth, p)]
