"""OAuth 2.1 authorization server for MCP connectors."""

from flyfun_common.oauth.models import (  # noqa: F401 — ensure tables registered
    OAuthAuthorizationCodeRow,
    OAuthClientRow,
    OAuthRefreshTokenRow,
)
from flyfun_common.oauth.router import create_oauth_router

__all__ = [
    "create_oauth_router",
    "OAuthClientRow",
    "OAuthAuthorizationCodeRow",
    "OAuthRefreshTokenRow",
]
