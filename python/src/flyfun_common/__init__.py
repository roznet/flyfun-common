"""Shared user management and auth for flyfun services."""

from flyfun_common.autorouter import create_autorouter_router, get_autorouter_token
from flyfun_common.oauth import create_oauth_router

__all__ = [
    "create_autorouter_router",
    "create_oauth_router",
    "get_autorouter_token",
]
