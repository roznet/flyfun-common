"""Auth utilities: JWT, OAuth, config."""

from flyfun_common.auth.config import (
    COOKIE_NAME,
    COOKIE_DOMAIN,
    is_dev_mode,
    get_jwt_secret,
    create_oauth,
)
from flyfun_common.auth.jwt_utils import create_token, decode_token
from flyfun_common.auth.router import create_auth_router

__all__ = [
    "COOKIE_NAME",
    "COOKIE_DOMAIN",
    "is_dev_mode",
    "get_jwt_secret",
    "create_oauth",
    "create_token",
    "decode_token",
    "create_auth_router",
]
