"""Auth utilities: JWT, OAuth, config."""

from flyfun_common.auth.config import (
    COOKIE_NAME,
    COOKIE_DOMAIN,
    SUPPORTED_PROVIDERS,
    is_dev_mode,
    get_jwt_secret,
    get_registered_providers,
    create_oauth,
)
from flyfun_common.auth.jwt_utils import (
    create_token,
    decode_token,
    get_jwt_cookie_max_age,
    get_jwt_expiry_days,
    get_jwt_refresh_threshold_days,
)
from flyfun_common.auth.middleware import SlidingSessionMiddleware
from flyfun_common.auth.router import create_auth_router

__all__ = [
    "COOKIE_NAME",
    "COOKIE_DOMAIN",
    "SUPPORTED_PROVIDERS",
    "is_dev_mode",
    "get_jwt_secret",
    "get_registered_providers",
    "create_oauth",
    "create_token",
    "decode_token",
    "get_jwt_cookie_max_age",
    "get_jwt_expiry_days",
    "get_jwt_refresh_threshold_days",
    "SlidingSessionMiddleware",
    "create_auth_router",
]
