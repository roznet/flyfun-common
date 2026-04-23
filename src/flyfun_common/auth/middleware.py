"""Sliding-session middleware: refresh JWT cookie when nearing expiry.

Stateless rolling sessions — a user who stays active keeps rolling forward
indefinitely (up to the absolute JWT expiry window). Decodes the incoming
cookie and, when the remaining lifetime drops below the refresh threshold,
attaches a fresh cookie to the outgoing response.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import jwt as pyjwt
from starlette.types import ASGIApp, Receive, Scope, Send

from flyfun_common.auth.config import (
    COOKIE_NAME,
    get_cookie_domain,
    get_jwt_secret,
    is_dev_mode,
)
from flyfun_common.auth.jwt_utils import (
    create_token,
    decode_token,
    get_jwt_cookie_max_age,
    get_jwt_refresh_threshold_days,
)

logger = logging.getLogger(__name__)


class SlidingSessionMiddleware:
    """Refresh the flyfun_auth cookie when it's close to expiring.

    Mount in each FastAPI app that issues flyfun_auth cookies:

        app.add_middleware(SlidingSessionMiddleware)

    Behavior:
      * Only fires on HTTP requests that carry a still-valid flyfun_auth cookie.
      * Refreshes when the token's remaining lifetime is below
        JWT_REFRESH_THRESHOLD_DAYS (default 15).
      * Bearer-token requests are left untouched (nothing to rewrite).
      * If the outgoing response already sets flyfun_auth (login callback,
        logout, account delete), the refresh is skipped so we don't clobber it.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        refreshed = self._maybe_build_refresh(scope)
        if refreshed is None:
            await self.app(scope, receive, send)
            return

        cookie_header = refreshed.encode("latin-1")

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                if not _response_sets_session_cookie(headers):
                    headers.append((b"set-cookie", cookie_header))
                    message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)

    def _maybe_build_refresh(self, scope: Scope) -> str | None:
        cookie = _extract_cookie(scope, COOKIE_NAME)
        if not cookie:
            return None

        try:
            payload = decode_token(cookie, get_jwt_secret())
        except pyjwt.PyJWTError:
            return None

        exp = payload.get("exp")
        sub = payload.get("sub")
        if exp is None or not sub:
            return None

        remaining = exp - datetime.now(timezone.utc).timestamp()
        threshold = get_jwt_refresh_threshold_days() * 24 * 3600
        if remaining >= threshold:
            return None

        try:
            new_token = create_token(
                sub,
                payload.get("email", ""),
                payload.get("name", ""),
                get_jwt_secret(),
            )
        except Exception:
            logger.warning(
                "SlidingSessionMiddleware failed to refresh token", exc_info=True
            )
            return None

        return _build_cookie_header(new_token, get_jwt_cookie_max_age())


def _extract_cookie(scope: Scope, name: str) -> str | None:
    for key, value in scope.get("headers", []):
        if key != b"cookie":
            continue
        for chunk in value.decode("latin-1").split(";"):
            k, _, v = chunk.strip().partition("=")
            if k == name:
                return v
    return None


def _response_sets_session_cookie(headers: list[tuple[bytes, bytes]]) -> bool:
    prefix = f"{COOKIE_NAME}=".encode("latin-1")
    for key, value in headers:
        if key == b"set-cookie" and value.startswith(prefix):
            return True
    return False


def _build_cookie_header(token: str, max_age: int) -> str:
    parts = [
        f"{COOKIE_NAME}={token}",
        f"Max-Age={max_age}",
        "Path=/",
        "HttpOnly",
        "SameSite=lax",
    ]
    domain = get_cookie_domain()
    if domain:
        parts.append(f"Domain={domain}")
    if not is_dev_mode():
        parts.append("Secure")
    return "; ".join(parts)
