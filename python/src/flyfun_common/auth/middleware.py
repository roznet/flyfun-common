"""Sliding-session middleware: refresh JWT when nearing expiry.

Stateless rolling sessions — a user who stays active keeps rolling forward
indefinitely (up to the absolute JWT expiry window). Decodes the incoming
credential and, when the remaining lifetime drops below the refresh
threshold, attaches a fresh token to the outgoing response.

Two transports are supported:
  * Cookie (`flyfun_auth`) — refreshed via `Set-Cookie`.
  * Bearer (`Authorization: Bearer <jwt>`) — refreshed via the
    `X-Renewed-Token` response header. Native clients (iOS / macOS) read
    the header and overwrite their stored JWT, mirroring the cookie
    behaviour for browsers.

If both a cookie and a Bearer token are present on the request, the cookie
takes precedence and only `Set-Cookie` is emitted (matches the assumption
that browser flows own the cookie path).

A token is only renewed when THIS request authenticated with it: the auth
dependencies (`current_user_id` / `optional_user_id`) call
`mark_session_authenticated` once every check has passed (user exists, not
suspended, not revoked by "log out everywhere"), and the middleware renews
only if that user is the token's `sub`. Decoding the token is not enough: on a
public route nothing checks revocation, so a revoked token would otherwise be
reissued with a fresh `iat` and pass the epoch check again.

For browsers consuming `X-Renewed-Token` from a different origin, expose
the header via CORS in the host app:

    app.add_middleware(
        CORSMiddleware,
        ...,
        expose_headers=["X-Renewed-Token"],
    )
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import jwt as pyjwt
from starlette.types import ASGIApp, Receive, Scope, Send

from flyfun_common.auth.config import (
    COOKIE_NAME,
    get_jwt_secret,
    get_session_cookie_attrs,
)
from flyfun_common.auth.jwt_utils import (
    create_token,
    decode_token,
    get_jwt_cookie_max_age,
    get_jwt_refresh_threshold_days,
)

logger = logging.getLogger(__name__)

RENEWED_TOKEN_HEADER = "X-Renewed-Token"

# ASGI scope key the auth dependencies set to the user id they authenticated
# from the session JWT (cookie or Bearer). Request.scope is the same dict the
# middleware holds, so it can read it when the response starts.
_AUTHENTICATED_SUB_KEY = "flyfun.session_authenticated_sub"


def mark_session_authenticated(request, user_id: str) -> None:
    """Record that this request authenticated ``user_id`` from its session JWT.

    Called by the auth dependencies after every check has passed. Only a
    marked request can have its token renewed by SlidingSessionMiddleware.
    """
    request.scope[_AUTHENTICATED_SUB_KEY] = user_id


class SlidingSessionMiddleware:
    """Refresh the user's JWT when it's close to expiring.

    Mount in each FastAPI app that issues flyfun_auth credentials:

        app.add_middleware(SlidingSessionMiddleware)

    Behavior:
      * Fires on HTTP requests carrying either a still-valid `flyfun_auth`
        cookie or an `Authorization: Bearer <jwt>` header.
      * Refreshes when the token's remaining lifetime is below
        JWT_REFRESH_THRESHOLD_DAYS (default 15), and only if the request
        authenticated with it (see ``mark_session_authenticated``). Public
        routes never renew.
      * Cookie input → `Set-Cookie: flyfun_auth=…` on the response.
      * Bearer input → `X-Renewed-Token: <jwt>` on the response.
      * If the response already sets the corresponding header itself
        (login callback, logout, account delete, manual rotation), the
        refresh is skipped so we don't clobber it.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        action = self._maybe_refresh_action(scope)
        if action is None:
            await self.app(scope, receive, send)
            return

        transport, value, sub = action

        async def send_wrapper(message):
            # Only roll the token forward when this request authenticated with
            # it (the dependency marked the token's own user), and only on a
            # successful response. Otherwise a revoked or suspended token in
            # its refresh window would be reissued with a new `iat` on any
            # public route, defeating session-epoch revocation.
            if (
                message["type"] == "http.response.start"
                and message.get("status", 200) < 400
                and scope.get(_AUTHENTICATED_SUB_KEY) == sub
            ):
                headers = list(message.get("headers", []))
                if transport == "cookie":
                    if not _response_sets_session_cookie(headers):
                        headers.append((b"set-cookie", value.encode("latin-1")))
                        message = {**message, "headers": headers}
                else:  # bearer
                    if not _response_sets_renewed_token(headers):
                        headers.append(
                            (RENEWED_TOKEN_HEADER.lower().encode("latin-1"),
                             value.encode("latin-1"))
                        )
                        message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)

    def _maybe_refresh_action(
        self, scope: Scope
    ) -> tuple[str, str, str] | None:
        """(transport, header value, token sub) for a renewable token, or None."""
        cookie = _extract_cookie(scope, COOKIE_NAME)
        if cookie:
            refreshed = self._maybe_refresh_token(cookie)
            if refreshed is None:
                return None
            new_token, sub = refreshed
            return (
                "cookie",
                _build_cookie_header(new_token, get_jwt_cookie_max_age()),
                sub,
            )

        bearer = _extract_bearer(scope)
        if bearer:
            refreshed = self._maybe_refresh_token(bearer)
            if refreshed is None:
                return None
            new_token, sub = refreshed
            return ("bearer", new_token, sub)

        return None

    def _maybe_refresh_token(self, current_token: str) -> tuple[str, str] | None:
        """Decode `current_token` and mint a successor if it's near expiry.

        Returns ``(new_token, sub)``, or None when the token can't be decoded,
        has no exp/sub, is outside the refresh window, or when re-issuance
        fails. Whether the successor is actually sent is decided per request
        in ``__call__``.
        """
        try:
            payload = decode_token(current_token, get_jwt_secret())
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
        return new_token, sub


def _extract_cookie(scope: Scope, name: str) -> str | None:
    for key, value in scope.get("headers", []):
        if key != b"cookie":
            continue
        for chunk in value.decode("latin-1").split(";"):
            k, _, v = chunk.strip().partition("=")
            if k == name:
                return v
    return None


def _extract_bearer(scope: Scope) -> str | None:
    for key, value in scope.get("headers", []):
        if key != b"authorization":
            continue
        decoded = value.decode("latin-1").strip()
        if decoded.lower().startswith("bearer "):
            token = decoded[7:].strip()
            return token or None
    return None


def _response_sets_session_cookie(headers: list[tuple[bytes, bytes]]) -> bool:
    prefix = f"{COOKIE_NAME}=".encode("latin-1")
    for key, value in headers:
        if key == b"set-cookie" and value.startswith(prefix):
            return True
    return False


def _response_sets_renewed_token(headers: list[tuple[bytes, bytes]]) -> bool:
    target = RENEWED_TOKEN_HEADER.lower().encode("latin-1")
    for key, _value in headers:
        if key == target:
            return True
    return False


def _build_cookie_header(token: str, max_age: int) -> str:
    attrs = get_session_cookie_attrs()
    parts = [f"{COOKIE_NAME}={token}", f"Max-Age={max_age}", f"Path={attrs['path']}"]
    if attrs.get("httponly"):
        parts.append("HttpOnly")
    samesite = attrs.get("samesite")
    if samesite:
        parts.append(f"SameSite={samesite}")
    if "domain" in attrs:
        parts.append(f"Domain={attrs['domain']}")
    if attrs.get("secure"):
        parts.append("Secure")
    return "; ".join(parts)
