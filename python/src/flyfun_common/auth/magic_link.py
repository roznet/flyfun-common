"""Magic-link (email) auth path.

A third login provider alongside Google/Apple. Mints the same
``flyfun_auth`` cookie -- magic-link is purely an alternate way to identify
a user.

Flow:

  1. ``POST /auth/magic-link/request`` -- mints a single-use token + 6-digit
     OTP, stores SHA-256 hashes only, invokes the app-provided
     ``send_magic_link_email`` callback. Always returns 200 (no account
     enumeration). 503 only when no callback is wired.
  2. ``GET  /auth/verify?token=...`` -- does NOT consume. 302s to the
     app-owned ``/auth-verify.html?token=...`` so corporate scanners that
     pre-click links never burn the token.
  3. ``POST /auth/magic-link/consume`` -- web flow. Validates, marks used,
     mints JWT, sets the ``flyfun_auth`` cookie, redirects.
  4. ``POST /auth/magic-link/consume-code`` -- iOS flow. Same logic, returns
     ``{token, user_id}`` JSON (no cookie).

Helpers ``_find_or_create_user_by_email`` and
``purge_expired_magic_link_tokens`` live alongside the endpoints.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Callable
from urllib.parse import urlencode, urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from flyfun_common.auth.config import (
    COOKIE_NAME,
    get_jwt_secret,
    is_dev_mode,
)
from flyfun_common.auth.jwt_utils import create_token
from flyfun_common.auth.rate_limit import (
    check_email_request_rate,
    check_ip_consume_rate,
    check_ip_request_rate,
    record_consume_attempt,
)
from flyfun_common.db.deps import get_db
from flyfun_common.db.models import MagicLinkTokenRow, UserRow

logger = logging.getLogger(__name__)

TOKEN_TTL = timedelta(minutes=15)
# Burn a token after this many wrong OTP guesses. With a 6-digit code and a
# 15-min TTL this caps the success probability of brute force well below
# 0.01% per token even with no working per-IP throttle.
MAX_OTP_ATTEMPTS = 5
APPLE_PRIVATE_RELAY_SUFFIX = "@privaterelay.appleid.com"

# Permissive RFC-ish check -- catches obvious garbage without pulling in
# email-validator. Real-world deliverability is what enforces uniqueness;
# we only normalize and case-fold.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


SendMagicLinkEmail = Callable[[str, str, str, "str | None"], None]


# --- helpers -----------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    """Treat naive datetimes as UTC.

    SQLite's ``DateTime(timezone=True)`` silently drops tz info on read;
    MySQL preserves it. Coerce both to tz-aware UTC before comparing
    against ``datetime.now(timezone.utc)`` so the same code works on
    dev (SQLite) and prod (MySQL).
    """
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _is_safe_relative_path(value: str | None) -> bool:
    """Mirror of router._is_safe_relative_path, duplicated to avoid an
    import cycle (magic_link is imported from router)."""
    if not value or not isinstance(value, str):
        return False
    if not value.startswith("/"):
        return False
    if value.startswith("//") or value.startswith("/\\"):
        return False
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    return parsed.scheme == "" and parsed.netloc == ""


def _client_ip(request: Request) -> str | None:
    """Best-effort trusted client IP for rate limiting.

    The leftmost ``X-Forwarded-For`` entry is client-supplied and therefore
    spoofable (our edge proxy appends, it does not replace). Prefer
    ``X-Real-IP`` (Caddy sets it to the real peer via
    ``header_up X-Real-IP {remote_host}``); otherwise take the *rightmost*
    XFF token (the one our own proxy appended), matching the weather app's
    ``security._client_ip``.
    """
    real_ip = request.headers.get("x-real-ip")
    if real_ip and real_ip.strip():
        return real_ip.strip()
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[-1].strip() or None
    if request.client:
        return request.client.host
    return None


def _build_verify_link(request: Request, token: str, next_path: str | None) -> str:
    base = str(request.url_for("magic_link_verify"))
    if not is_dev_mode():
        base = base.replace("http://", "https://")
    params = {"token": token}
    if next_path and _is_safe_relative_path(next_path):
        params["next"] = next_path
    return f"{base}?{urlencode(params)}"


def _find_or_create_user_by_email(
    db: Session,
    email: str,
    *,
    on_new_user: Callable | None = None,
    request: Request | None = None,
) -> UserRow:
    """Locate a user by email or create one with ``provider='email'``.

    Does not mutate the existing ``_find_or_create_user`` -- Google/Apple's
    ``(provider, provider_sub)`` path is left alone. Email-keyed lookup is
    case-insensitive. When an existing row is found, its ``provider`` field
    is preserved (a Google user verifying via magic-link stays
    ``provider='google'``).
    """
    email_lower = _normalize_email(email)
    user = (
        db.query(UserRow)
        .filter(UserRow.email == email_lower)
        .first()
    )
    if user is None:
        # Fall back to case-insensitive search for legacy rows that may have
        # been stored with mixed case.
        user = (
            db.query(UserRow)
            .filter(UserRow.email.ilike(email_lower))
            .first()
        )

    if user is None:
        user = UserRow(
            id=str(uuid.uuid4()),
            provider="email",
            provider_sub=email_lower,
            email=email_lower,
            display_name=email_lower,
            approved=True,
        )
        db.add(user)
        db.flush()
        logger.info("New user created via email magic-link: %s", user.id)
        if on_new_user and request is not None:
            try:
                on_new_user(user, request, db)
            except Exception:
                logger.warning(
                    "on_new_user callback failed for %s", user.id, exc_info=True
                )

    user.last_login_at = _now()
    db.flush()
    return user


def purge_expired_magic_link_tokens(
    db: Session, *, older_than_hours: int = 24
) -> int:
    """Remove expired/used magic-link rows and old consume-attempt rows.

    Returns the number of token rows deleted. Consumer apps should call
    this from their retention loop -- flyfun-common does not schedule.
    """
    from flyfun_common.db.models import MagicLinkConsumeAttemptRow

    cutoff = _now() - timedelta(hours=older_than_hours)
    tokens_deleted = (
        db.query(MagicLinkTokenRow)
        .filter(MagicLinkTokenRow.expires_at < cutoff)
        .delete(synchronize_session=False)
    )
    db.query(MagicLinkConsumeAttemptRow).filter(
        MagicLinkConsumeAttemptRow.attempted_at < cutoff
    ).delete(synchronize_session=False)
    db.flush()
    return tokens_deleted


# --- request/response bodies ------------------------------------------------


def _validate_email(value: str) -> str:
    value = value.strip()
    if not _EMAIL_RE.match(value):
        raise ValueError("not a valid email address")
    return value


class MagicLinkRequestBody(BaseModel):
    email: str
    platform: str | None = None
    next: str | None = None

    @field_validator("email")
    @classmethod
    def _check_email(cls, v: str) -> str:
        return _validate_email(v)


class MagicLinkConsumeBody(BaseModel):
    token: str
    next: str | None = None


class MagicLinkConsumeCodeBody(BaseModel):
    email: str
    code: str

    @field_validator("email")
    @classmethod
    def _check_email(cls, v: str) -> str:
        return _validate_email(v)


# --- router ------------------------------------------------------------------


def build_magic_link_router(
    *,
    send_magic_link_email: SendMagicLinkEmail | None,
    on_new_user: Callable | None,
) -> APIRouter:
    """Build the magic-link sub-router included by ``create_auth_router``.

    ``send_magic_link_email`` may be ``None``; in that case ``/request``
    returns 503 and consume endpoints still work for already-issued tokens
    (useful in tests).
    """
    router = APIRouter(tags=["auth"])

    @router.post("/magic-link/request")
    async def request_magic_link(
        body: MagicLinkRequestBody,
        request: Request,
        db: Session = Depends(get_db),
    ):
        if send_magic_link_email is None:
            raise HTTPException(
                status_code=503,
                detail="Magic-link sign-in is not configured on this server",
            )

        email_lower = _normalize_email(body.email)

        if email_lower.endswith(APPLE_PRIVATE_RELAY_SUFFIX):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Apple Private Relay addresses can't receive mail from "
                    "us. Use Sign in with Apple instead."
                ),
            )

        ip = _client_ip(request)

        # Rate-limit checks deliberately run before the side effect. We
        # return 429 to make the limit observable for the requester; the
        # account-enumeration concern only applies to the "happy path"
        # response distinguishing existing vs. new accounts, which it
        # doesn't.
        if not check_ip_request_rate(db, ip):
            raise HTTPException(status_code=429, detail="Too many requests")
        if not check_email_request_rate(db, email_lower):
            raise HTTPException(status_code=429, detail="Too many requests")

        raw_token = secrets.token_urlsafe(32)
        otp_code = f"{secrets.randbelow(10**6):06d}"
        now = _now()

        row = MagicLinkTokenRow(
            id=str(uuid.uuid4()),
            email=email_lower,
            token_hash=_sha256(raw_token),
            otp_code_hash=_sha256(otp_code),
            created_at=now,
            expires_at=now + TOKEN_TTL,
            requested_ip=ip,
        )
        db.add(row)
        db.flush()

        link = _build_verify_link(request, raw_token, body.next)

        try:
            send_magic_link_email(email_lower, link, otp_code, ip)
        except Exception:
            logger.exception("send_magic_link_email callback raised")
            # Still return 200: do not let callback failures leak
            # account state to the caller. The app's email infra is
            # responsible for its own retries/observability.

        return {"ok": True}

    @router.get("/verify", name="magic_link_verify")
    async def verify(token: str, next: str | None = None):
        """Pass-through page -- never consumes the token.

        Corporate email scanners (Outlook ATP, Proofpoint, Mimecast)
        pre-click links. Only the explicit POST from /auth-verify.html
        burns the token.
        """
        params = {"token": token}
        if next and _is_safe_relative_path(next):
            params["next"] = next
        return RedirectResponse(
            url=f"/auth-verify.html?{urlencode(params)}", status_code=302
        )

    @router.post("/magic-link/consume")
    async def consume(
        body: MagicLinkConsumeBody,
        request: Request,
        db: Session = Depends(get_db),
    ):
        ip = _client_ip(request)
        record_consume_attempt(db, ip)
        if not check_ip_consume_rate(db, ip):
            raise HTTPException(status_code=429, detail="Too many attempts")

        row = (
            db.query(MagicLinkTokenRow)
            .filter(MagicLinkTokenRow.token_hash == _sha256(body.token))
            .first()
        )
        if (
            row is None
            or row.used_at is not None
            or _aware(row.expires_at) < _now()
        ):
            raise HTTPException(
                status_code=400, detail="Invalid or expired link"
            )

        user = _find_or_create_user_by_email(
            db, row.email, on_new_user=on_new_user, request=request
        )

        # Pending-user parity with the OAuth callback: do not mint a JWT;
        # bounce the user to a status page. The token is intentionally NOT
        # marked used so an admin-approved user can click the same link
        # later. (Tokens expire in 15 min anyway.)
        if not user.approved:
            return RedirectResponse(
                url="/login.html?status=pending", status_code=302
            )

        row.used_at = _now()
        db.flush()

        jwt_token = create_token(
            user.id, user.email, user.display_name, get_jwt_secret()
        )

        target = (
            body.next
            if body.next and _is_safe_relative_path(body.next)
            else "/"
        )
        response = RedirectResponse(url=target, status_code=302)
        _set_session_cookie(response, jwt_token)
        return response

    @router.post("/magic-link/consume-code")
    async def consume_code(
        body: MagicLinkConsumeCodeBody,
        request: Request,
        db: Session = Depends(get_db),
    ):
        """iOS flow. Returns the JWT in JSON; no cookie set."""
        ip = _client_ip(request)
        record_consume_attempt(db, ip)
        if not check_ip_consume_rate(db, ip):
            raise HTTPException(status_code=429, detail="Too many attempts")

        email_lower = _normalize_email(body.email)
        code_hash = _sha256(body.code.strip())
        now = _now()

        # Fetch the live (unused, unexpired) tokens for this email WITHOUT the
        # code filter, so a wrong guess still maps to the candidate token(s)
        # and charges an attempt against them. OTPs are only 6 digits, so a
        # per-token attempt cap is what actually bounds brute force.
        candidates = (
            db.query(MagicLinkTokenRow)
            .filter(
                MagicLinkTokenRow.email == email_lower,
                MagicLinkTokenRow.used_at.is_(None),
                MagicLinkTokenRow.expires_at >= now,
            )
            .order_by(MagicLinkTokenRow.created_at.desc())
            .all()
        )
        match = next(
            (
                r
                for r in candidates
                if r.otp_code_hash
                and hmac.compare_digest(r.otp_code_hash, code_hash)
            ),
            None,
        )
        if match is None:
            # Wrong code: charge an attempt against every live candidate and
            # burn any that reaches the cap. Commit BEFORE raising — get_db
            # rolls back on HTTPException, which would otherwise erase the
            # counter (and the per-IP attempt row) and leave the OTP
            # effectively unthrottled.
            for r in candidates:
                r.attempt_count = (r.attempt_count or 0) + 1
                if r.attempt_count >= MAX_OTP_ATTEMPTS:
                    r.used_at = now
            db.commit()
            raise HTTPException(
                status_code=400, detail="Invalid or expired code"
            )

        user = _find_or_create_user_by_email(
            db, match.email, on_new_user=on_new_user, request=request
        )

        if not user.approved:
            raise HTTPException(
                status_code=403, detail="Account is pending approval"
            )

        match.used_at = _now()
        db.flush()

        jwt_token = create_token(
            user.id, user.email, user.display_name, get_jwt_secret()
        )
        return JSONResponse({"token": jwt_token, "user_id": user.id})

    return router


# Local copy of the cookie helper -- avoid importing it from router.py to
# keep the dependency direction one-way (router imports magic_link).
def _set_session_cookie(response, token: str) -> None:
    from flyfun_common.auth.config import get_session_cookie_attrs
    from flyfun_common.auth.jwt_utils import get_jwt_cookie_max_age

    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=get_jwt_cookie_max_age(),
        **get_session_cookie_attrs(),
    )
