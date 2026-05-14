"""DB-backed sliding-window rate limits for the magic-link flow.

Three windows enforced:
  * per email on /magic-link/request   - 3 / hour  (mailbox spam)
  * per IP    on /magic-link/request   - 10 / hour (quota abuse)
  * per IP    on /magic-link/consume*  - 5 / minute (brute force)

Storage strategy: counts run as sliding windows over
``magic_link_tokens.created_at`` for /request limits, and over
``magic_link_consume_attempts.attempted_at`` for /consume limits. No
counter rows -- the natural log tables are the truth.

All checks return ``True`` (skip the limit) when ``is_dev_mode()``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from flyfun_common.auth.config import is_dev_mode
from flyfun_common.db.models import (
    MagicLinkConsumeAttemptRow,
    MagicLinkTokenRow,
)

EMAIL_REQUEST_LIMIT = 3
EMAIL_REQUEST_WINDOW = timedelta(hours=1)

IP_REQUEST_LIMIT = 10
IP_REQUEST_WINDOW = timedelta(hours=1)

IP_CONSUME_LIMIT = 5
IP_CONSUME_WINDOW = timedelta(minutes=1)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def check_email_request_rate(
    db: Session,
    email_lower: str,
    *,
    limit: int = EMAIL_REQUEST_LIMIT,
    window: timedelta = EMAIL_REQUEST_WINDOW,
) -> bool:
    """Return True if another /request is allowed for this email."""
    if is_dev_mode():
        return True
    since = _now() - window
    count = (
        db.query(func.count(MagicLinkTokenRow.id))
        .filter(
            MagicLinkTokenRow.email == email_lower,
            MagicLinkTokenRow.created_at >= since,
        )
        .scalar()
        or 0
    )
    return count < limit


def check_ip_request_rate(
    db: Session,
    ip: str | None,
    *,
    limit: int = IP_REQUEST_LIMIT,
    window: timedelta = IP_REQUEST_WINDOW,
) -> bool:
    """Return True if another /request is allowed from this IP."""
    if is_dev_mode() or not ip:
        return True
    since = _now() - window
    count = (
        db.query(func.count(MagicLinkTokenRow.id))
        .filter(
            MagicLinkTokenRow.requested_ip == ip,
            MagicLinkTokenRow.created_at >= since,
        )
        .scalar()
        or 0
    )
    return count < limit


def check_ip_consume_rate(
    db: Session,
    ip: str | None,
    *,
    limit: int = IP_CONSUME_LIMIT,
    window: timedelta = IP_CONSUME_WINDOW,
) -> bool:
    """Return True if another /consume attempt is allowed from this IP."""
    if is_dev_mode() or not ip:
        return True
    since = _now() - window
    count = (
        db.query(func.count(MagicLinkConsumeAttemptRow.id))
        .filter(
            MagicLinkConsumeAttemptRow.ip == ip,
            MagicLinkConsumeAttemptRow.attempted_at >= since,
        )
        .scalar()
        or 0
    )
    return count < limit


def record_consume_attempt(db: Session, ip: str | None) -> None:
    """Record a /consume attempt for the per-IP rate limit.

    Records even when ``is_dev_mode()`` so tests can assert call counts; the
    limit check itself is what gets bypassed.
    """
    if not ip:
        return
    db.add(MagicLinkConsumeAttemptRow(ip=ip, attempted_at=_now()))
    db.flush()
