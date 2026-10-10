"""Email-keyed user lookup shared by both sign-in paths.

Magic-link (``auth.magic_link``) signs in to the account holding an email;
OAuth (``auth.router._find_or_create_user``) falls back to the same lookup to
join an existing account. Both must pick the same row among duplicates.
"""

from __future__ import annotations

from sqlalchemy import func
from sqlalchemy.orm import Session

from flyfun_common.db.models import UserRow


def normalize_email(email: str) -> str:
    return email.strip().lower()


def users_with_email(db: Session, email_lower: str) -> list[UserRow]:
    """Every user whose stored email equals ``email_lower`` ignoring case only.

    SQL narrows the candidates; Python decides. The database comparison
    depends on its collation (MySQL's ``utf8mb4_unicode_ci`` also ignores
    accents and folds ``ß``/``ss``, so ``gmäil.com`` = ``gmail.com``), and
    LIKE would add wildcards. Neither may pick the account. Rows stored with
    mixed case (OAuth providers' emails are kept as given) still match.

    Order is deterministic, since several rows can share an email: exact-case
    rows first, then by ``id``. That is the order MySQL returned them in before
    it was made explicit (``LOWER(email)`` can't use ``ix_users_email``, so it
    is a full scan in primary-key order), so a magic-link sign-in still lands
    on the account it always did. Don't change it to "oldest first": with
    duplicate accounts on prod that would move pilots to another account.
    """
    candidates = (
        db.query(UserRow)
        .filter(func.lower(UserRow.email) == email_lower)
        .order_by(UserRow.id)
        .all()
    )
    matches = [u for u in candidates if normalize_email(u.email or "") == email_lower]
    return sorted(matches, key=lambda u: u.email != email_lower)  # stable


def user_with_email(db: Session, email_lower: str) -> UserRow | None:
    """The first of ``users_with_email``: the account an email signs in to."""
    return next(iter(users_with_email(db, email_lower)), None)
