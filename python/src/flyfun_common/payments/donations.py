"""Donation ledger utilities: record (idempotent), refund, aggregate.

Pure DB layer over :class:`flyfun_common.db.models.DonationRow`. The webhook is
the source of truth; this module never talks to Stripe and never converts FX —
callers pass already-computed ``amount_usd`` / ``fx_rate`` (see
:mod:`flyfun_common.fx`). USD is canonical: aggregation sums ``amount_usd`` so
historical totals don't drift with the exchange rate.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from flyfun_common.db.models import DonationRow


def _get_by_ref(db: Session, provider_ref: str) -> DonationRow | None:
    return (
        db.query(DonationRow)
        .filter(DonationRow.provider_ref == provider_ref)
        .one_or_none()
    )


def record_donation(
    db: Session,
    *,
    provider_ref: str,
    service: str,
    amount: float,
    currency: str,
    amount_usd: float,
    fx_rate: float,
    user_id: str | None = None,
    net_usd: float | None = None,
    recurring: bool = False,
    status: str = "succeeded",
    provider: str = "stripe",
) -> tuple[DonationRow, bool]:
    """Record a donation, **idempotent** on ``provider_ref``.

    Returns ``(row, created)`` — ``created`` is ``False`` when a row with this
    ``provider_ref`` already existed (e.g. a Stripe webhook retry), in which case
    the existing row is returned untouched. The unique index on ``provider_ref``
    is the hard backstop: if a concurrent caller inserts between our check and
    flush, the resulting ``IntegrityError`` is swallowed and the now-existing row
    returned. The insert runs in a SAVEPOINT so that swallow doesn't poison the
    caller's surrounding transaction.

    ``amount``/``currency`` are what Stripe charged; ``amount_usd``/``fx_rate``
    are the conversion captured at webhook time. ``user_id`` is ``None`` for
    anonymous donors.
    """
    existing = _get_by_ref(db, provider_ref)
    if existing is not None:
        return existing, False

    row = DonationRow(
        user_id=user_id,
        service=service,
        amount=amount,
        currency=currency.upper(),
        amount_usd=amount_usd,
        fx_rate=fx_rate,
        net_usd=net_usd,
        recurring=recurring,
        status=status,
        provider=provider,
        provider_ref=provider_ref,
    )
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError:
        # Lost a race with a concurrent insert of the same provider_ref; the
        # SAVEPOINT rolled back, so re-read and treat as already-recorded.
        existing = _get_by_ref(db, provider_ref)
        if existing is not None:
            return existing, False
        raise
    return row, True


def mark_refunded(db: Session, provider_ref: str) -> DonationRow | None:
    """Flip a donation to ``refunded`` so it drops out of aggregation.

    Idempotent and tolerant of unknown refs: returns the updated row, or
    ``None`` if no donation matches ``provider_ref`` (e.g. a refund for a charge
    that predates the ledger).
    """
    row = _get_by_ref(db, provider_ref)
    if row is None:
        return None
    row.status = "refunded"
    db.flush()
    return row


def get_donation(db: Session, provider_ref: str) -> DonationRow | None:
    """Return the donation with this ``provider_ref``, or ``None``."""
    return _get_by_ref(db, provider_ref)


def set_net_usd(
    db: Session, provider_ref: str, net_usd: float
) -> DonationRow | None:
    """Set ``net_usd`` (USD net of the Stripe fee) on a donation, **once**.

    Idempotent and order-tolerant: the Stripe fee lives on the charge's balance
    transaction, which Stripe creates slightly *after* the charge — so it is
    usually unavailable when ``checkout.session.completed`` fires and
    ``net_usd`` starts NULL. A later ``charge.updated`` backfills it via this
    helper. Returns ``None`` (a no-op) if the donation is unknown or already has
    a ``net_usd``, so repeated ``charge.updated`` deliveries don't clobber it.
    """
    row = _get_by_ref(db, provider_ref)
    if row is None or row.net_usd is not None:
        return None
    row.net_usd = net_usd
    db.flush()
    return row


def get_user_total_usd(
    db: Session, user_id: str, service: str | None = None
) -> float:
    """Sum of a user's succeeded donations in USD (refunds excluded)."""
    q = db.query(func.coalesce(func.sum(DonationRow.amount_usd), 0.0)).filter(
        DonationRow.user_id == user_id,
        DonationRow.status == "succeeded",
    )
    if service:
        q = q.filter(DonationRow.service == service)
    return float(q.scalar())


def get_year_total_usd(
    db: Session, year: int, service: str | None = None
) -> float:
    """Sum of succeeded donations in a calendar year, USD (refunds excluded).

    ``year`` is passed in by the caller (the app knows "now") so this stays a
    pure, deterministic query. The window is ``[Jan 1 year, Jan 1 year+1)`` in
    UTC, matching the tz-aware ``created_at`` column.
    """
    start = datetime(year, 1, 1, tzinfo=timezone.utc)
    end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    q = db.query(func.coalesce(func.sum(DonationRow.amount_usd), 0.0)).filter(
        DonationRow.status == "succeeded",
        DonationRow.created_at >= start,
        DonationRow.created_at < end,
    )
    if service:
        q = q.filter(DonationRow.service == service)
    return float(q.scalar())
