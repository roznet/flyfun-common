"""Shared donation/payment plumbing (Stripe) — app-agnostic.

App-facing endpoints, impact framing, and UI live in each consuming app
(e.g. flyfun-weather). This package only handles the money mechanics:

- ``stripe_client``  — create Checkout Sessions, verify+parse webhooks, fee lookup
- ``donations``      — record_donation() (idempotent), refunds, aggregation queries

FX conversion lives in :mod:`flyfun_common.fx`. The ``donation_ledger`` table is
created by each app's own Alembic migration (this library ships no migrations).
"""

from flyfun_common.payments.donations import (  # noqa: F401
    get_user_total_usd,
    get_year_total_usd,
    mark_refunded,
    record_donation,
)
from flyfun_common.payments.stripe_client import (  # noqa: F401
    CheckoutDonation,
    StripeNotConfigured,
    create_checkout_session,
    extract_donation_from_session,
    retrieve_net_ratio,
    verify_webhook_event,
)

__all__ = [
    "CheckoutDonation",
    "StripeNotConfigured",
    "create_checkout_session",
    "extract_donation_from_session",
    "get_user_total_usd",
    "get_year_total_usd",
    "mark_refunded",
    "record_donation",
    "retrieve_net_ratio",
    "verify_webhook_event",
]
