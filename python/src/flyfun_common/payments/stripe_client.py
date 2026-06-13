"""Stripe SDK wrapper: Checkout Session creation + webhook verification.

Thin and app-agnostic. The only Stripe surfaces donations need:

- create a hosted **Checkout Session** (one-time or recurring),
- **verify** an incoming webhook's signature and parse the event,
- pull a charge's **fee ratio** so the caller can record a USD-net figure.

Secrets come from the environment (``STRIPE_SECRET_KEY`` /
``STRIPE_WEBHOOK_SECRET``). ``STRIPE_API_VERSION`` is pinned here so the
responses to our **outbound** calls (``Session.create``,
``PaymentIntent.retrieve``) deserialize against a known shape — notably the
balance-transaction fields :func:`retrieve_net_ratio` reads.

It does **not** govern the shape of incoming **webhook event payloads**:
``construct_event`` only verifies the signature and parses the JSON as-is, and
Stripe serializes the event using the *webhook endpoint's* configured API
version (or the account default), not the SDK's. To keep
:func:`extract_donation_from_session` parsing stable in production, the webhook
endpoint itself must be created with a pinned ``api_version`` (Stripe Dashboard,
or the ``api_version`` arg when registering the endpoint via API). That is part
of the Stripe-account setup tracked in flyfun-weather#186.

The donation flow is **recurring-capable but one-time-first**: the session
factory accepts ``recurring=True`` (``mode=subscription``) so callers never need
a signature change later, but the subscription *lifecycle* webhooks
(``invoice.paid``, ``customer.subscription.deleted``) are intentionally not
handled yet — that is a tracked follow-up.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import stripe

# Pin to the API version this SDK major (15.x) ships with, so the responses to
# our outbound calls (Session.create, PaymentIntent.retrieve) keep a known
# shape. This does NOT affect incoming webhook payload shapes — pin those on the
# webhook endpoint itself (see module docstring).
STRIPE_API_VERSION = "2026-05-27.dahlia"

# Currencies Stripe treats as having no minor unit — `unit_amount` is the whole
# amount, not amount*100. https://stripe.com/docs/currencies#zero-decimal
ZERO_DECIMAL_CURRENCIES = frozenset(
    {
        "BIF", "CLP", "DJF", "GNF", "JPY", "KMF", "KRW", "MGA",
        "PYG", "RWF", "UGX", "VND", "VUV", "XAF", "XOF", "XPF",
    }
)

# Re-export so callers can `except stripe_client.SignatureVerificationError`
# without importing stripe directly.
SignatureVerificationError = stripe.SignatureVerificationError


class StripeNotConfigured(RuntimeError):
    """A Stripe call was attempted without the required env secret set."""


@dataclass(frozen=True)
class CheckoutDonation:
    """The donation-relevant fields pulled from a completed Checkout Session.

    ``amount`` is in major units of ``currency`` (e.g. 10.0 EUR). The caller
    converts to USD (see :mod:`flyfun_common.fx`) and persists via
    :func:`flyfun_common.payments.donations.record_donation`.
    """

    provider_ref: str  # PaymentIntent id (stable across charge + refund); session id fallback
    user_id: str | None
    service: str
    amount: float
    currency: str  # ISO 4217, uppercase
    recurring: bool
    payment_intent_id: str | None  # for the fee-ratio lookup; None for subscriptions


def _secret_key() -> str:
    key = os.environ.get("STRIPE_SECRET_KEY")
    if not key:
        raise StripeNotConfigured("STRIPE_SECRET_KEY is not set")
    return key


def _configure() -> None:
    """Point the SDK at our key + pinned API version for this call."""
    stripe.api_key = _secret_key()
    stripe.api_version = STRIPE_API_VERSION


def to_minor_units(amount: float, currency: str) -> int:
    """Convert a major-unit amount to the integer minor unit Stripe expects."""
    if currency.upper() in ZERO_DECIMAL_CURRENCIES:
        return int(round(amount))
    return int(round(amount * 100))


def from_minor_units(amount: int, currency: str) -> float:
    """Inverse of :func:`to_minor_units` — minor unit back to major units."""
    if currency.upper() in ZERO_DECIMAL_CURRENCIES:
        return float(amount)
    return amount / 100.0


def create_checkout_session(
    *,
    amount: float,
    currency: str,
    recurring: bool,
    success_url: str,
    cancel_url: str,
    service: str,
    user_id: str | None = None,
    customer_email: str | None = None,
) -> stripe.checkout.Session:
    """Create a hosted Stripe Checkout Session for a donation.

    ``amount`` is in major units of ``currency``. ``recurring=False`` →
    one-time (``mode=payment``); ``recurring=True`` → a monthly subscription
    (``mode=subscription``). ``user_id`` (when logged in) and ``service`` ride
    along in metadata / ``client_reference_id`` so the webhook can attribute the
    donation; anonymous donations are allowed (``user_id=None``).
    """
    _configure()
    price_data: dict = {
        "currency": currency.lower(),
        "unit_amount": to_minor_units(amount, currency),
        "product_data": {"name": "Donation to flyfun"},
    }
    mode = "payment"
    if recurring:
        mode = "subscription"
        price_data["recurring"] = {"interval": "month"}

    params: dict = {
        "mode": mode,
        "line_items": [{"price_data": price_data, "quantity": 1}],
        "success_url": success_url,
        "cancel_url": cancel_url,
        "metadata": {"service": service, "user_id": user_id or ""},
    }
    if user_id:
        params["client_reference_id"] = user_id
    if customer_email:
        params["customer_email"] = customer_email
    return stripe.checkout.Session.create(**params)


def verify_webhook_event(payload: bytes, sig_header: str) -> stripe.Event:
    """Verify a webhook payload's signature and return the parsed event.

    Raises :class:`StripeNotConfigured` if ``STRIPE_WEBHOOK_SECRET`` is unset,
    :class:`stripe.SignatureVerificationError` on a bad/forged/expired
    signature, and ``ValueError`` on malformed JSON. This is the source of
    truth — never record a donation from the client redirect.
    """
    secret = os.environ.get("STRIPE_WEBHOOK_SECRET")
    if not secret:
        raise StripeNotConfigured("STRIPE_WEBHOOK_SECRET is not set")
    return stripe.Webhook.construct_event(payload, sig_header, secret)


def extract_donation_from_session(session: dict) -> CheckoutDonation:
    """Pull donation fields out of a ``checkout.session.completed`` object.

    ``provider_ref`` is the PaymentIntent id — stable across the charge and a
    later ``charge.refunded`` — falling back to the session id when no
    PaymentIntent is present (subscription mode). Accepts either a Stripe object
    or a plain dict (both support ``[]``/``.get``).
    """
    payment_intent_id = session.get("payment_intent")
    provider_ref = payment_intent_id or session.get("id")
    metadata = session.get("metadata") or {}
    # client_reference_id is the primary attribution; metadata is the backup.
    user_id = session.get("client_reference_id") or metadata.get("user_id") or None
    currency = (session.get("currency") or "usd").upper()
    amount_total = session.get("amount_total") or 0
    return CheckoutDonation(
        provider_ref=provider_ref,
        user_id=user_id,
        service=metadata.get("service") or "",
        amount=from_minor_units(amount_total, currency),
        currency=currency,
        recurring=session.get("mode") == "subscription",
        payment_intent_id=payment_intent_id,
    )


def retrieve_net_ratio(payment_intent_id: str) -> float | None:
    """Return net/gross for a PaymentIntent's charge, or ``None`` if unknown.

    The Stripe fee lives on the charge's balance transaction, not on the
    Checkout Session, so we retrieve the PaymentIntent with the balance
    transaction expanded. ``amount``/``net`` are in the account's settlement
    currency, but their **ratio** is currency-agnostic — the caller multiplies
    ``amount_usd`` by it to get ``net_usd``, keeping USD canonical.
    """
    _configure()
    pi = stripe.PaymentIntent.retrieve(
        payment_intent_id, expand=["latest_charge.balance_transaction"]
    )
    charge = pi.get("latest_charge")
    if not charge:
        return None
    bt = charge.get("balance_transaction")
    if not bt:
        return None
    gross = bt.get("amount")
    net = bt.get("net")
    if not gross:
        return None
    return net / gross
