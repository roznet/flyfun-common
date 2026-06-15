"""Tests for the Stripe wrapper — fully mocked, no live API calls."""

import pytest

import stripe

from flyfun_common.payments import stripe_client as sc


# --- minor-unit conversion ------------------------------------------------


def test_minor_units_standard_currency():
    assert sc.to_minor_units(10.0, "EUR") == 1000
    assert sc.to_minor_units(9.99, "USD") == 999
    assert sc.from_minor_units(1000, "EUR") == pytest.approx(10.0)


def test_minor_units_zero_decimal_currency():
    # JPY has no minor unit — 1000 yen is unit_amount 1000, not 100000.
    assert sc.to_minor_units(1000, "JPY") == 1000
    assert sc.from_minor_units(1000, "JPY") == pytest.approx(1000.0)


# --- create_checkout_session ----------------------------------------------


@pytest.fixture
def captured_create(monkeypatch):
    """Capture the params passed to stripe.checkout.Session.create."""
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_x")
    captured = {}

    def fake_create(**params):
        captured.update(params)
        return {"id": "cs_test_1", "url": "https://checkout.stripe.test/cs_test_1"}

    monkeypatch.setattr(stripe.checkout.Session, "create", staticmethod(fake_create))
    return captured


def test_create_one_time_session(captured_create):
    sc.create_checkout_session(
        amount=10.0,
        currency="EUR",
        recurring=False,
        success_url="https://x/ok",
        cancel_url="https://x/no",
        service="flyfun-weather",
        user_id="u1",
    )
    assert captured_create["mode"] == "payment"
    line = captured_create["line_items"][0]
    assert line["price_data"]["currency"] == "eur"
    assert line["price_data"]["unit_amount"] == 1000
    assert "recurring" not in line["price_data"]
    assert captured_create["client_reference_id"] == "u1"
    assert captured_create["metadata"] == {"service": "flyfun-weather", "user_id": "u1"}


def test_create_recurring_session(captured_create):
    sc.create_checkout_session(
        amount=5.0,
        currency="USD",
        recurring=True,
        success_url="https://x/ok",
        cancel_url="https://x/no",
        service="flyfun-weather",
    )
    assert captured_create["mode"] == "subscription"
    line = captured_create["line_items"][0]
    assert line["price_data"]["recurring"] == {"interval": "month"}
    # anonymous: no client_reference_id, empty user_id in metadata
    assert "client_reference_id" not in captured_create
    assert captured_create["metadata"]["user_id"] == ""


def test_create_session_without_key_raises(monkeypatch):
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    with pytest.raises(sc.StripeNotConfigured):
        sc.create_checkout_session(
            amount=10.0, currency="EUR", recurring=False,
            success_url="https://x/ok", cancel_url="https://x/no",
            service="flyfun-weather",
        )


# --- verify_webhook_event -------------------------------------------------


def test_verify_without_secret_raises(monkeypatch):
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
    with pytest.raises(sc.StripeNotConfigured):
        sc.verify_webhook_event(b"{}", "sig")


def test_verify_delegates_to_construct_event(monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_x")
    seen = {}

    def fake_construct(payload, sig_header, secret):
        seen.update(payload=payload, sig=sig_header, secret=secret)
        return {"type": "checkout.session.completed"}

    monkeypatch.setattr(stripe.Webhook, "construct_event", staticmethod(fake_construct))
    event = sc.verify_webhook_event(b'{"x":1}', "t=1,v1=abc")
    assert event["type"] == "checkout.session.completed"
    assert seen == {"payload": b'{"x":1}', "sig": "t=1,v1=abc", "secret": "whsec_x"}


def test_verify_bad_signature_propagates(monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_x")

    def fake_construct(payload, sig_header, secret):
        raise stripe.SignatureVerificationError("bad sig", sig_header)

    monkeypatch.setattr(stripe.Webhook, "construct_event", staticmethod(fake_construct))
    with pytest.raises(stripe.SignatureVerificationError):
        sc.verify_webhook_event(b"{}", "bad")


# --- extract_donation_from_session ----------------------------------------


def test_extract_one_time_session():
    session = {
        "id": "cs_1",
        "payment_intent": "pi_1",
        "client_reference_id": "u1",
        "metadata": {"service": "flyfun-weather", "user_id": "u1"},
        "currency": "eur",
        "amount_total": 1000,
        "mode": "payment",
    }
    d = sc.extract_donation_from_session(session)
    assert d.provider_ref == "pi_1"  # PaymentIntent preferred
    assert d.payment_intent_id == "pi_1"
    assert d.user_id == "u1"
    assert d.service == "flyfun-weather"
    assert d.amount == pytest.approx(10.0)
    assert d.currency == "EUR"
    assert d.recurring is False


def test_extract_anonymous_falls_back_to_session_id():
    session = {
        "id": "cs_2",
        "payment_intent": None,
        "client_reference_id": None,
        "metadata": {"service": "flyfun-weather"},
        "currency": "usd",
        "amount_total": 500,
        "mode": "subscription",
    }
    d = sc.extract_donation_from_session(session)
    assert d.provider_ref == "cs_2"  # no PI → session id
    assert d.payment_intent_id is None
    assert d.user_id is None
    assert d.amount == pytest.approx(5.0)
    assert d.recurring is True


# --- retrieve_net_ratio ---------------------------------------------------


def _mock_pi(monkeypatch, pi_obj):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_x")
    monkeypatch.setattr(
        stripe.PaymentIntent, "retrieve",
        staticmethod(lambda pid, expand=None: pi_obj),
    )


def test_net_ratio_computes_from_balance_transaction(monkeypatch):
    _mock_pi(monkeypatch, {
        "latest_charge": {"balance_transaction": {"amount": 1000, "net": 967}},
    })
    ratio = sc.retrieve_net_ratio("pi_1")
    assert ratio == pytest.approx(0.967)


def test_net_ratio_none_when_no_charge(monkeypatch):
    _mock_pi(monkeypatch, {"latest_charge": None})
    assert sc.retrieve_net_ratio("pi_1") is None


def test_net_ratio_none_when_no_balance_transaction(monkeypatch):
    _mock_pi(monkeypatch, {"latest_charge": {"balance_transaction": None}})
    assert sc.retrieve_net_ratio("pi_1") is None


# --- real StripeObject handling -------------------------------------------
# Regression: in stripe 15.x a StripeObject is NOT a dict and has no `.get()`.
# The earlier mocks all fed plain dicts, so the `.get()`-based code passed tests
# but broke against real API/webhook objects. These tests use genuine
# StripeObjects to lock in dict-coercion.


def test_verify_returns_plain_dict_from_real_event(monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_x")
    real_event = stripe.Event.construct_from(
        {"type": "checkout.session.completed",
         "data": {"object": {"id": "cs_1", "currency": "eur"}}},
        "sk_test",
    )
    assert not isinstance(real_event, dict) and not hasattr(real_event, "get")
    monkeypatch.setattr(stripe.Webhook, "construct_event",
                        staticmethod(lambda *a, **k: real_event))
    event = sc.verify_webhook_event(b"{}", "sig")
    # Must be a plain dict with working .get() / nested access.
    assert isinstance(event, dict)
    assert event.get("type") == "checkout.session.completed"
    assert event["data"]["object"].get("currency") == "eur"


def test_extract_from_real_stripe_object():
    session = stripe.checkout.Session.construct_from(
        {"id": "cs_1", "payment_intent": "pi_1", "client_reference_id": "u1",
         "metadata": {"service": "flyfun-weather", "user_id": "u1"},
         "currency": "eur", "amount_total": 1000, "mode": "payment"},
        "sk_test",
    )
    d = sc.extract_donation_from_session(session)  # would AttributeError without coercion
    assert d.provider_ref == "pi_1"
    assert d.amount == pytest.approx(10.0)
    assert d.currency == "EUR"
    assert d.service == "flyfun-weather"


def test_net_ratio_from_real_stripe_object(monkeypatch):
    pi = stripe.PaymentIntent.construct_from(
        {"id": "pi_1", "latest_charge": {"balance_transaction": {"amount": 1000, "net": 967}}},
        "sk_test",
    )
    _mock_pi(monkeypatch, pi)
    assert sc.retrieve_net_ratio("pi_1") == pytest.approx(0.967)
