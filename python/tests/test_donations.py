"""Tests for the donation ledger: record (idempotent), refund, aggregation."""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from flyfun_common.db.models import Base, DonationRow
from flyfun_common.payments.donations import (
    get_donation,
    get_user_total_usd,
    get_year_total_usd,
    mark_refunded,
    record_donation,
    set_net_usd,
)


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()
    engine.dispose()


def _donate(db, ref, **kw):
    params = dict(
        provider_ref=ref,
        service="flyfun-weather",
        amount=10.0,
        currency="EUR",
        amount_usd=11.0,
        fx_rate=0.91,
        user_id="u1",
    )
    params.update(kw)
    return record_donation(db, **params)


def test_record_returns_created(db):
    row, created = _donate(db, "pi_1")
    assert created is True
    assert row.id is not None
    assert row.status == "succeeded"
    assert row.currency == "EUR"
    assert row.amount_usd == pytest.approx(11.0)


def test_idempotent_on_provider_ref(db):
    row1, created1 = _donate(db, "pi_1", amount_usd=11.0)
    # A Stripe webhook retry with the same ref — even with different numbers —
    # must NOT create a second row, and returns the original untouched.
    row2, created2 = _donate(db, "pi_1", amount_usd=999.0)
    assert created1 is True
    assert created2 is False
    assert row2.id == row1.id
    assert row2.amount_usd == pytest.approx(11.0)  # original kept
    assert db.query(DonationRow).count() == 1


def test_currency_uppercased(db):
    row, _ = _donate(db, "pi_lower", currency="gbp")
    assert row.currency == "GBP"


def test_anonymous_donation(db):
    row, created = _donate(db, "pi_anon", user_id=None)
    assert created is True
    assert row.user_id is None


def test_refund_flips_status_and_drops_from_total(db):
    _donate(db, "pi_1", amount_usd=11.0)
    _donate(db, "pi_2", amount_usd=5.0)
    assert get_user_total_usd(db, "u1") == pytest.approx(16.0)

    refunded = mark_refunded(db, "pi_1")
    assert refunded is not None
    assert refunded.status == "refunded"
    assert get_user_total_usd(db, "u1") == pytest.approx(5.0)


def test_refund_unknown_ref_returns_none(db):
    assert mark_refunded(db, "pi_does_not_exist") is None


def test_get_donation(db):
    _donate(db, "pi_1")
    assert get_donation(db, "pi_1").provider_ref == "pi_1"
    assert get_donation(db, "nope") is None


def test_set_net_usd_backfills_once(db):
    row, _ = _donate(db, "pi_1")
    assert row.net_usd is None  # starts empty (balance txn not ready at record time)
    updated = set_net_usd(db, "pi_1", 23.4)
    assert updated is not None
    assert updated.net_usd == pytest.approx(23.4)
    # Idempotent: a later charge.updated must NOT clobber the existing value.
    again = set_net_usd(db, "pi_1", 99.9)
    assert again is None
    assert get_donation(db, "pi_1").net_usd == pytest.approx(23.4)


def test_set_net_usd_unknown_ref_returns_none(db):
    assert set_net_usd(db, "pi_missing", 1.0) is None


def test_user_total_service_filter(db):
    _donate(db, "pi_w", service="flyfun-weather", amount_usd=10.0)
    _donate(db, "pi_m", service="flyfun-maps", amount_usd=4.0)
    assert get_user_total_usd(db, "u1") == pytest.approx(14.0)
    assert get_user_total_usd(db, "u1", service="flyfun-maps") == pytest.approx(4.0)


def test_user_total_empty_is_zero(db):
    assert get_user_total_usd(db, "nobody") == pytest.approx(0.0)


def test_year_total_excludes_other_years_and_refunds(db):
    this_row, _ = _donate(db, "pi_this", amount_usd=10.0)
    old_row, _ = _donate(db, "pi_old", amount_usd=100.0)
    old_row.created_at = datetime(2020, 6, 1, tzinfo=timezone.utc)
    refunded_row, _ = _donate(db, "pi_ref", amount_usd=50.0)
    refunded_row.status = "refunded"
    db.flush()

    year = this_row.created_at.year
    assert get_year_total_usd(db, year) == pytest.approx(10.0)
    assert get_year_total_usd(db, 2020) == pytest.approx(100.0)


def test_year_total_service_filter(db):
    a, _ = _donate(db, "pi_a", service="flyfun-weather", amount_usd=7.0)
    _donate(db, "pi_b", service="flyfun-maps", amount_usd=3.0)
    year = a.created_at.year
    assert get_year_total_usd(db, year) == pytest.approx(10.0)
    assert get_year_total_usd(db, year, service="flyfun-weather") == pytest.approx(7.0)
