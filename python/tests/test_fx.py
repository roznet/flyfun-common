"""Tests for FX conversion: cache, conversion math, and failure fallback."""

import pytest

from flyfun_common import fx


@pytest.fixture(autouse=True)
def _clean_cache():
    fx.clear_cache()
    yield
    fx.clear_cache()


def _stub_rates(monkeypatch, rates, as_of="2026-06-10"):
    calls = {"n": 0}

    def fake_fetch():
        calls["n"] += 1
        full = {"USD": 1.0, **rates}
        return full, as_of

    monkeypatch.setattr(fx, "_fetch_rates", fake_fetch)
    return calls


def test_usd_short_circuits_without_fetch(monkeypatch):
    calls = _stub_rates(monkeypatch, {"EUR": 0.9})
    rate, as_of = fx.get_rate("USD")
    assert rate == 1.0
    assert calls["n"] == 0  # no network for USD


def test_to_usd_and_from_usd(monkeypatch):
    _stub_rates(monkeypatch, {"EUR": 0.9})
    amount_usd, rate, as_of = fx.to_usd(9.0, "EUR")
    assert rate == pytest.approx(0.9)
    assert amount_usd == pytest.approx(10.0)  # 9 EUR / 0.9 = 10 USD
    assert as_of == "2026-06-10"

    local, rate2, _ = fx.from_usd(10.0, "EUR")
    assert local == pytest.approx(9.0)
    assert rate2 == pytest.approx(0.9)


def test_case_insensitive_currency(monkeypatch):
    _stub_rates(monkeypatch, {"GBP": 0.8})
    amount_usd, rate, _ = fx.to_usd(8.0, "gbp")
    assert rate == pytest.approx(0.8)
    assert amount_usd == pytest.approx(10.0)


def test_cache_fetches_once_per_day(monkeypatch):
    calls = _stub_rates(monkeypatch, {"EUR": 0.9, "GBP": 0.8})
    fx.get_rate("EUR")
    fx.get_rate("EUR")
    fx.get_rate("GBP")
    assert calls["n"] == 1  # one fetch covers all currencies for the day


def test_unknown_currency_raises(monkeypatch):
    _stub_rates(monkeypatch, {"EUR": 0.9})
    with pytest.raises(fx.FxUnavailable):
        fx.get_rate("XYZ")


def test_no_cache_and_fetch_fails_raises(monkeypatch):
    def boom():
        raise RuntimeError("network down")

    monkeypatch.setattr(fx, "_fetch_rates", boom)
    with pytest.raises(fx.FxUnavailable):
        fx.get_rate("EUR")


def test_falls_back_to_stale_cache_on_failure(monkeypatch):
    # First, a successful fetch populates the cache for "today".
    _stub_rates(monkeypatch, {"EUR": 0.9}, as_of="2026-06-09")
    fx.get_rate("EUR")

    # Now simulate next-day fetch failing: clear the day guard but keep rates,
    # and make the fetch raise. Conversion should still succeed on stale rates.
    fx._cache.fetched_on = None
    monkeypatch.setattr(fx, "_fetch_rates", lambda: (_ for _ in ()).throw(RuntimeError()))
    rate, as_of = fx.get_rate("EUR")
    assert rate == pytest.approx(0.9)  # stale-but-usable
    assert as_of == "2026-06-09"


def test_fx_block_shape(monkeypatch):
    _stub_rates(monkeypatch, {"EUR": 0.92}, as_of="2026-06-10")
    block = fx.fx_block("eur")
    assert block == {"currency": "EUR", "rate": pytest.approx(0.92), "as_of": "2026-06-10"}
