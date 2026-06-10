"""USD <-> local currency conversion via the Frankfurter API (ECB daily rates).

Frankfurter (https://frankfurter.dev) is free and key-less, serving the ECB's
daily reference rates. Rates are cached **in memory, keyed by UTC date**: the
first call each day fetches, the rest reuse it. On a fetch failure — network
error, or a weekend/holiday with no fresh ECB publication — we fall back to the
last successfully cached rates rather than failing the conversion.

USD is the canonical accounting currency. ``fx_rate`` throughout is expressed as
**units of the foreign currency per 1 USD** (so 1 USD = 0.92 EUR → rate 0.92),
and ``amount_usd = amount / fx_rate``. This module powers both the at-webhook
conversion of a charged amount to ``amount_usd`` and the display ``fx`` block.
"""

from __future__ import annotations

from datetime import date, datetime, timezone

import httpx

_FRANKFURTER_URL = "https://api.frankfurter.dev/v1/latest"
_TIMEOUT = 10.0


class FxUnavailable(RuntimeError):
    """No rate could be obtained (fetch failed and nothing is cached)."""


class _Cache:
    """In-memory rate cache. Module-global singleton; reset via :func:`clear_cache`."""

    rates: dict[str, float] | None = None  # units per 1 USD, includes "USD": 1.0
    as_of: str | None = None  # ECB rate date, ISO (may lag on weekends/holidays)
    fetched_on: date | None = None  # UTC date of our last fetch attempt


_cache = _Cache()


def clear_cache() -> None:
    """Drop the cached rates (test hook / forced refresh)."""
    _cache.rates = None
    _cache.as_of = None
    _cache.fetched_on = None


def _today() -> date:
    return datetime.now(timezone.utc).date()


def _fetch_rates() -> tuple[dict[str, float], str]:
    """Fetch ``1 USD -> currency`` rates from Frankfurter. Raises on failure."""
    resp = httpx.get(_FRANKFURTER_URL, params={"base": "USD"}, timeout=_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    rates = {k.upper(): float(v) for k, v in data["rates"].items()}
    rates["USD"] = 1.0  # base is implicit in the response
    return rates, data["date"]


def _ensure_rates() -> None:
    """Make sure today's rates are loaded, with graceful degradation.

    Fetches at most once per UTC day. On failure: keep using the last cached
    rates if we have them (and back off until tomorrow so an outage doesn't get
    hammered); otherwise raise :class:`FxUnavailable`.
    """
    today = _today()
    if _cache.rates is not None and _cache.fetched_on == today:
        return
    try:
        rates, as_of = _fetch_rates()
        _cache.rates = rates
        _cache.as_of = as_of
        _cache.fetched_on = today
    except Exception as exc:  # network, HTTP, or malformed payload
        if _cache.rates is None:
            raise FxUnavailable(f"FX fetch failed and no cached rates: {exc}") from exc
        # Stale-but-usable: back off for the rest of the day, keep old rates.
        _cache.fetched_on = today


def get_rate(currency: str) -> tuple[float, str]:
    """Return ``(rate, as_of)`` where rate = units of ``currency`` per 1 USD.

    USD short-circuits to ``1.0`` with no network call (and reuses the cached
    ``as_of`` date if one is loaded). Raises :class:`FxUnavailable` if a
    non-USD currency has no rate available.
    """
    currency = currency.upper()
    if currency == "USD":
        return 1.0, (_cache.as_of or _today().isoformat())
    _ensure_rates()
    assert _cache.rates is not None  # _ensure_rates raises otherwise
    rate = _cache.rates.get(currency)
    if rate is None:
        raise FxUnavailable(f"no FX rate for {currency}")
    return rate, _cache.as_of or _today().isoformat()


def to_usd(amount: float, currency: str) -> tuple[float, float, str]:
    """Convert ``amount`` in ``currency`` to USD.

    Returns ``(amount_usd, fx_rate, as_of)`` where ``fx_rate`` is units per USD,
    so ``amount_usd == amount / fx_rate``.
    """
    rate, as_of = get_rate(currency)
    return amount / rate, rate, as_of


def from_usd(amount_usd: float, currency: str) -> tuple[float, float, str]:
    """Convert a USD amount into ``currency`` (for display).

    Returns ``(amount_local, fx_rate, as_of)`` where ``fx_rate`` is units per USD.
    """
    rate, as_of = get_rate(currency)
    return amount_usd * rate, rate, as_of


def fx_block(currency: str) -> dict:
    """Build the display ``fx`` block carried on API responses.

    ``{"currency": "EUR", "rate": 0.92, "as_of": "2026-06-10"}`` — rate is units
    per USD; the frontend formats USD-canonical amounts into the viewer's currency.
    """
    rate, as_of = get_rate(currency)
    return {"currency": currency.upper(), "rate": rate, "as_of": as_of}
