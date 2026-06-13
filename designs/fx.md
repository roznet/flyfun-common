# FX (Currency Conversion)

> USD↔local conversion via the key-less Frankfurter (ECB) API, with a daily cache

## Intent

USD is the canonical accounting currency across flyfun apps (costs and
donations are stored in USD). This module converts between USD and a donor's /
viewer's local currency for two jobs:

1. **At webhook time** — convert a charged `amount`/`currency` to `amount_usd`
   so the stored donation total never drifts with the exchange rate.
2. **For display** — produce an `fx` block so API responses (which stay
   USD-canonical) can be rendered in the viewer's currency by the frontend.

## Architecture

```
fx.py   # _fetch_rates(), in-memory date-keyed cache, get_rate/to_usd/from_usd, fx_block
```

Rates come from **Frankfurter** (`https://api.frankfurter.dev/v1/latest`) — the
ECB's daily reference rates, free and **key-less**. We request `base=USD`, so
the returned rates are "units of currency per 1 USD".

### Caching & fallback

- Rates are cached **in memory, keyed by UTC date**: the first call each day
  fetches; the rest reuse it (one HTTP call per process per day).
- On a fetch failure — network error, or a weekend/holiday with no fresh ECB
  publication — we **fall back to the last successfully cached rates** rather
  than failing the conversion, and back off retrying until the next day.
- If the very first fetch fails (no cache at all), `get_rate` raises
  `FxUnavailable`. USD always short-circuits to `1.0` with no network call.

The cache is process-local (a module-global singleton); a restart re-fetches.
There is intentionally **no `fx_rates` DB table** — the data is tiny and cheap
to refetch.

## Convention

`fx_rate` everywhere is **units of the foreign currency per 1 USD** (so
1 USD = 0.92 EUR → rate `0.92`), and therefore:

```
amount_usd = amount / fx_rate
amount_local = amount_usd * fx_rate
```

## Key functions

| Function | Returns | Purpose |
|----------|---------|---------|
| `get_rate(currency) -> (rate, as_of)` | rate = units per USD | Raw rate + ECB date. USD → `1.0`. |
| `to_usd(amount, currency) -> (amount_usd, fx_rate, as_of)` | | Convert a charged amount to USD (webhook time). |
| `from_usd(amount_usd, currency) -> (amount_local, fx_rate, as_of)` | | Convert USD to local (display). |
| `fx_block(currency) -> {"currency", "rate", "as_of"}` | | The display block carried on API responses. |
| `clear_cache()` | | Drop cached rates (test hook / forced refresh). |
| `FxUnavailable` | exception | Raised when no rate is obtainable and nothing is cached. |

## Key Choices

- **Frankfurter / ECB**: free, key-less, EUR-based — a natural fit for an
  EU-primary app. No API key to manage or rotate.
- **In-memory daily cache, no table**: the rate set is small and cheap to
  refetch; a DB table would be over-engineering. (A DB cache could be added later
  if cross-process consistency ever matters.)
- **Stale-but-usable on failure**: a transient outage degrades gracefully to
  yesterday's rate instead of failing a donation conversion.
- **USD canonical**: only stored values are USD; this module is the boundary,
  never a second source of truth.

## Gotchas

- The legacy `api.frankfurter.app` host no longer returns JSON — use
  `api.frankfurter.dev/v1/latest`.
- Weekends/holidays have no new ECB publication; `as_of` will lag the current
  date — that's expected, not a bug.
- The cache is per-process. In a multi-worker deployment each worker fetches
  once per day independently.

## References

- Implementation: `src/flyfun_common/fx.py`
- Consumer: [payments.md](./payments.md) (`record_donation` conversion + display `fx` block)
