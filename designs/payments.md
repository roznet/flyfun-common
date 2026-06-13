# Payments / Donations

> App-agnostic Stripe plumbing for voluntary donations across flyfun apps

## Intent

Provide the reusable, cross-app money mechanics for **voluntary donations** —
the same way `cost_ledger` provides shared cost tracking. This module handles
*only* the plumbing: creating Stripe Checkout Sessions, verifying and parsing
webhooks, and recording/aggregating donations. The app-facing pieces — HTTP
endpoints, the donate UI, and "impact" framing ("covers 1 user for ~8 months")
— live in each consuming app (e.g. flyfun-weather), not here.

Donations are tracked in their own `donation_ledger` (see [db.md](./db.md)),
**not** the cost ledger: money-in carries a charged currency, a Stripe
reference, and a refundable status — a different shape from the cost ledger's
"always positive USD = cost" invariant.

## Architecture

```
payments/
├── stripe_client.py   # Stripe SDK wrapper: Checkout Session, webhook verify/parse, fee lookup
└── donations.py       # record_donation() (idempotent), refunds, aggregation queries
fx.py                  # USD<->local conversion (see fx.md)
db/models.py           # DonationRow (donation_ledger)
```

### Money flow

```
Donor picks amount + currency on the app's web donate page
  → app calls create_checkout_session(...) → hosted Stripe Checkout
  → donor pays on Stripe, redirected back to a thank-you page
  → Stripe POSTs a webhook (the SOURCE OF TRUTH — never trust the redirect)
      → verify_webhook_event(payload, sig)            # signature check
      → extract_donation_from_session(session)        # pull charged fields
      → fx.to_usd(amount, currency)                    # convert at webhook time
      → retrieve_net_ratio(payment_intent_id)          # optional: Stripe fee
      → record_donation(...)                            # idempotent on provider_ref
  → charge.refunded webhook → mark_refunded(provider_ref)
```

The webhook is the only place a donation is written. It is **idempotent on
`provider_ref`** so Stripe's retries (and at-least-once delivery) never
double-count.

### Recurring: capable, one-time-first

`create_checkout_session(recurring=True)` issues a `mode=subscription` session,
so the signature never has to change later. But the subscription *lifecycle*
webhooks (`invoice.paid` per-period rows, `customer.subscription.deleted`) and
the cancel / Customer-Portal UI are **intentionally not handled yet** — a
tracked follow-up. One-time (`mode=payment`) is the supported path today.

## Key functions

**`stripe_client`**

| Function | Purpose |
|----------|---------|
| `create_checkout_session(*, amount, currency, recurring, success_url, cancel_url, service, user_id=None, customer_email=None)` | Create a hosted Checkout Session. `amount` is in major units; `user_id`/`service` ride along for attribution. Anonymous allowed. |
| `verify_webhook_event(payload, sig_header) -> stripe.Event` | Verify the signature (`STRIPE_WEBHOOK_SECRET`) and parse the event. Raises on bad/forged signature. |
| `extract_donation_from_session(session) -> CheckoutDonation` | Pull `provider_ref` (PaymentIntent id, session-id fallback), `user_id`, `service`, `amount`, `currency`, `recurring`. |
| `retrieve_net_ratio(payment_intent_id) -> float \| None` | net/gross from the charge's balance transaction, for `net_usd`. Currency-agnostic ratio. |

**`donations`**

| Function | Purpose |
|----------|---------|
| `record_donation(db, *, provider_ref, service, amount, currency, amount_usd, fx_rate, user_id=None, net_usd=None, recurring=False, status="succeeded", provider="stripe") -> (row, created)` | Idempotent on `provider_ref` (SAVEPOINT-guarded race backstop). `created=False` when the ref already existed. |
| `mark_refunded(db, provider_ref) -> DonationRow \| None` | Flip status to `"refunded"` so it drops from aggregation. `None` if ref unknown. |
| `get_user_total_usd(db, user_id, service=None) -> float` | Sum of a user's succeeded donations (refunds excluded). |
| `get_year_total_usd(db, year, service=None) -> float` | Calendar-year community total in USD; `year` passed in by the caller. |

## Net (Stripe fee)

The Stripe fee lives on the charge's **balance transaction**, not on the
Checkout Session, so `retrieve_net_ratio` retrieves the PaymentIntent with the
balance transaction expanded. `amount`/`net` there are in the account's
*settlement* currency, but their **ratio** is currency-agnostic — the caller
multiplies `amount_usd` by it to get `net_usd`, keeping USD canonical.

## Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `STRIPE_SECRET_KEY` | Yes | SDK auth for outbound calls (`Session.create`, `PaymentIntent.retrieve`) |
| `STRIPE_WEBHOOK_SECRET` | Yes | Webhook signature verification |

## Migrations

flyfun-common ships **no migrations** — each consuming app creates the
`donation_ledger` table in its own Alembic migration (same as `cost_ledger`).
Use `op.create_table` (works on SQLite + MySQL without batch mode); keep
`provider_ref` at `VARCHAR(191)` for MySQL utf8mb4 unique-index limits.

## Key Choices

- **Separate `donation_ledger`, not `cost_ledger`**: money-in with
  currency/refund/Stripe-ref is a different shape from positive-USD money-out;
  keeps the cost ledger's "always positive = cost" invariant intact.
- **USD canonical, display-only conversion**: convert once at webhook time and
  store `amount_usd` + `fx_rate`; historical totals never drift with FX.
- **Webhook is source of truth**: never record from the client redirect;
  idempotent on `provider_ref`.
- **Anonymous donations allowed**: `user_id` nullable; attributed when logged in.
- **App-agnostic**: endpoints, impact framing, and UI belong to each app.

## Gotchas

- **API-version pinning is asymmetric.** `STRIPE_API_VERSION` (set on the SDK)
  pins only the shape of *outbound*-call responses (e.g. the balance-transaction
  fields `retrieve_net_ratio` reads). It does **not** govern incoming **webhook
  payload** shapes — Stripe serializes those using the *webhook endpoint's*
  configured version. To keep `extract_donation_from_session` stable in
  production, pin the version on the **webhook endpoint** itself (Dashboard, or
  the `api_version` arg when registering the endpoint via API).
- `record_donation` returns `(row, created)` — check `created` before sending
  any side effect (thank-you email, etc.) so retries don't re-fire it.
- Zero-decimal currencies (JPY, KRW, …) have no minor unit; `to_minor_units`
  handles the `unit_amount` conversion — don't multiply by 100 yourself.

## References

- Implementation: `src/flyfun_common/payments/stripe_client.py`, `src/flyfun_common/payments/donations.py`
- FX conversion: [fx.md](./fx.md)
- DonationRow model: [db.md](./db.md)
- Cross-app cost tracking (sibling pattern): [db.md](./db.md) `cost_ledger`
