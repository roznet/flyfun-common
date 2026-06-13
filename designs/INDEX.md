# flyfun-common

> Shared user management, authentication, and cross-subdomain SSO for flyfun FastAPI services

Install: `pip install -e ~/Developer/public/flyfun-common`

Related: flyfun-weather, flyfun-customs

## Modules

### auth
Google/Apple OAuth login, JWT session cookies, rolling sessions, cross-subdomain SSO via `.flyfun.aero` cookie domain, and post-login `?next=` redirects. Provides a mountable FastAPI auth router, the `SlidingSessionMiddleware`, and configuration helpers.
Key exports: `create_auth_router`, `SlidingSessionMiddleware`, `create_token`, `decode_token`, `COOKIE_NAME`, `get_jwt_secret`, `is_dev_mode`
→ Full doc: auth.md

### db
Shared SQLAlchemy models (UserRow, ApiTokenRow, CostLedgerRow, DonationRow), database engine singleton, and FastAPI dependencies for session management and authentication.
Key exports: `UserRow`, `ApiTokenRow`, `Base`, `get_db`, `current_user_id`, `init_shared_db`, `ensure_dev_user`, `SessionLocal`
→ Full doc: db.md

### payments
App-agnostic donation plumbing (Stripe): create Checkout Sessions (one-time + recurring), verify+parse webhooks, record donations idempotently, refunds, and aggregation. USD-canonical; the webhook is the source of truth. App-facing endpoints/UI/impact framing live in each consuming app.
Key exports: `create_checkout_session`, `verify_webhook_event`, `extract_donation_from_session`, `retrieve_net_ratio`, `record_donation`, `mark_refunded`, `get_user_total_usd`, `get_year_total_usd`
→ Full doc: payments.md

### fx
USD↔local currency conversion via the key-less Frankfurter (ECB) API, with an in-memory daily cache and stale-cache fallback on fetch failure. Powers at-webhook conversion to `amount_usd` and the display `fx` block.
Key exports: `to_usd`, `from_usd`, `get_rate`, `fx_block`, `clear_cache`, `FxUnavailable`
→ Full doc: fx.md

### autorouter
OAuth2 account linking for Autorouter API access (NOTAMs, flight plans, weather). Service-linking flow for already-authenticated users — not a login provider.
Key exports: `create_autorouter_router`, `get_autorouter_token`
→ Full doc: autorouter.md

### mcp-oauth
OAuth 2.1 authorization server for MCP connectors (claude.ai, Cowork). Dynamic client registration, PKCE, consent screen. Issues `api_tokens` tied to user accounts.
Key exports: `create_oauth_router`, `OAuthClientRow`, `OAuthAuthorizationCodeRow`
→ Full doc: mcp-oauth.md
