# Auth Module

> Google/Apple OAuth, magic-link email, JWT sessions, and cross-subdomain SSO for all flyfun services

## Intent

Provide a single authentication layer shared by all flyfun FastAPI apps. A user who logs in on `weather.flyfun.aero` is automatically authenticated on `forms.flyfun.aero` (and any future service) without logging in again.

This module should NOT contain app-specific logic (welcome emails, credit provisioning). Apps hook into user creation via the `on_new_user` callback.

## Architecture

```
auth/
├── config.py      # COOKIE_NAME, JWT_SECRET, OAuth setup, dev mode
├── jwt_utils.py   # create_token / decode_token (HS256, configurable expiry)
├── middleware.py  # SlidingSessionMiddleware — rolling cookie refresh
├── router.py      # create_auth_router() → FastAPI APIRouter
├── magic_link.py  # email magic-link + OTP sub-router & helpers
└── rate_limit.py  # DB-backed sliding-window limits for magic-link
```

### SSO Mechanism

Three things make cross-subdomain SSO work:

1. **Unified cookie name**: `flyfun_auth` (all apps read the same cookie)
2. **Shared JWT secret**: All apps use the same `JWT_SECRET` env var
3. **Cookie domain**: `.flyfun.aero` in production (browser sends cookie to all subdomains)

In dev mode, cookie domain is `None` (localhost only), and auth is bypassed entirely (returns `dev-user-001`).

### Auth Priority (in `deps.py`)

1. Dev mode → `DEV_USER_ID` (no validation)
2. `flyfun_auth` cookie → decode JWT, extract `sub` claim
3. `Authorization: Bearer <token>` → if no `ff_` prefix, decode as JWT; if `ff_` prefix, hash-lookup in `api_tokens` table
4. None of the above → 401

After extracting user ID, production mode also checks `users.approved` → 403 if suspended.

### OAuth Flow

```
GET /auth/login/google → Google consent → GET /auth/callback/google
  ↓
  Lookup user by (provider, provider_sub)
  ↓ not found → create UserRow (auto-approved), call on_new_user
  ↓ found → update last_login_at, email, name
  ↓
  Issue JWT → set cookie (domain=.flyfun.aero) → redirect to /
```

iOS variant: `?platform=ios` on login → callback redirects to `flyfun://auth/callback?token=...` instead of setting cookie.

### Magic-link (email) flow

A third login provider alongside Google/Apple. Mints the same `flyfun_auth` JWT — only the identification path differs. Mounted by `create_auth_router()` only when a `send_magic_link_email` callback is wired:

```python
def send_magic_link_email(email, link, code, requesting_ip):
    # app-specific email infra (Resend / SMTP / SES …)
    ...

app.include_router(create_auth_router(
    send_magic_link_email=send_magic_link_email,
))
```

Endpoints (all prefixed `/auth`):

| Endpoint | Purpose |
|----------|---------|
| `POST /magic-link/request` | Body `{email, platform?, next?}`. Mints a 256-bit token + 6-digit OTP, stores SHA-256 hashes only, calls `send_magic_link_email`. **Always returns 200** (no account enumeration). 503 if no callback. 400 for Apple Private Relay addresses. 429 on rate-limit. |
| `GET  /verify?token=...&next=...` | Pass-through page. **Does NOT consume the token.** 302s to `/auth-verify.html?token=...&next=...`. Each consumer app owns that page. Defends against corporate email scanners (Outlook ATP, Proofpoint, Mimecast) that pre-click links. |
| `POST /magic-link/consume` | Web flow. Body `{token, next?}`. Validates, marks `used_at`, mints JWT, sets `flyfun_auth` cookie, redirects to `next` or `/`. Unapproved users → 302 `/login.html?status=pending`. |
| `POST /magic-link/consume-code` | iOS flow. Body `{email, code}`. Same validation logic, returns `{token, user_id}` JSON (no cookie). Mirrors `/auth/apple/token`. |

Account-linking rule: `_find_or_create_user_by_email` looks up by lowercased email. Existing rows keep their original `provider` (a Google user verifying via magic-link stays `provider="google"`). New rows are created with `provider="email"`, `provider_sub=<email>`, `approved=True`.

**Rate limits** (DB-backed sliding windows, skipped when `is_dev_mode()`):

- per email: 3 / hour on `/magic-link/request`
- per IP:   10 / hour on `/magic-link/request`
- per IP:    5 / minute on `/magic-link/consume*`

Counters run as `count(*)` over `magic_link_tokens.created_at` (for /request) and `magic_link_consume_attempts.attempted_at` (for /consume). No separate counter table.

**Token cleanup**: `purge_expired_magic_link_tokens(db, older_than_hours=24)` deletes expired tokens and old consume-attempt rows. flyfun-common does NOT schedule — consumer apps call this from their own retention loop.

**Consumer-app responsibilities** (not in flyfun-common):

1. **Alembic migration** for `magic_link_tokens` + `magic_link_consume_attempts` tables, plus a `ix_users_email` index on `users.email` (every consume reads it).
2. **Email template** + `send_magic_link_email` callback wired into `create_auth_router`.
3. **`/login.html`** showing an email-input form that POSTs to `/auth/magic-link/request`.
4. **`/auth-verify.html`** confirmation page that POSTs to `/auth/magic-link/consume`.
5. **Retention loop** call to `purge_expired_magic_link_tokens`.

### Post-login redirect (`?next=`)

`GET /auth/login/{provider}` accepts an optional `next=/path` query parameter. When a user follows a shared deep link (e.g. `/flight.html?id=abc`) and isn't logged in, the frontend can redirect to `/auth/login/google?next=/flight.html?id=abc` and the callback will land the user on that path after issuing the cookie.

- Validated in the login endpoint by `_is_safe_relative_path` — must start with `/`, must not start with `//` or `/\`, must have no scheme or netloc. Hostile values are silently dropped; login proceeds with fallback to `/`.
- Stashed under session key `post_login_redirect`. This is distinct from `oauth_next`, which is reserved for the MCP OAuth authorize flow (`/oauth/*`) — the callback checks `oauth_next` first, then `post_login_redirect`, then falls back to `/`.
- Ignored for `platform=ios` (iOS callback owns navigation via its custom URL scheme).

### Rolling sessions (`SlidingSessionMiddleware`)

Sessions slide forward on active use. Mount the middleware on any app that issues `flyfun_auth` cookies:

```python
from flyfun_common.auth import SlidingSessionMiddleware
app.add_middleware(SlidingSessionMiddleware)
```

Behavior:
- On each HTTP request, decodes the `flyfun_auth` cookie. If the remaining lifetime is below `JWT_REFRESH_THRESHOLD_DAYS` (default 15), mints a fresh JWT and attaches it as a new `Set-Cookie` on the response.
- Users who visit at least once every ~15 days stay logged in indefinitely; users silent for the full `JWT_EXPIRY_DAYS` window (default 30) are forced to re-login.
- Bearer-token requests (JWT or `ff_` API tokens) are never refreshed — there's no cookie to rewrite.
- Expired or malformed cookies are passed through unchanged (the auth dependency will 401).
- If the endpoint already sets `flyfun_auth` (login callback, logout, account delete), the middleware skips to avoid clobbering.
- Refreshing reissues a JWT with the same `sub`/`email`/`name` claims, new `iat`/`exp`, same HS256 secret. No refresh-token plumbing, no server-side denylist.
- Admin suspension still takes effect immediately because `current_user_id` re-checks `user.approved` on every request regardless of token lifetime.

## Usage Examples

```python
# Mount the shared auth router in your FastAPI app
from flyfun_common.auth import create_auth_router

def on_new_user(user, request, db):
    send_welcome_email(user.email, user.display_name)

app.include_router(create_auth_router(on_new_user=on_new_user))
# Provides: /auth/login/google, /auth/callback/google, /auth/logout, /auth/me
```

```python
# Protect an endpoint with current_user_id
from flyfun_common.db import current_user_id, get_db

@app.get("/my-data")
def my_data(user_id: str = Depends(current_user_id), db=Depends(get_db)):
    return db.query(MyModel).filter_by(user_id=user_id).all()
```

## Key Choices

- **HS256 JWT** (symmetric): All apps share one secret. Simpler than RS256 for same-infrastructure services. If apps move to separate servers, consider switching to RS256.
- **30-day expiry with sliding refresh**: Default `JWT_EXPIRY_DAYS=30`, refresh when below `JWT_REFRESH_THRESHOLD_DAYS=15`. No refresh-token plumbing — we reissue the same kind of JWT with a fresh `exp`. Previously a flat 7-day expiry.
- **Auto-approve on signup**: New Google OAuth users get `approved=True`. Admin can revoke later.
- **API token prefix `ff_`**: Distinguishes hashed API tokens from JWTs in Bearer header. Previously `wb_` in weather — unified to `ff_` (flyfun).
- **`on_new_user` callback**: Avoids coupling the router to app-specific logic (emails, provisioning).
- **Magic-link provider gated by callback presence**: `/auth/providers` lists `"email"` iff `send_magic_link_email` was wired in `create_auth_router`. Mirrors how Google/Apple gate on env-var presence — one source of truth, no extra env var.
- **`GET /auth/verify` never consumes**: Corporate email scanners pre-click links. Only the explicit POST from `/auth-verify.html` burns the token. The verify endpoint is a thin 302 redirect.

## Gotchas

- `SessionMiddleware` is required on the FastAPI app for OAuth state to survive the Google redirect roundtrip. Each app must add it.
- In production behind Caddy, the callback replaces `http://` with `https://` in the redirect URI. This assumes the app sees the proxied scheme.
- The `COOKIE_DOMAIN` env var overrides the default `.flyfun.aero` if needed.
- Dev mode JWT secret is hardcoded and insecure — `get_jwt_secret()` raises if you try to use it in production.

## Environment Variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `ENVIRONMENT` | No | `development` | `production` enables real auth |
| `JWT_SECRET` | Prod | dev default | HS256 signing key (same across all apps) |
| `JWT_EXPIRY_DAYS` | No | `30` | Absolute JWT / cookie lifetime (days) |
| `JWT_REFRESH_THRESHOLD_DAYS` | No | `15` | Sliding refresh kicks in below this remaining lifetime |
| `GOOGLE_CLIENT_ID` | Prod | `""` | Google OAuth |
| `GOOGLE_CLIENT_SECRET` | Prod | `""` | Google OAuth |
| `COOKIE_DOMAIN` | No | `.flyfun.aero` | Override SSO cookie domain |

## References

- Config: `src/flyfun_common/auth/config.py`
- JWT: `src/flyfun_common/auth/jwt_utils.py`
- Middleware: `src/flyfun_common/auth/middleware.py`
- Router: `src/flyfun_common/auth/router.py`
- Magic-link: `src/flyfun_common/auth/magic_link.py`
- Rate limits: `src/flyfun_common/auth/rate_limit.py`
- Auth deps: `src/flyfun_common/db/deps.py`
- See [DB design](./db.md) for UserRow, ApiTokenRow, MagicLinkTokenRow models
