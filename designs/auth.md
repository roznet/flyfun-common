# Auth Module

> Google OAuth, JWT sessions, and cross-subdomain SSO for all flyfun services

## Intent

Provide a single authentication layer shared by all flyfun FastAPI apps. A user who logs in on `weather.flyfun.aero` is automatically authenticated on `forms.flyfun.aero` (and any future service) without logging in again.

This module should NOT contain app-specific logic (welcome emails, credit provisioning). Apps hook into user creation via the `on_new_user` callback.

## Architecture

```
auth/
├── config.py      # COOKIE_NAME, JWT_SECRET, OAuth setup, dev mode
├── jwt_utils.py   # create_token / decode_token (HS256, 7-day expiry)
└── router.py      # create_auth_router() → FastAPI APIRouter
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
- **7-day expiry**: Matches previous flyfun-weather behavior. No refresh tokens — user re-logs after expiry.
- **Auto-approve on signup**: New Google OAuth users get `approved=True`. Admin can revoke later.
- **API token prefix `ff_`**: Distinguishes hashed API tokens from JWTs in Bearer header. Previously `wb_` in weather — unified to `ff_` (flyfun).
- **`on_new_user` callback**: Avoids coupling the router to app-specific logic (emails, provisioning).

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
| `GOOGLE_CLIENT_ID` | Prod | `""` | Google OAuth |
| `GOOGLE_CLIENT_SECRET` | Prod | `""` | Google OAuth |
| `COOKIE_DOMAIN` | No | `.flyfun.aero` | Override SSO cookie domain |

## References

- Config: `src/flyfun_common/auth/config.py`
- JWT: `src/flyfun_common/auth/jwt_utils.py`
- Router: `src/flyfun_common/auth/router.py`
- Auth deps: `src/flyfun_common/db/deps.py`
- See [DB design](./db.md) for UserRow and ApiTokenRow models
