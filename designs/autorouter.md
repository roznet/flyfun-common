# Autorouter Integration

> OAuth2 account linking for Autorouter API access (NOTAMs, flight plans, weather)

## Intent

Allow flyfun users to link their Autorouter account so we can call the Autorouter API on their behalf. This is a **service-linking** flow, not a login provider — users are already authenticated via Google/Apple SSO before connecting Autorouter.

Autorouter provides flight planning, NOTAM, and weather services via their API at `api.autorouter.aero`. API access requires an OAuth2 bearer token obtained through their Authorization Code flow.

## Architecture

```
autorouter.py          # Router, token exchange, credential storage
credentials.py         # Encrypted storage helpers (shared, pre-existing)
encryption.py          # Fernet encrypt/decrypt (shared, pre-existing)
```

The module is intentionally separate from `auth/` because it serves a different purpose: `auth/` handles user identity (login/signup), while `autorouter.py` handles third-party service linking for an already-authenticated user.

### OAuth2 Flow

```
User clicks "Connect Autorouter"
  ↓
GET /autorouter/link (requires active flyfun session)
  → stores CSRF state + user_id in session
  → redirects to https://www.autorouter.aero/authorize
  ↓
User authorizes on Autorouter's site
  ↓
GET /auth/callback/autorouter?code=...&state=...
  → validates state (CSRF protection)
  → exchanges code for access token at Autorouter's token endpoint
  → stores token encrypted in UserPreferencesRow
  → redirects to /settings?autorouter=linked
```

### Token Storage

Autorouter tokens are stored in `UserPreferencesRow.encrypted_creds_json` under the `"autorouter"` key, alongside any other service credentials. The stored structure:

```json
{
  "autorouter": {
    "access_token": "...",
    "token_type": "bearer",
    "expires_in": 31536000,
    "linked_at": "2026-04-09T..."
  }
}
```

This uses the existing `credentials.py` helpers (Fernet encryption at rest) — no new tables needed.

### Token Lifecycle

- Tokens last approximately **one year** with no refresh mechanism.
- When a token expires or is revoked, API calls will fail with 401 — the app should prompt the user to re-link.
- Users can unlink at any time via `POST /autorouter/unlink`.

## Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `GET` | `/autorouter/link` | Required | Start OAuth flow → redirect to Autorouter |
| `GET` | `/auth/callback/autorouter` | Session | Handle Autorouter redirect, exchange code |
| `GET` | `/autorouter/status` | Required | Check if user has linked account |
| `POST` | `/autorouter/unlink` | Required | Remove stored Autorouter token |

## Usage

### Mounting the router

```python
from flyfun_common.autorouter import create_autorouter_router

app.include_router(create_autorouter_router())
```

Requires `SessionMiddleware` on the app (same as the auth router).

### Retrieving the token for API calls

```python
from flyfun_common.autorouter import get_autorouter_token

token = get_autorouter_token(db, user_id)
if token is None:
    # user hasn't linked — prompt them to connect
    ...

# Use with Autorouter API
headers = {"Authorization": f"Bearer {token}"}
resp = httpx.get("https://api.autorouter.aero/v1.0/...", headers=headers)
```

## Autorouter API Reference

- **Authorization endpoint**: `https://www.autorouter.aero/authorize`
- **Token endpoint**: `https://api.autorouter.aero/v1.0/oauth2/token`
- **API base**: `https://api.autorouter.aero/v1.0/`
- **Auth code validity**: 30 seconds (exchange must be fast)
- **Token validity**: ~1 year
- **Docs**: https://www.autorouter.aero/wiki/api/authentication/

## Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `AUTOROUTER_CLIENT_ID` | Yes | Registered application ID |
| `AUTOROUTER_CLIENT_SECRET` | Yes | Application secret from Autorouter |

## Key Choices

- **Separate from auth router**: Autorouter is not an identity provider. Mixing it into `auth/router.py` would conflate login with service linking.
- **Encrypted credential storage**: Reuses `credentials.py` + `encryption.py` rather than a new table. The token sits alongside other per-user secrets in a single encrypted JSON blob.
- **No refresh flow**: Autorouter doesn't provide refresh tokens. The ~1 year lifetime is long enough that re-linking once a year is acceptable.
- **CSRF via session state**: Same pattern as Google/Apple OAuth — random state stored in `SessionMiddleware`, validated on callback.

## Gotchas

- The authorization code is only valid for **30 seconds**. The token exchange must happen immediately in the callback handler.
- `SessionMiddleware` must be mounted on the app for the state parameter to survive the redirect roundtrip.
- The redirect URI registered with Autorouter must exactly match what the callback generates. Behind Caddy, the code forces `https://` replacement.

## References

- Implementation: `src/flyfun_common/autorouter.py`
- Credential helpers: `src/flyfun_common/credentials.py`
- Encryption: `src/flyfun_common/encryption.py`
- See [auth.md](./auth.md) for the login/SSO flow (separate concern)
- See [db.md](./db.md) for UserPreferencesRow model
