# MCP OAuth 2.1

> OAuth 2.1 authorization server for MCP connectors (claude.ai, Cowork), enabling AI assistants to authenticate as flyfun users

## Problem

The MCP server at `mcp.flyfun.aero/weather` currently authenticates via static Bearer tokens that users generate in the settings UI. This works for Claude Code (CLI), which supports `--header "Authorization: Bearer <token>"`, but **not** for claude.ai or Cowork — those clients only support OAuth 2.1 with dynamic client registration.

To make the MCP server accessible to non-technical users on claude.ai/Cowork, we need an OAuth 2.1 authorization server that:
1. Lets claude.ai discover auth endpoints via `.well-known` metadata
2. Registers itself as an OAuth client (dynamic registration)
3. Redirects the user to log in with their existing flyfun account (Google OAuth)
4. Issues a Bearer token tied to their `user_id` — same as the existing `api_tokens` table

## URL Architecture

```
mcp.flyfun.aero                          ← Caddy (shared-infra)
├── /.well-known/oauth-authorization-server          ← static JSON (Caddy respond)
├── /.well-known/oauth-authorization-server/weather  ← same JSON (RFC 8414 path variant)
├── /weather/mcp                         ← MCP protocol (proxy → weatherbrief-mcp:8021)
│
weather.flyfun.aero                      ← Caddy → weatherbrief:8020
├── /oauth/register                      ← Dynamic client registration (POST)
├── /oauth/authorize                     ← Authorization page (GET → browser)
├── /oauth/token                         ← Token exchange (POST)
├── /auth/login/google                   ← Existing Google OAuth (reused)
├── /auth/callback/google                ← Existing Google callback (reused)
```

**Why this split:**
- `.well-known` must be on `mcp.flyfun.aero` (same origin the MCP client connects to)
- OAuth endpoints live on `weather.flyfun.aero` where the auth infrastructure, DB, and sessions already exist
- The MCP server itself stays stateless — it just validates Bearer tokens like today
- Caddy serves `.well-known` as static JSON — no app involvement needed

## OAuth 2.1 Flow

### 1. Discovery

Claude.ai GETs `mcp.flyfun.aero/.well-known/oauth-authorization-server`:

```json
{
  "issuer": "https://weather.flyfun.aero",
  "authorization_endpoint": "https://weather.flyfun.aero/oauth/authorize",
  "token_endpoint": "https://weather.flyfun.aero/oauth/token",
  "registration_endpoint": "https://weather.flyfun.aero/oauth/register",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_methods_supported": ["client_secret_post"],
  "code_challenge_methods_supported": ["S256"],
  "scopes_supported": ["mcp"]
}
```

Caddy serves this — add to `mcp.flyfun.aero.caddy`:
```
handle /.well-known/oauth-authorization-server* {
    header Content-Type application/json
    respond `{...}`
}
```

### 2. Dynamic Client Registration

Claude.ai POSTs to `weather.flyfun.aero/oauth/register`:

```json
{
  "client_name": "Claude.ai - Acme Corp",
  "redirect_uris": ["https://claude.ai/oauth/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_method": "client_secret_post"
}
```

Response:
```json
{
  "client_id": "mcp_abc123",
  "client_secret": "secret_xyz",
  "client_name": "Claude.ai - Acme Corp",
  "redirect_uris": ["https://claude.ai/oauth/callback"],
  "grant_types": ["authorization_code", "refresh_token"]
}
```

**New table: `oauth_clients`**

| Column | Type | Notes |
|--------|------|-------|
| id | String(64) PK | `mcp_` + random |
| client_secret_hash | String(64) | SHA-256 hex of secret |
| client_name | String(256) | Display name, default `""` |
| redirect_uris_json | Text | JSON array of allowed URIs |
| created_at | DateTime(tz) | Auto-set to UTC now |

### 3. Authorization

Claude.ai opens browser to:
```
https://weather.flyfun.aero/oauth/authorize?
  client_id=mcp_abc123&
  redirect_uri=https://claude.ai/oauth/callback&
  response_type=code&
  code_challenge=<S256 hash>&
  code_challenge_method=S256&
  state=<opaque>
```

The `/oauth/authorize` endpoint:
1. Validates `client_id` and `redirect_uri` against `oauth_clients`
2. Checks if user is logged in (has `flyfun_auth` cookie)
   - If not → redirect to Google OAuth with `?next=/oauth/authorize?...` (preserve the full query)
   - If yes → show a consent screen: "Claude.ai wants to access your weather briefings"
3. On approval → generate authorization code, store in DB, redirect:
   ```
   https://claude.ai/oauth/callback?code=<auth_code>&state=<opaque>
   ```

**New table: `oauth_authorization_codes`**

| Column | Type | Notes |
|--------|------|-------|
| code | String(64) PK | Random, single-use |
| client_id | String(64) | → oauth_clients, indexed |
| user_id | String(64) | → users, indexed |
| redirect_uri | String(1024) | Must match on exchange |
| code_challenge | String(128) | PKCE S256 |
| scope | String(256) | Default `"mcp"` |
| expires_at | DateTime(tz) | Short-lived (~10 min) |
| used | Boolean | Default false, prevent replay |

### 4. Token Exchange

Claude.ai POSTs to `weather.flyfun.aero/oauth/token`:

```
grant_type=authorization_code&
code=<auth_code>&
redirect_uri=https://claude.ai/oauth/callback&
client_id=mcp_abc123&
client_secret=secret_xyz&
code_verifier=<PKCE verifier>
```

The endpoint:
1. Validates client_id + client_secret
2. Looks up the authorization code — checks: not expired, not used, redirect_uri matches, PKCE verifier matches
3. Marks code as used
4. Generates a Bearer token via `generate_api_token()` → stores in `api_tokens` with:
   - `user_id` from the auth code
   - `name` = client_name (e.g. "Claude.ai - Acme Corp")
   - `oauth_client_id` = the client that requested it (for revocation tracking)
5. Optionally generates a refresh token (longer-lived, stored separately)
6. Returns:
```json
{
  "access_token": "ff_...",
  "token_type": "bearer",
  "expires_in": 604800,
  "refresh_token": "ffr_..."
}
```

### 5. Refresh (optional but recommended)

Claude.ai POSTs to `weather.flyfun.aero/oauth/token`:
```
grant_type=refresh_token&
refresh_token=ffr_...&
client_id=mcp_abc123&
client_secret=secret_xyz
```

Issues a new access token, rotates the refresh token, revokes the old access token.

**New table: `oauth_refresh_tokens`**

| Column | Type | Notes |
|--------|------|-------|
| id | Integer PK | Auto-increment |
| token_hash | String(64) | SHA-256 hex, unique, indexed |
| client_id | String(64) | → oauth_clients, indexed |
| user_id | String(64) | → users, indexed |
| access_token_hash | String(64) | Links to the api_tokens row it issued |
| scope | String(256) | Default `"mcp"` |
| created_at | DateTime(tz) | Auto-set to UTC now |
| expires_at | DateTime(tz) | Nullable (no expiry = lives forever) |
| revoked | Boolean | Default false, set true on rotation |

**New column on `api_tokens`:** `oauth_client_id` — String(64), nullable. Tracks which OAuth client issued the token (for revocation/audit). Null for manually-created tokens.

### 6. MCP Requests

Claude.ai sends `Authorization: Bearer ff_...` on every MCP request to `mcp.flyfun.aero/weather/mcp`. The existing `_extract_token()` → `current_user_id` chain handles this — no changes needed.

## What Lives Where

### flyfun-common (new module: `oauth/`)
- `oauth/models.py` — `OAuthClientRow`, `OAuthAuthorizationCodeRow`, `OAuthRefreshTokenRow` (shared Base)
- `oauth/router.py` — `create_oauth_router()` → FastAPI router with `/oauth/register`, `/oauth/authorize`, `/oauth/token`
- `oauth/pkce.py` — PKCE S256 verification helper
- Models only — no Alembic migrations here (see flyfun-weather below)

### flyfun-apps (Caddy config)
- Update `mcp.flyfun.aero.caddy` to serve `.well-known` JSON

### flyfun-weather
- Mount the OAuth router: `app.include_router(create_oauth_router())`
- Alembic migration for the three new tables + `api_tokens.oauth_client_id` column
- No other changes — existing Bearer token validation already works

### weatherbrief MCP server
- No changes needed

## Consent Screen

The `/oauth/authorize` page needs a simple consent screen. Design:

```
┌──────────────────────────────────────┐
│  FlyFun Weather                      │
│                                      │
│  "Claude.ai" wants to access your    │
│  weather briefings.                  │
│                                      │
│  This will allow the app to:         │
│  • View your flights and briefings   │
│  • Create flights and request        │
│    weather briefings                 │
│  • View airport weather forecasts    │
│                                      │
│  Logged in as: user@example.com      │
│                                      │
│  [Authorize]  [Cancel]               │
└──────────────────────────────────────┘
```

This is a server-rendered HTML page (not a SPA route) since it must work in a popup/redirect flow.

## Security Considerations

- **PKCE required** (S256 only) — prevents authorization code interception
- **Client secrets hashed** in DB (same as api_tokens)
- **Authorization codes**: single-use, 10-minute expiry; replay revokes all tokens issued from that code (RFC 6749 §10.5)
- **CSRF protection**: consent form includes a session-bound CSRF token, validated on POST with constant-time comparison
- **Redirect URI validation**: exact match against registered URIs
- **Scope validation**: requested scopes validated against `scopes_supported`; unsupported scopes return `invalid_scope` error redirect
- **Refresh token expiry**: checked on use if `expires_at` is set
- **Token revocation**: revoking from the Settings UI (existing token management) works — tokens issued via OAuth are regular `api_tokens` rows
- **Rate limiting**: consider rate-limiting `/oauth/register` to prevent abuse (low priority — no real attack surface since registration just stores a row)

## Migration Path

1. Build OAuth router in flyfun-common (models + endpoints) — **this repo**
2. Add Alembic migration in the **consuming app** (e.g. flyfun-weather) for:
   - `oauth_clients`, `oauth_authorization_codes`, `oauth_refresh_tokens` tables
   - `api_tokens.oauth_client_id` column (nullable, added with `batch_alter_table`)
   - flyfun-common defines the models; the consuming app owns migrations because it owns the database and Alembic env
3. Mount router in weatherbrief app: `app.include_router(create_oauth_router())`
4. Update Caddy config for `.well-known` (in flyfun-apps/shared-infra)
5. Test with claude.ai connector
6. Existing Bearer token flow (Claude Code, Settings UI) continues working unchanged

### Alembic Migration Reference

The migration in flyfun-weather should follow the pattern from `004_flight_profiles.py` (create tables + add FK column to existing table with `batch_alter_table`):

```python
"""Add OAuth 2.1 tables for MCP connectors.

Revision ID: 041
Revises: 040
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "041"
down_revision: Union[str, None] = "040"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "oauth_clients",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("client_secret_hash", sa.String(64), nullable=False),
        sa.Column("client_name", sa.String(256), nullable=False, server_default=""),
        sa.Column("redirect_uris_json", sa.Text, nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "oauth_authorization_codes",
        sa.Column("code", sa.String(64), primary_key=True),
        sa.Column("client_id", sa.String(64), nullable=False, index=True),
        sa.Column("user_id", sa.String(64), nullable=False, index=True),
        sa.Column("redirect_uri", sa.String(1024), nullable=False),
        sa.Column("code_challenge", sa.String(128), nullable=False),
        sa.Column("scope", sa.String(256), nullable=False, server_default="mcp"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Boolean, nullable=False, server_default=sa.text("0")),
    )

    op.create_table(
        "oauth_refresh_tokens",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True, index=True),
        sa.Column("client_id", sa.String(64), nullable=False, index=True),
        sa.Column("user_id", sa.String(64), nullable=False, index=True),
        sa.Column("access_token_hash", sa.String(64), nullable=False),
        sa.Column("scope", sa.String(256), nullable=False, server_default="mcp"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean, nullable=False, server_default=sa.text("0")),
    )

    # Add oauth_client_id to existing api_tokens (nullable — null for manual tokens)
    with op.batch_alter_table("api_tokens") as batch_op:
        batch_op.add_column(
            sa.Column("oauth_client_id", sa.String(64), nullable=True),
        )


def downgrade() -> None:
    with op.batch_alter_table("api_tokens") as batch_op:
        batch_op.drop_column("oauth_client_id")
    op.drop_table("oauth_refresh_tokens")
    op.drop_table("oauth_authorization_codes")
    op.drop_table("oauth_clients")
```

> **Note:** Verify `down_revision` matches the latest migration in flyfun-weather at the time of creation. The example above assumes `040` is current.

## References

- [MCP OAuth spec](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization)
- [RFC 8414 — OAuth Authorization Server Metadata](https://tools.ietf.org/html/rfc8414)
- [RFC 7591 — Dynamic Client Registration](https://tools.ietf.org/html/rfc7591)
- [Claude.ai connector setup](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp)
- [Building remote MCP servers](https://support.claude.com/en/articles/11503834-build-custom-connectors-via-remote-mcp-servers)
- Existing auth: `flyfun-common/designs/auth.md`
