# flyfun-common

> Shared user management, authentication, and cross-subdomain SSO for flyfun FastAPI services

Install: `pip install -e ~/Developer/public/flyfun-common`

Related: flyfun-weather, flyfun-customs

## Modules

### auth
Google OAuth login, JWT session cookies, cross-subdomain SSO via `.flyfun.aero` cookie domain. Provides a mountable FastAPI auth router and configuration helpers.
Key exports: `create_auth_router`, `create_token`, `decode_token`, `COOKIE_NAME`, `get_jwt_secret`, `is_dev_mode`
→ Full doc: auth.md

### db
Shared SQLAlchemy models (UserRow, ApiTokenRow), database engine singleton, and FastAPI dependencies for session management and authentication.
Key exports: `UserRow`, `ApiTokenRow`, `Base`, `get_db`, `current_user_id`, `init_shared_db`, `ensure_dev_user`, `SessionLocal`
→ Full doc: db.md

### autorouter
OAuth2 account linking for Autorouter API access (NOTAMs, flight plans, weather). Service-linking flow for already-authenticated users — not a login provider.
Key exports: `create_autorouter_router`, `get_autorouter_token`
→ Full doc: autorouter.md

### mcp-oauth
OAuth 2.1 authorization server for MCP connectors (claude.ai, Cowork). Dynamic client registration, PKCE, consent screen. Issues `api_tokens` tied to user accounts.
Key exports: `create_oauth_router`, `OAuthClientRow`, `OAuthAuthorizationCodeRow`
→ Full doc: mcp-oauth.md
