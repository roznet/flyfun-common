# OpenID Connect / OAuth 2.0 — Research Summary

## Current State

flyfun-common **already implements OAuth 2.0 + OpenID Connect (OIDC)** for
authentication via the `authlib` library. Both configured providers — Google and
Apple — are standard OIDC providers.

## Terminology

| Term | Definition | How We Use It |
|------|-----------|---------------|
| **OAuth 2.0** | Authorization framework that lets users grant third-party apps limited access to their accounts | The redirect-based login flow: `/auth/login/{provider}` → provider consent → `/auth/callback/{provider}` |
| **OpenID Connect (OIDC)** | Identity layer built on top of OAuth 2.0; standardizes how identity information (email, name, unique subject ID) is conveyed via an `id_token` JWT | We request the `openid` scope and extract identity claims from the ID token returned by Google/Apple |
| **OIDC Discovery** | A well-known URL (`/.well-known/openid-configuration`) that advertises a provider's endpoints, supported scopes, and signing keys | `authlib` fetches this automatically for both Google and Apple |

**In short:** OAuth 2.0 answers *"let me access your stuff"*; OIDC answers
*"tell me who you are."* We use both together.

## How Our Auth Flow Works (OIDC)

```
1. User clicks "Sign in with Google/Apple"
2. Server redirects to provider's authorization endpoint (OAuth 2.0)
3. User authenticates and consents
4. Provider redirects back to /auth/callback/{provider} with an auth code
5. Server exchanges auth code for access_token + id_token (OAuth 2.0 token endpoint)
6. Server validates id_token signature via provider's JWKS (OIDC)
7. Server extracts claims: sub (unique ID), email, name
8. Server finds or creates a UserRow keyed on (provider, provider_sub)
9. Server issues a flyfun JWT (HS256, 7-day expiry)
10. Web: JWT set as httponly cookie on .flyfun.aero
    iOS: Redirect to custom URL scheme with JWT in query param
```

## Configured Providers

### Google
- **OIDC Discovery**: `https://accounts.google.com/.well-known/openid-configuration`
- **Scopes**: `openid email profile`
- **Env vars**: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`

### Apple
- **OIDC Discovery**: `https://appleid.apple.com/.well-known/openid-configuration`
- **Scopes**: `openid email name`
- **Env vars**: `APPLE_CLIENT_ID`, `APPLE_TEAM_ID`, `APPLE_KEY_ID`, `APPLE_PRIVATE_KEY`, `APPLE_APP_IDS`
- **Special**: Client secret is a short-lived ES256 JWT generated per request.
  Also supports native iOS token validation via `POST /auth/apple/token`.

## Adding More OIDC Providers

The architecture is already generic — routes use `{provider}` path parameters
and `authlib` handles OIDC discovery automatically. Adding a new provider
requires:

1. **Register the provider** in `auth/config.py` with its OIDC discovery URL
   and client credentials.
2. **Handle any provider quirks** in `_extract_userinfo()` in `router.py`
   (e.g., Apple sends user info only on first auth; some providers put email
   in different claim fields).
3. **Set environment variables** for the new provider's client ID and secret.

### Candidate Providers (all support OIDC)

| Provider | Discovery URL | Notes |
|----------|--------------|-------|
| Microsoft / Entra ID | `https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration` | Multi-tenant; good for enterprise users |
| GitHub | N/A (OAuth 2.0 only, no OIDC) | Would need custom userinfo fetch from `/user` API |
| Facebook | N/A (OAuth 2.0 only, no OIDC) | Would need custom userinfo fetch from Graph API |

> **Note**: GitHub and Facebook do *not* support OIDC natively — they only
> implement OAuth 2.0. Adding them requires fetching user info from their
> respective APIs after the token exchange, rather than decoding an `id_token`.
> `authlib` supports this pattern too, but it's slightly more code.

## Key Files

| File | Purpose |
|------|---------|
| `src/flyfun_common/auth/config.py` | OAuth client registration, OIDC discovery URLs, Apple client secret generation |
| `src/flyfun_common/auth/router.py` | Login/callback/token endpoints, user extraction logic |
| `src/flyfun_common/auth/jwt_utils.py` | JWT creation and validation (HS256) |
| `src/flyfun_common/db/deps.py` | Request authentication middleware (cookie → bearer → API token) |
| `src/flyfun_common/db/models.py` | UserRow model (provider, provider_sub, email, etc.) |

## Conclusion

The suggestion to support "OpenID / OAuth" is already fulfilled by the current
implementation. Google Sign-In and Apple Sign-In are both OIDC providers running
over OAuth 2.0. The codebase is structured to easily add more providers if
needed.
