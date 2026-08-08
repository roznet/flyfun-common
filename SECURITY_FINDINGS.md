# Security Findings — flyfun-common

The full, consolidated flyfun security audit lives in the **flyfun-weather** repo
at `SECURITY_AUDIT.md` (it covers the backend, web frontend, iOS app, deployment,
and this shared library together). This file is a repo-local pointer to the
findings whose fix lives **in this library**, so a reader working here sees them
without cross-referencing.

## 2026-08-08 pass — open items in this library

| ID | Sev | Where | Summary |
|----|-----|-------|---------|
| 2026-08-H1 | **High** | `python/src/flyfun_common/auth/middleware.py:133-165` (+ `db/deps.py:185-193`) | `SlidingSessionMiddleware._maybe_refresh_token` re-mints a JWT (fresh `iat`) after checking only signature+`exp`, with **no DB access and no `tokens_valid_after` check**. A stolen credential in its refresh window survives `logout-all` by hitting any public 200 endpoint (`/health`, `/whats-new`), which reissues a token with `iat > epoch` that then passes the revocation check everywhere — indefinitely. **Fix:** perform the epoch/`approved` check before reissue (load the user in the middleware), or carry the original `iat`/`auth_time` forward unchanged, or move refresh behind the authenticated dependency. |
| 2026-08-M3 | Medium | `db/deps.py:179-193`; `auth/router.py` (`logout_all`) | `_is_session_revoked` returns `False` for `token_iat is None`; `ff_`/OAuth bearer tokens authenticate with `token_iat=None` and refresh tokens are never consulted, so `logout-all` revokes JWT sessions only — leaked API/OAuth access + refresh tokens stay live. **Fix:** on `logout-all`, revoke the user's OAuth-issued `ApiTokenRow`s + `OAuthRefreshTokenRow`s (or check `tokens_valid_after` against token `created_at` in `_authenticate_bearer_token`). Pairs with 2026-08-H1 to restore a real kill-switch. |
| 2026-08-M2 | Medium | `oauth/router.py:256` | DCR per-IP rate limiter uses `request.client.host` (the Caddy proxy IP behind the reverse proxy), collapsing the per-IP window onto one world-shared bucket and logging the proxy IP as `registered_ip`. Regression vs. the 0.6.0 DCR-throttle fix. **Fix:** use the same trusted-IP helper as `magic_link._client_ip` (`X-Real-IP` / rightmost-XFF). |
| 2026-08-M4 | Medium | `oauth/router.py:569-660` (auth code), `:686-767` (refresh) | Auth-code redemption and refresh rotation read-then-set `used`/`revoked` non-atomically (concurrent double-redeem on MySQL InnoDB), and a rotated-token replay returns `invalid_grant` **without** revoking the descendant family (no OAuth 2.1 breach-detection). **Fix:** atomic `UPDATE … WHERE used=0` (check rowcount); revoke the full refresh-token family on rotated-token reuse. |
| 2026-08-I1 | Info | `autorouter.py:152-156,164` | Token-exchange error paths log `resp.text` / the whole `token_data` dict; a provider error body could carry a partial token / `refresh_token` / echoed `code`. **Fix:** log status + field names only. |

### Carry-forward (still open in this library)
- **H3/L4** — single `JWT_SECRET` signs JWTs + Starlette session + native exchange codes + (dev) Fernet key; session JWT carries no `aud`/`iss`. Derive per-purpose subkeys (HKDF).
- **M-new-3 / 2026-08-L1** — sharpened in the weather repo (approval-link interstitial).

### Fixed / improved since the prior pass (verified this pass)
- **iOS OAuth deep-link (long-open H8)** — the `oauth-deeplink-hardening.md` design shipped: the Swift client (`Sources/FlyFunCommon/Auth/FlyFunAuthService.swift`) now uses a `code`+`state` HTTPS exchange with a CSPRNG `state` verified on callback; the JWT never travels in a URL. The bare-token deep link survives only as a signed-out + `scope:"review"`-gated reviewer path.
- **OAuth consent CSRF (06-20 H2)**, **refresh 90-day sliding expiry (06-20 H3)**, **PKCE S256**, **redirect-URI exact-match**, **magic-link enumeration-safety + per-token OTP attempt cap**, **`ENVIRONMENT` fail-closed** — all re-verified intact.

See `flyfun-weather/SECURITY_AUDIT.md` (2026-08-08 section) for full detail, reconciliation, and the cross-stack roadmap.
