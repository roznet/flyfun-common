# OAuth deep-link hardening (H8) — design for review

Status: **proposed, not implemented**. Addresses SECURITY_AUDIT.md **H8**
("iOS JWT in custom-scheme query + loose regex"). Cross-repo: `flyfun-common`
(Python auth router + Swift auth client) and each native app. Related:
[ios-auth.md](ios-auth.md), [auth.md](auth.md).

## Problem

Today the native sign-in returns the session JWT to the app by redirecting the
OAuth callback to a **custom URL scheme with the token in the query string**:

```python
# flyfun_common/auth/router.py  (callback)
scheme = request.session.pop("oauth_scheme", "flyfun")
redirect_url = f"{scheme}://auth/callback?token={quote(jwt_token)}"
return RedirectResponse(url=redirect_url, status_code=302)
```

and the scheme is validated with a loose regex at `/auth/login/{provider}`:

```python
if not re.fullmatch(r"flyfun[a-z0-9\-]*", scheme):  # accepts any flyfun*
```

On the client, `WeatherBriefApp.onOpenURL` hands **any** inbound
`flyfunweather://auth?token=…` (or the universal-link form) straight to
`AppState.handleAuthCallback`, which signs in with no check tying the callback
to an in-app-initiated flow (`AuthCallbackParser` only extracts `token`).

Three distinct weaknesses:

1. **Bearer token in a URL.** Query strings leak into server/proxy access logs,
   referer chains, and OS hand-off surfaces far more readily than a POST body.
   The token is a 7-day credential.
2. **Custom schemes aren't exclusively owned.** A second app registering
   `flyfun*` can be chosen by the OS to receive the redirect, intercepting the
   token. The loose regex widens this.
3. **No `state` binding → login CSRF / session fixation.** Because the app
   accepts a bare token from any inbound deep link, an attacker who holds a JWT
   for *their own* account can craft `flyfunweather://auth?token=<attacker_jwt>`
   (a web link, email, or another app) and, if the victim opens it, silently log
   the victim into the attacker's account. The victim's subsequent flights,
   route/position data, and PIREPs then land in the attacker's account. The
   normal Google flow uses `ASWebAuthenticationSession`, whose callback is
   captured internally — so this `onOpenURL` path is *extra* attack surface, not
   the happy path.

## Goal

Move to the standard "native app authorization code" pattern: the redirect
carries a **one-time, short-TTL opaque code** (never the JWT), the app exchanges
it for the JWT over an HTTPS **POST** (token only ever in a response body), and
the exchange is bound to a client-generated `state`/PKCE nonce so an injected
callback can't authenticate the victim.

## Design

### Server (`flyfun_common/auth/router.py`)

1. **Exact-scheme allowlist.** Replace the regex with a configured set of exact
   schemes tied to known bundle IDs (e.g. `{"flyfunweather", "flyfunforms"}`).
   Reject anything else with 400. (Defense-in-depth; the code exchange below is
   the real fix.)
2. **Carry `state`.** `/auth/login/{provider}` already accepts `scheme`; also
   accept and stash a `state` (opaque, app-generated) in the session.
3. **Issue a code, not a token.** On callback, mint a single-use code
   (e.g. 32 bytes urlsafe), store `code → (user_id, state, expiry≈60s)` in the
   existing short-TTL store (reuse the magic-link/OTP store), and redirect:
   ```
   {scheme}://auth/callback?code=<opaque>&state=<state>
   ```
   No JWT in the URL.
4. **New `POST /auth/exchange`.** Body `{code, state}` over HTTPS. Validate the
   code exists, is unexpired, single-use (delete on read), and `state` matches.
   Return the JWT in the JSON body — the same shape `consumeMagicLinkCode`
   already returns, so the client path is familiar.
5. **Prefer Universal Links.** The associated-domain (`applinks:weather.flyfun.aero`)
   callback is domain-verified; keep it as the primary return and treat the
   custom scheme as a deprecated fallback.

### Client (`flyfun-common` Swift + apps)

1. **Generate `state` before auth.** In `FlyFunAuthService.signIn`, create a
   random `state` (and optionally PKCE `code_verifier`), pass `state=` on the
   authorize URL, and keep it in-memory for the lifetime of the
   `ASWebAuthenticationSession`.
2. **Parse `code` + `state`, not `token`.** Extend `AuthCallbackParser` to
   return `(code, state)`; the parser already validates scheme/host/path.
3. **Verify `state`, then exchange.** Reject the callback if `state` doesn't
   match the in-flight value. On match, `POST /auth/exchange` to get the JWT,
   then store via `KeychainBearerTokenStore` (now `ThisDeviceOnly`).
4. **Harden `onOpenURL`.** `AppState.handleAuthCallback` should no longer accept
   a bare token. Either route inbound callbacks through the same
   state-checked exchange, or — since `ASWebAuthenticationSession` captures its
   own callback — drop custom-scheme token handling from `onOpenURL` entirely
   and accept only domain-verified universal links for any out-of-session entry.
   **Exception:** the narrow review-token carve-out below (the *only* bare-token
   deep link still accepted).

## App Store review access (hard constraint on Phase 2)

We currently hand the App Store reviewer a one-tap deep link of the form
`flyfunweather://auth?token=<jwt>` that drops them into a prepopulated demo
account. That link **is** the bare-token `onOpenURL` path H8 removes — so the
`onOpenURL` hardening cannot ship without a replacement, or the next review
submission can't sign in.

Relying on a real Google/Apple demo account through the normal flow is possible
but operationally fragile: a fresh account signed into via OAuth from Apple's
review environment (unfamiliar device/IP) frequently trips Google's
"suspicious sign-in" challenges and can lock at the worst moment. So for review
we keep a **controlled** path rather than a third-party one.

**Recommended: demo-scoped review token.** Keep accepting a bare-token deep link
in `onOpenURL`, but **only** when the JWT carries a `scope:"review"` (or
`demo:true`) claim:

- The token is a normal **server-signed** JWT, minted **only** by the server,
  **only** for a single dedicated, throwaway review account (no real PII).
- The app decodes the (unverified) payload purely to *route* — "does this claim
  `review`? then allow the bare-token path." It is **not** trusting the claim for
  authorization: the server verifies the signature on every API call, so a
  forged `review` token is accepted locally but 401s on first use and bounces to
  login. The only token that works end-to-end is one the server actually signed.
- A real attacker token (their own account) carries no `review` claim, so the
  carve-out rejects it — the login-CSRF vector stays closed.
- Residual worst case: someone replays the *genuine* review token to land a
  victim in the **shared throwaway review account** — no data theft into a real
  attacker account, which was H8's severity driver. Acceptable, and further
  reducible by scoping the review account read-mostly / no destructive actions.

This keeps your existing one-tap reviewer link working unchanged while closing
the real hole. **Phase 2 must ship this carve-out together with the `onOpenURL`
hardening.**

## Migration / compatibility

No flag-day for installed users. Three phases:

1. **Server, backward-compatible.** Add `POST /auth/exchange`, accept optional
   `state` on `/auth/login`, and **emit both** params on the callback:
   `…?token=<jwt>&code=<opaque>` (+ `&state=` when provided). Tighten the scheme
   regex to an exact allowlist **that still includes every shipped scheme**
   (`flyfunweather`, `flyfunforms`, …). Old apps keep reading `token` → no
   breakage, no app update required. (Always-emit-both is simpler than a
   `flow=code` capability flag and needs no per-request negotiation.)
2. **App update.** New build generates `state`, uses `code`+`state` exchange,
   hardens `onOpenURL` (with the review carve-out). Additive — old builds keep
   using `token`, so nothing breaks while users update.
3. **Server, the actual hardening.** Once the old token-flow cohort has aged out,
   stop emitting `token` (emit only `code`+`state`). This is the *only* break
   point, and it affects solely a never-updated old build doing a **fresh** Google
   sign-in (Apple Sign In and already-signed-in/rolling-token users are never
   affected). You control its timing; wait until that cohort is ~zero.

## Test plan

- Server: code is single-use (second exchange 400s), expiry enforced, `state`
  mismatch rejected, scheme allowlist rejects `flyfunX` but accepts shipped
  schemes; review-token mint is gated to the review account.
- Client: `AuthCallbackParser` round-trips `code`/`state`; injected callback with
  a wrong/absent `state` is rejected (the login-CSRF regression test); a
  bare-token deep link is rejected **unless** it carries the `review` claim, and
  a forged `review` token still 401s server-side.
- E2E: full Google + Apple sign-in still succeeds on device; the reviewer
  deep-link lands in the demo account.

## Effort

Small-to-moderate, agent-time: server ~code-exchange endpoint + 2 route edits;
client ~parser + service changes in `flyfun-common` consumed by all apps. The
dual-emit migration window is the only sequencing constraint.
