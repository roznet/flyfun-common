# iOS Authentication Guide

> How to integrate Google, Apple, and magic-link sign-in in flyfun iOS apps using
> the shared `FlyFunCommon` Swift package and auth backend.

Related: [auth.md](./auth.md) (server auth module),
[oauth-deeplink-hardening.md](oauth-deeplink-hardening.md) (the H8 hardening this
guide reflects), [db.md](./db.md).

## Overview

All flyfun iOS apps authenticate against the same server-side auth system, and the
**client side is now shared** — apps depend on the `FlyFunCommon` Swift package
rather than hand-rolling their own auth service. The package provides everything:
the OAuth/Apple/magic-link client, the callback parser, the Keychain store, and a
rolling-Bearer `URLSession` wrapper.

The web sign-in (Google, or Apple via web) uses the native **authorization-code**
pattern — the hardened H8 flow:

1. The client generates a random `state` nonce.
2. It opens `ASWebAuthenticationSession` to `/auth/login/{provider}` with
   `platform=ios`, the app's `scheme`, and the `state`.
3. The user authenticates with the provider.
4. The server callback redirects to `<scheme>://auth?code=<short-TTL-code>&state=<state>`
   — a one-time signed code, **never the JWT**.
5. The client verifies the returned `state` matches, then `POST`s the code to
   `/auth/exchange` and receives the JWT in the **response body** (never a URL).
6. The JWT is stored in the Keychain (device-bound) and attached to all API calls.

The bearer JWT is valid for 7 days but **rolls automatically**: authenticated
responses may carry an `X-Renewed-Token` header that `RollingBearerSession`
persists, so active users effectively stay signed in. A 401 clears the token and
returns the app to the login screen.

> **Why not a token in the callback URL?** The pre-H8 flow returned the JWT as
> `<scheme>://auth?token=<jwt>` and accepted a bare token from any inbound deep
> link. That leaked the credential into redirect logs and opened a login-CSRF /
> session-fixation vector. See [oauth-deeplink-hardening.md](oauth-deeplink-hardening.md)
> for the full rationale. **Do not read a `token=` param from a deep link** — the
> only exception is the App Store reviewer carve-out below.

## The shared package (`FlyFunCommon`)

Add the Swift package `https://github.com/roznet/flyfun-common` as a dependency and
link the `FlyFunCommon` product. Pin to a released tag (e.g. `exactVersion 0.6.3`).

> **Transitive requirement:** the device-bound Keychain store needs
> **rzutils ≥ 1.0.31** (the `accessible:` parameter on `CodableSecureStorage`).
> Apps that pin rzutils by branch must ensure their resolved revision includes it,
> or the package fails to compile with `extra argument 'accessible' in call`.

Key types:

| Type | Purpose |
|------|---------|
| `FlyFunAuthService` | The auth client. Configured with `Config(baseURL:callbackScheme:)`. Methods: `signIn(provider:)`, `exchangeAppleCredential(_:)`, `requestMagicLinkCode(email:)` / `consumeMagicLinkCode(email:code:)`, `deleteAccount(jwt:)`. |
| `KeychainBearerTokenStore` | `BearerTokenStore` backed by the Keychain, partitioned by `service:` (use the bundle id). Bound to this device (`ThisDeviceOnly`) — a session JWT never migrates via backup or iCloud Keychain. |
| `RollingBearerSession` | `URLSession` wrapper that injects `Authorization: Bearer`, persists `X-Renewed-Token`, and on 401 clears the store and fires `onUnauthorized`. Use it for every authenticated request. |
| `AuthCallbackParser` | Used internally by `signIn` (`codeAndState`). Its legacy `token(from:)` reader exists **only** for the reviewer carve-out. |

## Server Endpoints (provided by `create_auth_router`)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/auth/providers` | GET | List enabled providers (`["google", "apple"]`, plus `email` when magic-link is wired) |
| `/auth/login/{provider}` | GET | Start web OAuth. Params: `platform=ios`, `scheme=<app-scheme>`, `state=<nonce>`. Rejects a `scheme` not on the exact allowlist (400). |
| `/auth/callback/{provider}` | GET/POST | Provider redirect target (server-side; the app never calls it). Emits `<scheme>://auth?code=…&state=…`. |
| `/auth/exchange` | POST | Trade `{code, state}` for `{token, ...}` over HTTPS. The client half of the code flow. |
| `/auth/apple/token` | POST | Native Apple Sign-In: exchange an identity token for a JWT. |
| `/auth/me` | GET | Current user info (verify the token works). |
| `/auth/logout` | POST | Invalidate this session. |
| `/auth/logout-all` | POST | Invalidate all of the user's sessions. |
| `/auth/account` | DELETE | Permanently delete the authenticated user (204). |
| `/auth/magic-link/request` · `/auth/magic-link/consume-code` | POST | Email OTP sign-in (only when the server wires a `send_magic_link_email` callback). |

## Per-app URL scheme (NOT a shared scheme)

Each app registers its **own** custom scheme, and the server enforces an exact
allowlist so a second app registering a `flyfun*` scheme can't intercept the
callback. The allowlist defaults to `{flyfunweather, flyfunforms}` and is
overridable via the `OAUTH_ALLOWED_SCHEMES` env var.

| App | Scheme |
|-----|--------|
| flyfun-weather | `flyfunweather` |
| flyfun-forms | `flyfunforms` |
| new app | `flyfun<app>` — **add it to the server allowlist** before shipping |

Register the scheme in `Info.plist` under `CFBundleURLTypes` → `CFBundleURLSchemes`.
(`ASWebAuthenticationSession(callback: .customScheme(...))` captures the callback
internally and does not strictly require the registration, but registering it is
conventional and harmless.)

## Implementation

### 1. Configure the auth service

```swift
import FlyFunCommon

let authService = FlyFunAuthService(config: .init(
    baseURL: APIConfig.baseURL,
    callbackScheme: "flyfunforms"   // this app's scheme
))
```

### 2. Auth state (Keychain + rolling session)

```swift
import FlyFunCommon
import Foundation

@Observable @MainActor
final class AppState {
    @ObservationIgnored let tokenStore: KeychainBearerTokenStore
    @ObservationIgnored private(set) var rollingSession: RollingBearerSession!
    private(set) var jwt: String?
    var isAuthenticated: Bool { jwt != nil }

    init() {
        let store = KeychainBearerTokenStore(service: "net.ro-z.flyfun-forms")
        self.tokenStore = store
        self.jwt = store.token
        self.rollingSession = RollingBearerSession(
            store: store,
            onUnauthorized: { [weak self] in await self?.handleUnauthorized() }
        )
    }

    func signIn(token: String) { tokenStore.token = token; jwt = token }
    func logout() { tokenStore.token = nil; jwt = nil }
    func handleUnauthorized() { jwt = nil }   // rolling session already cleared the store
}
```

> **No `handleAuthCallback` / no `onOpenURL` for sign-in.** The web flow is captured
> inside `ASWebAuthenticationSession` and never reaches `onOpenURL`. Do not add a
> bare-token deep-link handler (see the reviewer carve-out for the one exception).

### 3. Login view

`signIn(provider:)` runs the whole code/state exchange and returns the JWT:

```swift
struct LoginView: View {
    @Environment(AppState.self) private var appState
    private var authService: FlyFunAuthService {
        FlyFunAuthService(config: .init(baseURL: APIConfig.baseURL, callbackScheme: "flyfunforms"))
    }

    // Google (web OAuth)
    private func signIn(provider: String) async {
        do {
            let token = try await authService.signIn(provider: provider)
            appState.signIn(token: token)
        } catch { /* ignore ASWebAuthenticationSessionError.canceledLogin */ }
    }

    // Apple (native)
    private func handleAppleSignIn(_ result: Result<ASAuthorization, Error>) async {
        guard let cred = try? result.get().credential as? ASAuthorizationAppleIDCredential else { return }
        let token = try? await authService.exchangeAppleCredential(cred)
        if let token { appState.signIn(token: token) }
    }
}
```

### 4. Authenticated requests

Route every authenticated call through the rolling session — never build the
`Authorization` header by hand, so token renewal and 401 handling stay centralized:

```swift
let (data, http) = try await appState.rollingSession.data(for: request)
```

### 5. App entry point

```swift
@main
struct MyApp: App {
    @State private var appState = AppState()
    var body: some Scene {
        WindowGroup {
            if appState.isAuthenticated { ContentView() } else { LoginView() }
        }
        .environment(appState)
        // No .onOpenURL for auth. Add one only for a reviewer carve-out (below).
    }
}
```

## Apple Sign-In

Prefer the **native** button (`SignInWithAppleButton`) with
`exchangeAppleCredential(_:)` — it's the standard for flyfun apps and avoids a web
round-trip. Web-based Apple sign-in still works via `signIn(provider: "apple")` if
you need it. Native Apple Sign-In requires the `Sign in with Apple` capability and
the `APPLE_*` server env vars below.

## App Store reviewer carve-out (optional, per app)

Apple reviewers need a one-tap way in. Two options:

1. **A real demo account through the normal flow** (what flyfun-forms does). No
   special code — the reviewer signs in with a dedicated Apple/Google test account.
   Simplest; keeps the bare-token path fully removed.
2. **A reviewer deep link** (what flyfun-weather does). Keep a bare-token
   `onOpenURL` handler that accepts a token **only** when the app is signed out
   **and** the (unverified) JWT carries a `scope:"review"` claim. The claim is a
   routing hint only — the server verifies the signature on every call, so a forged
   review token 401s. Mint the reviewer token with `scripts/mint_reviewer_token.py`
   (in the weather repo), signed with the production `JWT_SECRET`, against a
   dedicated throwaway review account. See the carve-out rationale in
   [oauth-deeplink-hardening.md](oauth-deeplink-hardening.md).

## Server Environment Variables

Google OAuth: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`.

Apple Sign-In: `APPLE_CLIENT_ID` (Service ID), `APPLE_TEAM_ID`, `APPLE_KEY_ID`,
`APPLE_PRIVATE_KEY` (PEM ES256), `APPLE_APP_IDS` (comma-separated bundle ids, for
native token validation).

OAuth callback: `OAUTH_ALLOWED_SCHEMES` (comma-separated allowlist; defaults to
`flyfunweather,flyfunforms`). `JWT_SECRET` signs both session tokens and the
short-TTL exchange codes.

## Xcode Setup Checklist

- [ ] Add the `flyfun-common` Swift package; link `FlyFunCommon`. Ensure resolved
      rzutils ≥ 1.0.31.
- [ ] Register the app's own custom URL scheme in `Info.plist`, and add it to the
      server's `OAUTH_ALLOWED_SCHEMES` allowlist.
- [ ] Add the `Sign in with Apple` capability (for native Apple Sign-In).
- [ ] Ensure App Transport Security allows the API domain (HTTPS is fine by default).

## References

- Hardening rationale / migration: [oauth-deeplink-hardening.md](oauth-deeplink-hardening.md)
- Server auth module: [auth.md](./auth.md) · Database schema: [db.md](./db.md)
- Reference apps: **flyfun-weather** (`App/AppState.swift` — includes the reviewer
  carve-out) and **flyfun-forms** (`Services/AppState.swift`, `Views/LoginView.swift`
  — no carve-out, bare-token path removed).
