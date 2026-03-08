# iOS Authentication Guide

> How to integrate Google and Apple Sign-In in flyfun iOS apps using the shared auth backend.

## Overview

All flyfun iOS apps authenticate via the same server-side auth system (see [auth.md](./auth.md)). The flow is:

1. iOS app opens an in-app browser to the OAuth login endpoint
2. User authenticates with Google or Apple
3. Server issues a JWT and redirects to a custom URL scheme
4. App captures the JWT, stores it in Keychain, and attaches it to all API requests

The JWT is valid for 7 days. After expiry, the user simply signs in again (no refresh tokens).

> **Note on code sharing:** The auth boilerplate per app is small (~150 lines across 3 files). Each app currently implements its own copy. If shared auth logic grows significantly over time, consider extracting a `FlyfunAuth` Swift package in flyfun-common.

## Server Endpoints (provided by flyfun-common)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/auth/providers` | GET | List enabled providers (`["google", "apple"]`) |
| `/auth/login/{provider}?platform=ios` | GET | Start OAuth flow; `platform=ios` makes callback redirect to custom URL scheme |
| `/auth/callback/{provider}` | GET/POST | OAuth callback (server-side, not called by app directly) |
| `/auth/apple/token` | POST | Native Apple Sign-In: exchange identity token for JWT |
| `/auth/me` | GET | Returns current user info (verify token works) |
| `/auth/logout` | POST | Invalidate session |

## Implementation Steps

### 1. Register Custom URL Scheme

In `Info.plist`, register a URL scheme for the OAuth callback redirect:

```xml
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLName</key>
        <string>net.ro-z.flyfun-forms</string>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>flyfun</string>
        </array>
    </dict>
</array>
```

The server redirects to `{scheme}://auth/callback?token=JWT_TOKEN` after successful login.

**URL scheme:** All flyfun apps use the shared `flyfun://` scheme. The server redirects to `flyfun://auth/callback?token=JWT` after successful login.

| App | Scheme | Callback |
|-----|--------|----------|
| flyfun-weather | `weatherbrief` (legacy) | `weatherbrief://auth/callback?token=...` |
| flyfun-forms | `flyfun` | `flyfun://auth/callback?token=...` |
| future apps | `flyfun` | `flyfun://auth/callback?token=...` |

New apps should use `flyfun` as their URL scheme. The weather app still uses `weatherbrief` for historical reasons and may be migrated later.

### 2. AuthService (OAuth via ASWebAuthenticationSession)

This handles both Google and Apple web-based OAuth:

```swift
import AuthenticationServices
import Foundation
import OSLog

@MainActor
final class AuthService: NSObject, ASWebAuthenticationPresentationContextProviding {
    private static let logger = Logger(subsystem: "your.bundle.id", category: "Auth")
    private var authSession: ASWebAuthenticationSession?

    nonisolated func presentationAnchor(
        for session: ASWebAuthenticationSession
    ) -> ASPresentationAnchor {
        MainActor.assumeIsolated {
            #if os(iOS)
            let scene = UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }.first
            return scene?.keyWindow ?? ASPresentationAnchor()
            #else
            return NSApplication.shared.keyWindow ?? ASPresentationAnchor()
            #endif
        }
    }

    /// Opens OAuth flow for the given provider and returns the JWT.
    func signIn(baseURL: URL, provider: String = "google") async throws -> String {
        let loginURL = baseURL.appendingPathComponent("auth/login/\(provider)")
        var components = URLComponents(url: loginURL, resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "platform", value: "ios")]

        guard let url = components.url else { throw URLError(.badURL) }

        let callbackURL = try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<URL, Error>) in
            let session = ASWebAuthenticationSession(
                url: url,
                callback: .customScheme("flyfun")
            ) { url, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let url {
                    continuation.resume(returning: url)
                } else {
                    continuation.resume(throwing: URLError(.cancelled))
                }
            }
            session.presentationContextProvider = self
            session.prefersEphemeralWebBrowserSession = false
            self.authSession = session
            session.start()
        }

        guard let token = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false)?
            .queryItems?.first(where: { $0.name == "token" })?.value,
              !token.isEmpty
        else {
            throw URLError(.userAuthenticationRequired)
        }
        return token
    }
}
```

### 3. AppState (JWT Storage + Auth State)

Store the JWT in Keychain using `CodableSecureStorage` from rzutils:

```swift
import Foundation
import RZUtilsSwift

@Observable @MainActor
final class AppState {
    @ObservationIgnored
    private var secureStorage = CodableSecureStorage<String, String>(
        key: "jwt", service: "your.bundle.id"
    )

    private(set) var jwt: String?
    var isAuthenticated: Bool { jwt != nil }

    init() {
        jwt = secureStorage.wrappedValue
    }

    func handleAuthCallback(url: URL) {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.host == "auth",
              let token = components.queryItems?.first(where: { $0.name == "token" })?.value,
              !token.isEmpty
        else { return }
        secureStorage.wrappedValue = token
        jwt = token
    }

    func logout() {
        secureStorage.wrappedValue = nil
        jwt = nil
    }
}
```

### 4. Authenticated API Requests

Attach the JWT as a Bearer token on all API requests:

```swift
var request = URLRequest(url: url)
request.setValue("Bearer \(jwt)", forHTTPHeaderField: "Authorization")
```

Handle 401 responses by prompting re-login (token expired).

### 5. Login View

Show sign-in buttons for each provider:

```swift
struct LoginView: View {
    @Environment(AppState.self) private var appState
    @State private var isSigningIn = false
    @State private var errorMessage: String?
    private let authService = AuthService()

    var body: some View {
        VStack(spacing: 24) {
            // App branding...

            Button("Sign in with Google") {
                Task { await signIn(provider: "google") }
            }

            // Apple Sign-In button (optional, see below)
        }
    }

    private func signIn(provider: String) async {
        isSigningIn = true
        defer { isSigningIn = false }
        do {
            let token = try await authService.signIn(
                baseURL: APIConfig.baseURL, provider: provider
            )
            let url = URL(string: "flyfun://auth/callback?token=\(token)")!
            appState.handleAuthCallback(url: url)
        } catch {
            if (error as? ASWebAuthenticationSessionError)?.code != .canceledLogin {
                errorMessage = error.localizedDescription
            }
        }
    }
}
```

### 6. App Entry Point

Wire up the `onOpenURL` handler and gate content on auth state:

```swift
@main
struct MyApp: App {
    @State private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            if appState.isAuthenticated {
                ContentView()
            } else {
                LoginView()
            }
        }
        .environment(appState)
        .onOpenURL { url in
            appState.handleAuthCallback(url: url)
        }
    }
}
```

## Apple Sign-In

Two approaches:

### Option A: Web OAuth (simpler, same as Google)

Use the same `ASWebAuthenticationSession` flow with `provider: "apple"`:
```swift
authService.signIn(baseURL: baseURL, provider: "apple")
```

The server handles the Apple OAuth flow identically to Google. This requires the Apple Service ID and private key configured on the server (see server env vars below).

### Option B: Native ASAuthorizationAppleIDProvider (polished UX)

Uses the native iOS Apple Sign-In button and sends the identity token directly to the server:

```swift
import AuthenticationServices

func handleAppleSignIn() {
    let request = ASAuthorizationAppleIDProvider().createRequest()
    request.requestedScopes = [.fullName, .email]
    // Present via ASAuthorizationController...
    // On success, POST identity token to /auth/apple/token
}
```

The server endpoint `POST /auth/apple/token` accepts:
```json
{
    "identity_token": "eyJhbGc...",
    "first_name": "Jane",
    "last_name": "Doe"
}
```
and returns `{"token": "jwt...", "user_id": "uuid"}`.

**Recommendation:** Start with Option A. Upgrade to Option B later for a more polished experience.

## Server Environment Variables

For Google OAuth (already configured):
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`

For Apple Sign-In (needed for both options):
- `APPLE_CLIENT_ID` — Service ID from Apple Developer Console
- `APPLE_TEAM_ID` — your Apple Developer Team ID
- `APPLE_KEY_ID` — private key ID
- `APPLE_PRIVATE_KEY` — PEM-formatted ES256 private key
- `APPLE_APP_IDS` — comma-separated bundle IDs for native token validation (Option B only)

## Xcode Setup Checklist

- [ ] Register custom URL scheme in `Info.plist`
- [ ] Add `Sign in with Apple` capability (if using native Apple Sign-In)
- [ ] Import `RZUtilsSwift` for `CodableSecureStorage`
- [ ] Ensure `App Transport Security` allows your API domain (HTTPS is fine by default)

## References

- Server auth module: [auth.md](./auth.md)
- Database schema: [db.md](./db.md)
- Reference implementation: flyfun-weather iOS app (`Services/AuthService.swift`, `App/AppState.swift`)
