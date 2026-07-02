import AuthenticationServices
import Foundation
import OSLog
import Security

#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

// Module-scope so it stays nonisolated and can be touched from the
// ASWebAuthenticationSession completion handler (which runs on Apple's
// XPC queue, not MainActor).
private let logger = Logger(subsystem: "aero.flyfun.common", category: "FlyFunAuthService")

/// OAuth + Apple Sign-In client for flyfun-common-protected servers.
///
/// Hosts a single instance per app, configured with the server's base URL
/// and the app's custom URL scheme used for the OAuth callback.
@MainActor
public final class FlyFunAuthService: NSObject, ASWebAuthenticationPresentationContextProviding {
    public struct Config: Sendable {
        public let baseURL: URL
        /// Custom URL scheme registered by the app (e.g. `flyfunforms`,
        /// `flyfunweather`). Used both as the `?scheme=` parameter in the
        /// authorize URL and as the callback's URL scheme.
        public let callbackScheme: String

        public init(baseURL: URL, callbackScheme: String) {
            self.baseURL = baseURL
            self.callbackScheme = callbackScheme
        }
    }

    public let config: Config

    /// Strong reference so the session isn't deallocated mid-flow.
    private var authSession: ASWebAuthenticationSession?

    public init(config: Config) {
        self.config = config
        super.init()
    }

    // MARK: - OAuth (Google, etc. via ASWebAuthenticationSession)

    /// Opens the OAuth flow for `provider` and returns the JWT token.
    ///
    /// Uses the native "authorization code" pattern: the server callback hands
    /// back a short-TTL `code` bound to a client-generated `state` nonce (never
    /// the token itself), which we verify and exchange for the session JWT over
    /// an HTTPS POST. This keeps the bearer token out of URLs and closes the
    /// login-CSRF vector an injected callback would otherwise open.
    public func signIn(provider: String = "google") async throws -> String {
        let state = Self.generateState()
        let loginURL = config.baseURL.appendingPathComponent("auth/login/\(provider)")
        var components = URLComponents(url: loginURL, resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "platform", value: "ios"),
            URLQueryItem(name: "scheme", value: config.callbackScheme),
            URLQueryItem(name: "state", value: state),
        ]

        guard let url = components.url else { throw URLError(.badURL) }
        logger.info("Starting OAuth flow (\(provider)) to \(url)")

        let callbackURL: URL = try await withCheckedThrowingContinuation { continuation in
            // The completion handler is invoked by ASWebAuthenticationSession on
            // its own XPC queue — must NOT inherit MainActor isolation from this
            // @MainActor class, or the Swift 6 runtime trips on
            // _swift_task_checkIsolatedSwift. @Sendable strips the inherited
            // isolation; we keep all touched state inside the closure (the
            // continuation is Sendable, the logger is Sendable).
            let session = ASWebAuthenticationSession(
                url: url,
                callback: .customScheme(config.callbackScheme)
            ) { @Sendable url, error in
                if let error {
                    logger.error("OAuth error: \(error.localizedDescription)")
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

        let parser = AuthCallbackParser(customScheme: config.callbackScheme)
        guard let (code, returnedState) = parser.codeAndState(from: callbackURL) else {
            logger.error("No auth code in callback URL: \(callbackURL)")
            throw URLError(.userAuthenticationRequired)
        }
        // Reject a callback whose state doesn't match the one we generated —
        // an injected/forged callback can't satisfy this.
        guard returnedState == state else {
            logger.error("OAuth state mismatch — rejecting callback")
            throw URLError(.userAuthenticationRequired)
        }
        return try await exchangeCode(code: code, state: state)
    }

    /// Trades a one-time auth code for the session JWT over HTTPS POST.
    private func exchangeCode(code: String, state: String) async throws -> String {
        let url = config.baseURL.appendingPathComponent("auth/exchange")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(
            withJSONObject: ["code": code, "state": state]
        )

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw URLError(.badServerResponse)
        }
        guard http.statusCode == 200 else {
            let detail = String(data: data, encoding: .utf8) ?? "Unknown error"
            logger.error("Auth-code exchange failed (\(http.statusCode)): \(detail)")
            throw URLError(.userAuthenticationRequired)
        }
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let token = json["token"] as? String
        else {
            throw URLError(.cannotParseResponse)
        }
        return token
    }

    /// A URL-safe random `state` nonce (matches the server's
    /// `[A-Za-z0-9_-]{8,128}` validation).
    private static func generateState() -> String {
        var bytes = [UInt8](repeating: 0, count: 24)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    // MARK: - Apple Sign-In

    /// Exchanges an Apple credential (from `SignInWithAppleButton`) with the
    /// server for a JWT.
    public func exchangeAppleCredential(_ credential: ASAuthorizationAppleIDCredential) async throws -> String {
        guard let identityTokenData = credential.identityToken,
              let identityToken = String(data: identityTokenData, encoding: .utf8)
        else {
            logger.error("No identity token in Apple credential")
            throw URLError(.userAuthenticationRequired)
        }

        // Apple only provides the name on the very first authorization.
        let firstName = credential.fullName?.givenName
        let lastName = credential.fullName?.familyName

        return try await exchangeAppleToken(
            identityToken: identityToken,
            firstName: firstName,
            lastName: lastName
        )
    }

    private func exchangeAppleToken(
        identityToken: String,
        firstName: String?,
        lastName: String?
    ) async throws -> String {
        let url = config.baseURL.appendingPathComponent("auth/apple/token")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        var body: [String: String] = ["identity_token": identityToken]
        if let firstName { body["first_name"] = firstName }
        if let lastName { body["last_name"] = lastName }
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let http = response as? HTTPURLResponse else {
            throw URLError(.badServerResponse)
        }
        guard http.statusCode == 200 else {
            let detail = String(data: data, encoding: .utf8) ?? "Unknown error"
            logger.error("Apple token exchange failed (\(http.statusCode)): \(detail)")
            throw URLError(.userAuthenticationRequired)
        }

        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let token = json["token"] as? String
        else {
            throw URLError(.cannotParseResponse)
        }
        return token
    }

    // MARK: - Magic-link (email OTP)

    /// Requests a magic-link email containing a 6-digit OTP. Server always
    /// responds 200 (no account enumeration); a non-200 response means a
    /// real failure (rate-limit, Apple Private Relay, etc.).
    public func requestMagicLinkCode(email: String) async throws {
        let url = config.baseURL.appendingPathComponent("auth/magic-link/request")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body: [String: String] = [
            "email": email,
            "platform": "ios",
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw URLError(.badServerResponse)
        }
        guard http.statusCode == 200 else {
            let detail = String(data: data, encoding: .utf8) ?? "Unknown error"
            logger.error("Magic-link request failed (\(http.statusCode)): \(detail)")
            throw URLError(.badServerResponse)
        }
    }

    /// Exchanges the email + 6-digit OTP code for a JWT. The returned
    /// token can be stored in `KeychainBearerTokenStore` directly.
    public func consumeMagicLinkCode(email: String, code: String) async throws -> String {
        let url = config.baseURL.appendingPathComponent("auth/magic-link/consume-code")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body: [String: String] = ["email": email, "code": code]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw URLError(.badServerResponse)
        }
        guard http.statusCode == 200 else {
            let detail = String(data: data, encoding: .utf8) ?? "Unknown error"
            logger.error("Magic-link consume failed (\(http.statusCode)): \(detail)")
            throw URLError(.userAuthenticationRequired)
        }
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let token = json["token"] as? String
        else {
            throw URLError(.cannotParseResponse)
        }
        return token
    }

    // MARK: - Account deletion

    /// Permanently deletes the authenticated user on the server. Caller is
    /// responsible for clearing local state afterwards.
    public func deleteAccount(jwt: String) async throws {
        let url = config.baseURL.appendingPathComponent("auth/account")
        var request = URLRequest(url: url)
        request.httpMethod = "DELETE"
        request.setValue("Bearer \(jwt)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let http = response as? HTTPURLResponse else {
            throw URLError(.badServerResponse)
        }
        guard http.statusCode == 204 else {
            let detail = String(data: data, encoding: .utf8) ?? "Unknown error"
            logger.error("Account deletion failed (\(http.statusCode)): \(detail)")
            throw URLError(.badServerResponse)
        }
    }

    // MARK: - ASWebAuthenticationPresentationContextProviding

    nonisolated public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        MainActor.assumeIsolated {
            #if canImport(UIKit)
            let scene = UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .first
            if let key = scene?.keyWindow {
                return key
            }
            if let scene {
                return ASPresentationAnchor(windowScene: scene)
            }
            return ASPresentationAnchor()
            #elseif canImport(AppKit)
            return NSApplication.shared.keyWindow ?? ASPresentationAnchor()
            #else
            return ASPresentationAnchor()
            #endif
        }
    }
}
