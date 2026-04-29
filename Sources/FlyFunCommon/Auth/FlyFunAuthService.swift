import AuthenticationServices
import Foundation
import OSLog

#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

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

    private static let logger = Logger(subsystem: "aero.flyfun.common", category: "FlyFunAuthService")

    public let config: Config

    /// Strong reference so the session isn't deallocated mid-flow.
    private var authSession: ASWebAuthenticationSession?

    public init(config: Config) {
        self.config = config
        super.init()
    }

    // MARK: - OAuth (Google, etc. via ASWebAuthenticationSession)

    /// Opens the OAuth flow for `provider` and returns the JWT token.
    public func signIn(provider: String = "google") async throws -> String {
        let loginURL = config.baseURL.appendingPathComponent("auth/login/\(provider)")
        var components = URLComponents(url: loginURL, resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "platform", value: "ios"),
            URLQueryItem(name: "scheme", value: config.callbackScheme),
        ]

        guard let url = components.url else { throw URLError(.badURL) }
        Self.logger.info("Starting OAuth flow (\(provider)) to \(url)")

        let callbackURL: URL = try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: url,
                callback: .customScheme(config.callbackScheme)
            ) { url, error in
                if let error {
                    Self.logger.error("OAuth error: \(error.localizedDescription)")
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
        guard let token = parser.token(from: callbackURL) else {
            Self.logger.error("No token in callback URL: \(callbackURL)")
            throw URLError(.userAuthenticationRequired)
        }
        return token
    }

    // MARK: - Apple Sign-In

    /// Exchanges an Apple credential (from `SignInWithAppleButton`) with the
    /// server for a JWT.
    public func exchangeAppleCredential(_ credential: ASAuthorizationAppleIDCredential) async throws -> String {
        guard let identityTokenData = credential.identityToken,
              let identityToken = String(data: identityTokenData, encoding: .utf8)
        else {
            Self.logger.error("No identity token in Apple credential")
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
            Self.logger.error("Apple token exchange failed (\(http.statusCode)): \(detail)")
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
            Self.logger.error("Account deletion failed (\(http.statusCode)): \(detail)")
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
