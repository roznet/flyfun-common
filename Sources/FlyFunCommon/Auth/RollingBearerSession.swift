import Foundation
import OSLog

/// Closure invoked after the store has been cleared because the server
/// returned 401. Apps typically use this to route to the login screen.
public typealias UnauthorizedHandler = @Sendable () async -> Void

/// Wraps a `URLSession` to inject `Authorization: Bearer <jwt>`,
/// transparently rotate the token when the server emits a fresh one
/// in a response header, and surface a single global signal when the
/// server rejects the token.
///
/// Pair with `BearerTokenStore` (use `KeychainBearerTokenStore` for
/// production, `InMemoryBearerTokenStore` for tests).
public actor RollingBearerSession {
    /// Header the server uses to deliver a refreshed JWT mid-session.
    /// Mirrors `flyfun_common.auth.middleware`'s sliding-session refresh
    /// for cookie-based clients.
    public static let renewedTokenHeader = "X-Renewed-Token"

    private static let logger = Logger(subsystem: "aero.flyfun.common", category: "RollingBearerSession")

    private let store: any BearerTokenStore
    private let session: URLSession
    private let onUnauthorized: UnauthorizedHandler?

    public init(
        store: any BearerTokenStore,
        session: URLSession = .shared,
        onUnauthorized: UnauthorizedHandler? = nil
    ) {
        self.store = store
        self.session = session
        self.onUnauthorized = onUnauthorized
    }

    /// Performs the request with rolling-Bearer behavior:
    /// 1. Injects `Authorization: Bearer <token>` if the request doesn't already set one.
    /// 2. If the response includes `X-Renewed-Token`, persists it via the store.
    /// 3. On 401, clears the store, fires `onUnauthorized`, then throws `.unauthorized`.
    /// 4. Returns the raw `(Data, HTTPURLResponse)` for any other status — the
    ///    caller maps endpoint-specific codes (e.g. 404, 422) to its own errors.
    public func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        var req = request
        if req.value(forHTTPHeaderField: "Authorization") == nil,
           let token = store.token {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: req)
        } catch {
            throw FlyFunAPIError.networkError(error)
        }

        guard let http = response as? HTTPURLResponse else {
            throw FlyFunAPIError.networkError(URLError(.badServerResponse))
        }

        if let renewed = http.value(forHTTPHeaderField: Self.renewedTokenHeader),
           !renewed.isEmpty {
            Self.logger.debug("Rolling JWT forward via \(Self.renewedTokenHeader)")
            store.token = renewed
        }

        if http.statusCode == 401 {
            Self.logger.info("401 from \(req.url?.absoluteString ?? "unknown") — clearing token")
            store.token = nil
            await onUnauthorized?()
            throw FlyFunAPIError.unauthorized
        }

        return (data, http)
    }
}
