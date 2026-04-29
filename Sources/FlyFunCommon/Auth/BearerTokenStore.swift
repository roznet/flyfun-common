import Foundation

/// Storage for an authenticated user's Bearer JWT.
///
/// Implementations are actors so the token can be safely read and rotated
/// from any context (URL response handlers, UI, login flows). The store
/// is purely a value holder — it does not decide what to do when the
/// token is missing or rejected. That belongs to the caller (typically
/// via `RollingBearerSession`'s `onUnauthorized` callback).
public protocol BearerTokenStore: Actor {
    var token: String? { get }
    func setToken(_ token: String?)
}

/// In-memory token store. Useful for tests and for callers that manage
/// persistence themselves.
public actor InMemoryBearerTokenStore: BearerTokenStore {
    public private(set) var token: String?

    public init(initialToken: String? = nil) {
        self.token = initialToken
    }

    public func setToken(_ token: String?) {
        self.token = token
    }
}
