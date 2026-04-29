import Foundation

/// Storage for an authenticated user's Bearer JWT.
///
/// Implementations must be thread-safe — `RollingBearerSession` reads
/// and writes the token from arbitrary contexts (URL response handlers,
/// UI, login flows). Implementations are simple enough that an `NSLock`
/// is sufficient; an actor would force async access at every call site
/// (including UI init), which isn't worth the formality for one optional
/// string.
///
/// The store is purely a value holder — it does not decide what to do
/// when the token is missing or rejected. That belongs to the caller
/// (typically via `RollingBearerSession`'s `onUnauthorized` callback).
public protocol BearerTokenStore: AnyObject, Sendable {
    var token: String? { get set }
}

/// In-memory token store. Useful for tests and for callers that manage
/// persistence themselves.
public final class InMemoryBearerTokenStore: BearerTokenStore, @unchecked Sendable {
    private let lock = NSLock()
    private var _token: String?

    public init(initialToken: String? = nil) {
        self._token = initialToken
    }

    public var token: String? {
        get { lock.withLock { _token } }
        set { lock.withLock { _token = newValue } }
    }
}
