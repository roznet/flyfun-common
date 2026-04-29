import Foundation
import RZUtilsSwift

/// Keychain-backed `BearerTokenStore`. Each instance partitions by
/// `service` (use the host app's bundle identifier or similar).
public final class KeychainBearerTokenStore: BearerTokenStore, @unchecked Sendable {
    private enum Key: String { case bearerToken }

    private let lock = NSLock()
    private var storage: CodableSecureStorage<Key, String>

    public init(service: String, accessGroup: String? = nil) {
        self.storage = CodableSecureStorage(
            key: .bearerToken,
            service: service,
            accessGroup: accessGroup
        )
    }

    public var token: String? {
        get { lock.withLock { storage.wrappedValue } }
        set { lock.withLock { storage.wrappedValue = newValue } }
    }
}
