import Foundation
import RZUtilsSwift

/// Keychain-backed `BearerTokenStore`. Each instance partitions by
/// `service` (use the host app's bundle identifier or similar).
public actor KeychainBearerTokenStore: BearerTokenStore {
    private enum Key: String { case bearerToken }

    private var storage: CodableSecureStorage<Key, String>

    public init(service: String, accessGroup: String? = nil) {
        self.storage = CodableSecureStorage(
            key: .bearerToken,
            service: service,
            accessGroup: accessGroup
        )
    }

    public var token: String? {
        storage.wrappedValue
    }

    public func setToken(_ token: String?) {
        storage.wrappedValue = token
    }
}
