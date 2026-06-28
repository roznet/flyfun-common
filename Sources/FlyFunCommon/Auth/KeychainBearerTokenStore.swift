import Foundation
import RZUtilsSwift

/// Keychain-backed `BearerTokenStore`. Each instance partitions by
/// `service` (use the host app's bundle identifier or similar).
public final class KeychainBearerTokenStore: BearerTokenStore, @unchecked Sendable {
    private enum Key: String { case bearerToken }

    private let lock = NSLock()
    private var storage: CodableSecureStorage<Key, String>

    public init(service: String, accessGroup: String? = nil) {
        // Bind the token to this device: accessible only after first unlock and
        // never migrated to another device via encrypted backup or iCloud
        // Keychain. A session JWT should not survive a restore onto new hardware.
        self.storage = CodableSecureStorage(
            key: .bearerToken,
            service: service,
            accessGroup: accessGroup,
            accessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        )
    }

    public var token: String? {
        get { lock.withLock { storage.wrappedValue } }
        set { lock.withLock { storage.wrappedValue = newValue } }
    }
}
