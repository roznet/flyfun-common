import Foundation

/// Parses post-OAuth callback URLs of the shape used by all flyfun apps:
///
/// - Custom scheme: `<scheme>://auth?token=<jwt>` (e.g. `flyfunforms://auth?token=...`)
/// - Universal link: `https://<host><path>?token=<jwt>` (e.g. `https://weather.flyfun.aero/auth/callback?token=...`)
public struct AuthCallbackParser: Sendable {
    public let customScheme: String
    public let universalLinkHost: String?
    public let universalLinkPaths: Set<String>

    public init(
        customScheme: String,
        universalLinkHost: String? = nil,
        universalLinkPaths: Set<String> = ["/callback", "/auth/callback"]
    ) {
        self.customScheme = customScheme
        self.universalLinkHost = universalLinkHost
        self.universalLinkPaths = universalLinkPaths
    }

    /// Returns the JWT if `url` is one of our recognized auth callbacks; nil otherwise.
    public func token(from url: URL) -> String? {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return nil
        }

        let isCustomScheme = components.scheme == customScheme && components.host == "auth"
        let isUniversalLink: Bool = {
            guard let host = universalLinkHost else { return false }
            return components.scheme == "https"
                && components.host == host
                && universalLinkPaths.contains(components.path)
        }()

        guard isCustomScheme || isUniversalLink else { return nil }

        guard let token = components.queryItems?.first(where: { $0.name == "token" })?.value,
              !token.isEmpty
        else { return nil }

        return token
    }
}
