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
    ///
    /// This is the legacy bare-token shape. Kept only for the App Store
    /// reviewer deep link (a `scope:"review"` token) — the normal sign-in now
    /// uses the code/state exchange below.
    public func token(from url: URL) -> String? {
        queryValue(from: url, name: "token")
    }

    /// Returns `(code, state)` for the auth-code deep-link flow, or nil if the
    /// URL isn't one of our recognized callbacks or carries no `code`. `state`
    /// is optional (older callbacks may omit it) but is verified by the caller
    /// against the value it generated before starting the flow.
    public func codeAndState(from url: URL) -> (code: String, state: String?)? {
        guard let code = queryValue(from: url, name: "code") else { return nil }
        return (code, queryValue(from: url, name: "state"))
    }

    /// True if `url` matches our custom-scheme or universal-link callback shape.
    private func isRecognizedCallback(_ components: URLComponents) -> Bool {
        let isCustomScheme = components.scheme == customScheme && components.host == "auth"
        let isUniversalLink: Bool = {
            guard let host = universalLinkHost else { return false }
            return components.scheme == "https"
                && components.host == host
                && universalLinkPaths.contains(components.path)
        }()
        return isCustomScheme || isUniversalLink
    }

    /// Extracts a non-empty query value from a recognized callback URL.
    private func queryValue(from url: URL, name: String) -> String? {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              isRecognizedCallback(components),
              let value = components.queryItems?.first(where: { $0.name == name })?.value,
              !value.isEmpty
        else { return nil }
        return value
    }
}
