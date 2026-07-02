import Foundation
import Testing
@testable import FlyFunCommon

@Suite("AuthCallbackParser")
struct AuthCallbackParserTests {

    @Test func extractsTokenFromCustomScheme() {
        let parser = AuthCallbackParser(customScheme: "flyfunforms")
        let url = URL(string: "flyfunforms://auth?token=abc.def.ghi")!
        #expect(parser.token(from: url) == "abc.def.ghi")
    }

    @Test func rejectsCustomSchemeWithWrongHost() {
        let parser = AuthCallbackParser(customScheme: "flyfunforms")
        let url = URL(string: "flyfunforms://other?token=abc")!
        #expect(parser.token(from: url) == nil)
    }

    @Test func rejectsCustomSchemeWithDifferentScheme() {
        let parser = AuthCallbackParser(customScheme: "flyfunforms")
        let url = URL(string: "flyfunweather://auth?token=abc")!
        #expect(parser.token(from: url) == nil)
    }

    @Test func rejectsMissingToken() {
        let parser = AuthCallbackParser(customScheme: "flyfunforms")
        let url = URL(string: "flyfunforms://auth?other=abc")!
        #expect(parser.token(from: url) == nil)
    }

    @Test func rejectsEmptyToken() {
        let parser = AuthCallbackParser(customScheme: "flyfunforms")
        let url = URL(string: "flyfunforms://auth?token=")!
        #expect(parser.token(from: url) == nil)
    }

    @Test func extractsTokenFromUniversalLink() {
        let parser = AuthCallbackParser(
            customScheme: "flyfunweather",
            universalLinkHost: "weather.flyfun.aero"
        )
        let url = URL(string: "https://weather.flyfun.aero/auth/callback?token=xyz")!
        #expect(parser.token(from: url) == "xyz")
    }

    @Test func universalLinkRespectsConfiguredPaths() {
        let parser = AuthCallbackParser(
            customScheme: "flyfunweather",
            universalLinkHost: "weather.flyfun.aero",
            universalLinkPaths: ["/auth/callback"]
        )
        let url = URL(string: "https://weather.flyfun.aero/callback?token=xyz")!
        #expect(parser.token(from: url) == nil)
    }

    @Test func universalLinkRequiresMatchingHost() {
        let parser = AuthCallbackParser(
            customScheme: "flyfunweather",
            universalLinkHost: "weather.flyfun.aero"
        )
        let url = URL(string: "https://evil.example.com/auth/callback?token=xyz")!
        #expect(parser.token(from: url) == nil)
    }

    // MARK: - Auth-code flow

    @Test func extractsCodeAndStateFromCustomScheme() {
        let parser = AuthCallbackParser(customScheme: "flyfunweather")
        let url = URL(string: "flyfunweather://auth/callback?code=one-time-code&state=nonce123")!
        let result = parser.codeAndState(from: url)
        #expect(result?.code == "one-time-code")
        #expect(result?.state == "nonce123")
    }

    @Test func extractsCodeWithoutState() {
        let parser = AuthCallbackParser(customScheme: "flyfunweather")
        let url = URL(string: "flyfunweather://auth/callback?code=one-time-code")!
        let result = parser.codeAndState(from: url)
        #expect(result?.code == "one-time-code")
        #expect(result?.state == nil)
    }

    @Test func codeAndStateRejectsMissingCode() {
        let parser = AuthCallbackParser(customScheme: "flyfunweather")
        let url = URL(string: "flyfunweather://auth/callback?state=nonce123")!
        #expect(parser.codeAndState(from: url) == nil)
    }

    @Test func codeAndStateRejectsWrongScheme() {
        let parser = AuthCallbackParser(customScheme: "flyfunweather")
        let url = URL(string: "evilapp://auth/callback?code=stolen")!
        #expect(parser.codeAndState(from: url) == nil)
    }

    @Test func codeAndStateFromUniversalLink() {
        let parser = AuthCallbackParser(
            customScheme: "flyfunweather",
            universalLinkHost: "weather.flyfun.aero"
        )
        let url = URL(string: "https://weather.flyfun.aero/auth/callback?code=c1&state=s1")!
        let result = parser.codeAndState(from: url)
        #expect(result?.code == "c1")
        #expect(result?.state == "s1")
    }
}
