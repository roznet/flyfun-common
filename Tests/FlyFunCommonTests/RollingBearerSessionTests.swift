import Foundation
import Testing
@testable import FlyFunCommon

@Suite("RollingBearerSession", .serialized)
struct RollingBearerSessionTests {

    private static func makeSession(
        token: String? = nil,
        onUnauthorized: UnauthorizedHandler? = nil
    ) -> (RollingBearerSession, InMemoryBearerTokenStore) {
        let store = InMemoryBearerTokenStore(initialToken: token)
        let session = RollingBearerSession(
            store: store,
            session: URLSession.stubbed(),
            onUnauthorized: onUnauthorized
        )
        return (session, store)
    }

    private static func ok(_ url: URL, headers: [String: String] = [:], body: String = "{}") -> (HTTPURLResponse, Data) {
        let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: headers)!
        return (response, Data(body.utf8))
    }

    private static func status(_ code: Int, url: URL, body: String = "") -> (HTTPURLResponse, Data) {
        let response = HTTPURLResponse(url: url, statusCode: code, httpVersion: "HTTP/1.1", headerFields: nil)!
        return (response, Data(body.utf8))
    }

    @Test func injectsBearerHeaderWhenTokenPresent() async throws {
        let (rolling, _) = Self.makeSession(token: "tok-123")
        let url = URL(string: "https://example.com/x")!
        nonisolated(unsafe) var seenAuth: String?
        StubURLProtocol.setHandler { req in
            seenAuth = req.value(forHTTPHeaderField: "Authorization")
            return Self.ok(url)
        }
        defer { StubURLProtocol.setHandler(nil) }

        _ = try await rolling.data(for: URLRequest(url: url))
        #expect(seenAuth == "Bearer tok-123")
    }

    @Test func skipsBearerHeaderWhenStoreEmpty() async throws {
        let (rolling, _) = Self.makeSession(token: nil)
        let url = URL(string: "https://example.com/x")!
        nonisolated(unsafe) var seenAuth: String?
        StubURLProtocol.setHandler { req in
            seenAuth = req.value(forHTTPHeaderField: "Authorization")
            return Self.ok(url)
        }
        defer { StubURLProtocol.setHandler(nil) }

        _ = try await rolling.data(for: URLRequest(url: url))
        #expect(seenAuth == nil)
    }

    @Test func doesNotOverwriteCallerProvidedAuthHeader() async throws {
        let (rolling, _) = Self.makeSession(token: "tok-123")
        let url = URL(string: "https://example.com/x")!
        nonisolated(unsafe) var seenAuth: String?
        StubURLProtocol.setHandler { req in
            seenAuth = req.value(forHTTPHeaderField: "Authorization")
            return Self.ok(url)
        }
        defer { StubURLProtocol.setHandler(nil) }

        var req = URLRequest(url: url)
        req.setValue("Bearer custom", forHTTPHeaderField: "Authorization")
        _ = try await rolling.data(for: req)
        #expect(seenAuth == "Bearer custom")
    }

    @Test func rotatesTokenFromRenewedHeader() async throws {
        let (rolling, store) = Self.makeSession(token: "old")
        let url = URL(string: "https://example.com/x")!
        StubURLProtocol.setHandler { _ in
            Self.ok(url, headers: [RollingBearerSession.renewedTokenHeader: "new"])
        }
        defer { StubURLProtocol.setHandler(nil) }

        _ = try await rolling.data(for: URLRequest(url: url))
        #expect(store.token == "new")
    }

    @Test func unauthorizedClearsStoreFiresCallbackAndThrows() async throws {
        actor Box { var fired = false; func fire() { fired = true } }
        let box = Box()
        let handler: UnauthorizedHandler = { await box.fire() }

        let (rolling, store) = Self.makeSession(token: "tok", onUnauthorized: handler)
        let url = URL(string: "https://example.com/x")!
        StubURLProtocol.setHandler { _ in Self.status(401, url: url) }
        defer { StubURLProtocol.setHandler(nil) }

        await #expect(throws: FlyFunAPIError.self) {
            _ = try await rolling.data(for: URLRequest(url: url))
        }
        let fired = await box.fired
        #expect(store.token == nil)
        #expect(fired == true)
    }

    @Test func nonAuthErrorsReturnRawResponseToCaller() async throws {
        let (rolling, _) = Self.makeSession(token: "tok")
        let url = URL(string: "https://example.com/x")!
        StubURLProtocol.setHandler { _ in Self.status(404, url: url, body: "{\"detail\": \"nope\"}") }
        defer { StubURLProtocol.setHandler(nil) }

        let (data, http) = try await rolling.data(for: URLRequest(url: url))
        #expect(http.statusCode == 404)
        #expect(String(data: data, encoding: .utf8)?.contains("nope") == true)
    }
}
