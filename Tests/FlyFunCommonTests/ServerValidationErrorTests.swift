import Foundation
import Testing
@testable import FlyFunCommon

@Suite("ServerValidationError")
struct ServerValidationErrorTests {

    @Test func decodesFastAPIDetailEnvelope() throws {
        let json = """
        {
          "detail": [
            {"field": "extra_fields.dob", "error": "invalid date", "value": "2025-13-40"},
            {"field": "crew[0].id_number", "error": "required"}
          ]
        }
        """.data(using: .utf8)!

        let envelope = try JSONDecoder().decode(ServerValidationErrorResponse.self, from: json)
        #expect(envelope.detail.count == 2)
        #expect(envelope.detail[0].field == "extra_fields.dob")
        #expect(envelope.detail[0].error == "invalid date")
        #expect(envelope.detail[0].value == "2025-13-40")
        #expect(envelope.detail[1].value == nil)
    }

    @Test func roundTripsThroughCoder() throws {
        let original = ServerValidationError(field: "f", error: "e", value: "v")
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(ServerValidationError.self, from: data)
        #expect(decoded == original)
    }

    @Test func idCombinesFieldAndError() {
        let err = ServerValidationError(field: "x.y", error: "bad")
        #expect(err.id == "x.y:bad")
    }
}
