import Foundation

/// One field-level validation error as returned by FastAPI/Pydantic.
///
/// Wire format:
/// ```json
/// { "field": "extra_fields.dob", "error": "invalid date", "value": "2025-13-40" }
/// ```
public struct ServerValidationError: Codable, Identifiable, Hashable, Sendable {
    public let field: String
    public let error: String
    public let value: String?

    public var id: String { "\(field):\(error)" }

    public init(field: String, error: String, value: String? = nil) {
        self.field = field
        self.error = error
        self.value = value
    }
}

/// Envelope for FastAPI's standard 422 response body: `{ "detail": [...] }`.
public struct ServerValidationErrorResponse: Codable, Sendable {
    public let detail: [ServerValidationError]

    public init(detail: [ServerValidationError]) {
        self.detail = detail
    }
}
