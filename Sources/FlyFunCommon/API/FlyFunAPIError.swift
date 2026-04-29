import Foundation

public enum FlyFunAPIError: LocalizedError, Sendable {
    case unauthorized
    case forbidden(String?)
    case notFound
    case validationErrors([ServerValidationError])
    case serverError(Int, String?)
    case networkError(any Error & Sendable)
    case decodingError(any Error & Sendable)

    public var errorDescription: String? {
        switch self {
        case .unauthorized:
            return String(localized: "Session expired. Please sign in again.")
        case .forbidden(let message):
            return message ?? String(localized: "Forbidden.")
        case .notFound:
            return String(localized: "Not found.")
        case .validationErrors(let errors):
            return errors.map { "• \($0.field): \($0.error)" }.joined(separator: "\n")
        case .serverError(let code, let message):
            return String(localized: "Server error (\(code)): \(message ?? "unknown")")
        case .networkError(let error):
            return error.localizedDescription
        case .decodingError(let error):
            return String(localized: "Decoding error: \(error.localizedDescription)")
        }
    }
}
