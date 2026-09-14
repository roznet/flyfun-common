import Foundation

/// One selectable timezone for a date/time picker, carrying a display label
/// whose UTC offset was resolved for a specific instant.
///
/// The label is built for an instant rather than for "now" on purpose: a zone's
/// offset depends on the date (`Europe/Paris` is GMT+1 in January and GMT+2 in
/// July), so a picker that labels its options from the current date misreports
/// every flight planned across a DST boundary.
public struct ZonedTimeZoneOption: Identifiable, Hashable, Sendable {
    public var id: String { identifier }

    /// IANA identifier, e.g. `"Europe/Paris"`, or `"UTC"`.
    public let identifier: String

    /// Display label, e.g. `"Paris (GMT+2)"`, or `"UTC"`.
    public let label: String

    public init(identifier: String, label: String) {
        self.identifier = identifier
        self.label = label
    }
}
