import Foundation

/// A timezone-aware wall-clock over an absolute instant.
///
/// The single source of truth is ``instant``. The wall-clock (date, hour,
/// minute) is *derived* by reading that instant in ``timeZoneId``, and every
/// edit rebuilds the instant from the wall-clock interpreted in that same zone.
/// Two behaviours fall out of that, and they are the point of the type:
///
/// - Switching the timezone preserves the instant and re-displays it, rather
///   than reinterpreting the digits on screen as a different moment.
/// - Editing is DST-correct for the *displayed date* rather than for today.
///   `Calendar.date(from:)` and `TimeZone.secondsFromGMT(for:)` both resolve
///   the offset for the actual date, so a summer `Europe/Paris` is GMT+2 and a
///   winter one GMT+1 with no special casing.
///
/// Rebuilds carry the full date, so a time edit that crosses midnight in the
/// selected zone moves the day instead of wrapping within it. A picker built on
/// a fixed offset and a bare `HH:mm` cannot express that, which is the class of
/// bug this type exists to remove.
///
/// This is a value type: every edit returns a new `ZonedWallClock`. A SwiftUI
/// view can derive one from a `Binding<Date>` plus view-local zone state on
/// each render, so there is no second copy of the time to keep in sync.
public struct ZonedWallClock: Hashable, Sendable {

    /// The absolute instant. Everything else is derived from it.
    public var instant: Date

    /// IANA identifier the wall-clock is read and written in, e.g.
    /// `"Europe/Paris"`. Defaults to UTC. An unknown identifier falls back to
    /// GMT rather than trapping, so a stale stored zone degrades to a readable
    /// time instead of crashing.
    public var timeZoneId: String

    public init(instant: Date, timeZoneId: String = Self.utcIdentifier) {
        self.instant = instant
        self.timeZoneId = timeZoneId
    }

    public static let utcIdentifier = "UTC"

    public var timeZone: TimeZone { TimeZone(identifier: timeZoneId) ?? .gmt }

    private var calendar: Calendar {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        return calendar
    }

    // MARK: - Derived wall-clock

    public var hour: Int { calendar.component(.hour, from: instant) }

    public var minute: Int { calendar.component(.minute, from: instant) }

    /// The wall-clock minute snapped to the nearest option a picker of `step`
    /// offers. A `Picker` selection has to match one of its tags, so a stored
    /// 14:37 shown in a 15-minute picker must resolve to 30 rather than leave
    /// the control blank.
    public func minuteOption(step: Int) -> Int {
        Self.nearestMinuteOption(minute, step: step)
    }

    /// A proxy `Date` for a `DatePicker`, which always renders in the device's
    /// own timezone.
    ///
    /// It carries the selected zone's calendar day re-expressed in the device
    /// zone, so the picker shows the correct year/month/day whatever timezone
    /// the device is in. Noon is used to keep the value clear of midnight and
    /// DST transitions in the device zone, where a date-only picker would
    /// otherwise be able to land on a wall-clock time that does not exist.
    public var dateProxy: Date {
        let components = calendar.dateComponents([.year, .month, .day], from: instant)
        var deviceComponents = DateComponents()
        deviceComponents.year = components.year
        deviceComponents.month = components.month
        deviceComponents.day = components.day
        deviceComponents.hour = 12
        return Calendar.current.date(from: deviceComponents) ?? instant
    }

    // MARK: - Edits

    /// Move to `newHour` on the same displayed day, in the selected zone.
    public func settingHour(_ newHour: Int) -> ZonedWallClock {
        rebuilding(hour: newHour)
    }

    /// Move to `newMinute` within the same displayed hour, in the selected zone.
    public func settingMinute(_ newMinute: Int) -> ZonedWallClock {
        rebuilding(minute: newMinute)
    }

    /// Adopt the calendar day of `proxy`, keeping the displayed time of day.
    ///
    /// `proxy` is read in the *device* timezone, matching what ``dateProxy``
    /// produces and what a `DatePicker` writes back.
    public func settingDateProxy(_ proxy: Date) -> ZonedWallClock {
        let components = Calendar.current.dateComponents([.year, .month, .day], from: proxy)
        return rebuilding(year: components.year, month: components.month, day: components.day)
    }

    /// Display the same moment in another zone.
    ///
    /// The instant is deliberately unchanged: the pilot is re-expressing a time
    /// they have already chosen, not moving the flight. The displayed
    /// hour/minute change to match.
    public func settingTimeZone(_ identifier: String) -> ZonedWallClock {
        ZonedWallClock(instant: instant, timeZoneId: identifier)
    }

    /// Rebuild the instant from the current wall-clock with the given overrides,
    /// interpreting the result in the selected zone.
    ///
    /// The full set of components is passed to `Calendar.date(from:)`, so the
    /// date moves with the time when an edit crosses midnight, and the offset
    /// is resolved for the resulting date rather than for today.
    ///
    /// A wall-clock that does not exist (the hour skipped by a spring-forward
    /// transition) is resolved by `Calendar` to the instant the transition
    /// lands on. If it cannot be resolved at all the instant is left unchanged,
    /// so an edit is dropped rather than silently jumping somewhere arbitrary.
    /// A wall-clock that exists twice (fall-back) keeps the occurrence being
    /// displayed; see ``preservingRepeatedHourOffset(_:)``.
    private func rebuilding(
        year: Int? = nil, month: Int? = nil, day: Int? = nil,
        hour: Int? = nil, minute: Int? = nil
    ) -> ZonedWallClock {
        var components = calendar.dateComponents([.year, .month, .day, .hour, .minute], from: instant)
        if let year { components.year = year }
        if let month { components.month = month }
        if let day { components.day = day }
        if let hour { components.hour = hour }
        if let minute { components.minute = minute }
        components.second = 0
        guard let rebuilt = calendar.date(from: components) else { return self }
        return ZonedWallClock(instant: preservingRepeatedHourOffset(rebuilt), timeZoneId: timeZoneId)
    }

    /// On a fall-back night one wall-clock hour happens twice, and
    /// `Calendar.date(from:)` always resolves it to the first occurrence. An
    /// edit made while displaying the *second* occurrence (setting the minute
    /// of 02:30 GMT+1 on the night Paris leaves summer time) would then jump an
    /// hour earlier. When the same wall-clock also exists at the original
    /// instant's UTC offset, keep that occurrence. Any other offset change (a
    /// date edit across a DST boundary, a spring-forward gap) is left to
    /// `Calendar`.
    private func preservingRepeatedHourOffset(_ rebuilt: Date) -> Date {
        let zone = timeZone
        let originalOffset = zone.secondsFromGMT(for: instant)
        let rebuiltOffset = zone.secondsFromGMT(for: rebuilt)
        guard rebuiltOffset != originalOffset else { return rebuilt }
        let sameWallClock = rebuilt.addingTimeInterval(TimeInterval(rebuiltOffset - originalOffset))
        return zone.secondsFromGMT(for: sameWallClock) == originalOffset ? sameWallClock : rebuilt
    }

    // MARK: - Minute options

    /// The minute values a picker of `step` offers, e.g. `[0, 15, 30, 45]`.
    ///
    /// `step` is clamped to 1...60. A step that does not divide 60 simply
    /// yields a shorter final gap rather than being rejected.
    public static func minuteOptions(step: Int) -> [Int] {
        let step = min(max(step, 1), 60)
        return Array(stride(from: 0, to: 60, by: step))
    }

    /// The option of `step` closest to `minute`.
    ///
    /// Candidates stop at 55 (for a 5-step), so a minute in the final gap snaps
    /// down to the last option rather than up to the next hour. That keeps the
    /// operation inside the displayed hour, which is what a picker selection
    /// has to do.
    public static func nearestMinuteOption(_ minute: Int, step: Int) -> Int {
        let options = minuteOptions(step: step)
        return options.min(by: { abs($0 - minute) < abs($1 - minute) }) ?? 0
    }

    // MARK: - Timezone options

    /// Build picker options for `identifiers`, labelled with each zone's offset
    /// at `instant`.
    ///
    /// UTC is always offered first: it is the zone flight plans and customs
    /// forms are filed in, so it has to remain reachable whatever the route.
    /// The rest follow in the order given, de-duplicated.
    public static func timeZoneOptions(
        for identifiers: [String],
        at instant: Date
    ) -> [ZonedTimeZoneOption] {
        var seen = Set<String>()
        var result: [ZonedTimeZoneOption] = []
        for identifier in [utcIdentifier] + identifiers where !seen.contains(identifier) {
            seen.insert(identifier)
            result.append(
                ZonedTimeZoneOption(identifier: identifier, label: label(for: identifier, at: instant))
            )
        }
        return result
    }

    /// Resolve which zone a picker should have selected, given the options now
    /// available.
    ///
    /// Guarantees the selection is always present in the options, so the
    /// control can never render blank. Two cases move it:
    ///
    /// - the current selection is no longer offered (the route changed), so it
    ///   falls back to `preferred`, else UTC;
    /// - the selection is still the untouched UTC default and `preferred` is
    ///   available, so it adopts `preferred` (typically the relevant airport's
    ///   zone).
    ///
    /// Any other selection is left alone: once the pilot has picked a zone,
    /// route changes must not silently move it.
    public static func resolvedTimeZoneId(
        current: String,
        available identifiers: [String],
        preferred: String?
    ) -> String {
        let available = Set([utcIdentifier] + identifiers)
        guard available.contains(current) else {
            return preferred.map { available.contains($0) ? $0 : utcIdentifier } ?? utcIdentifier
        }
        if current == utcIdentifier, let preferred, identifiers.contains(preferred) {
            return preferred
        }
        return current
    }

    /// `"UTC"`, or a city plus its offset at `instant`, e.g. `"Paris (GMT+2)"`.
    public static func label(for identifier: String, at instant: Date) -> String {
        guard identifier != utcIdentifier else { return utcIdentifier }
        let zone = TimeZone(identifier: identifier) ?? .gmt
        let offsetMinutes = zone.secondsFromGMT(for: instant) / 60
        let city = identifier.split(separator: "/").last
            .map { $0.replacingOccurrences(of: "_", with: " ") } ?? identifier
        return "\(city) (\(formatOffset(offsetMinutes)))"
    }

    /// Format a signed minute offset as `"GMT+2"` or `"GMT-5:30"`.
    ///
    /// Half- and quarter-hour zones (India, Nepal, Chatham) keep their minutes;
    /// whole-hour zones drop the `:00`.
    public static func formatOffset(_ offsetMinutes: Int) -> String {
        let sign = offsetMinutes >= 0 ? "+" : "-"
        let magnitude = abs(offsetMinutes)
        let hours = magnitude / 60
        let minutes = magnitude % 60
        return minutes != 0
            ? String(format: "GMT%@%d:%02d", sign, hours, minutes)
            : "GMT\(sign)\(hours)"
    }
}
