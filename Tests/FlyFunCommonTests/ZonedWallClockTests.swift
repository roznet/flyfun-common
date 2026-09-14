import Foundation
import Testing
@testable import FlyFunCommon

private func iso(_ string: String) -> Date {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime]
    return formatter.date(from: string)!
}

/// A device-timezone date at noon for the given Y/M/D, matching how
/// `ZonedWallClock.dateProxy` is produced and read back.
private func deviceDate(_ year: Int, _ month: Int, _ day: Int) -> Date {
    var components = DateComponents()
    components.year = year
    components.month = month
    components.day = day
    components.hour = 12
    return Calendar.current.date(from: components)!
}

@Suite("ZonedWallClock offsets and minutes")
struct ZonedWallClockFormattingTests {

    @Test func formatsWholeHourOffsets() {
        #expect(ZonedWallClock.formatOffset(120) == "GMT+2")
        #expect(ZonedWallClock.formatOffset(0) == "GMT+0")
        #expect(ZonedWallClock.formatOffset(-480) == "GMT-8")
    }

    @Test func formatsFractionalHourOffsets() {
        #expect(ZonedWallClock.formatOffset(-330) == "GMT-5:30")
        #expect(ZonedWallClock.formatOffset(330) == "GMT+5:30")
        #expect(ZonedWallClock.formatOffset(345) == "GMT+5:45")
    }

    @Test func minuteOptionsFollowTheStep() {
        #expect(ZonedWallClock.minuteOptions(step: 15) == [0, 15, 30, 45])
        #expect(ZonedWallClock.minuteOptions(step: 5).count == 12)
        #expect(ZonedWallClock.minuteOptions(step: 1).count == 60)
    }

    @Test func minuteOptionsClampAnOutOfRangeStep() {
        #expect(ZonedWallClock.minuteOptions(step: 0) == ZonedWallClock.minuteOptions(step: 1))
        #expect(ZonedWallClock.minuteOptions(step: 999) == [0])
    }

    @Test func nearestMinuteSnapsToTheClosestOption() {
        #expect(ZonedWallClock.nearestMinuteOption(7, step: 15) == 0)
        #expect(ZonedWallClock.nearestMinuteOption(8, step: 15) == 15)
        #expect(ZonedWallClock.nearestMinuteOption(22, step: 15) == 15)
        #expect(ZonedWallClock.nearestMinuteOption(23, step: 15) == 30)
        #expect(ZonedWallClock.nearestMinuteOption(45, step: 15) == 45)
        #expect(ZonedWallClock.nearestMinuteOption(37, step: 5) == 35)
        #expect(ZonedWallClock.nearestMinuteOption(38, step: 5) == 40)
    }

    /// A minute past the last option snaps back down rather than rolling into
    /// the next hour, so a picker selection stays inside the displayed hour.
    @Test func nearestMinuteStaysWithinTheHour() {
        #expect(ZonedWallClock.nearestMinuteOption(58, step: 15) == 45)
        #expect(ZonedWallClock.nearestMinuteOption(59, step: 5) == 55)
    }
}

@Suite("ZonedWallClock DST handling")
struct ZonedWallClockDSTTests {

    @Test func wallClockBuildsCorrectUTCInSummer() {
        // 09:00 on 2026-07-15 in Paris is CEST (GMT+2), so 07:00Z.
        let clock = ZonedWallClock(instant: iso("2026-01-01T00:00:00Z"), timeZoneId: "Europe/Paris")
            .settingDateProxy(deviceDate(2026, 7, 15))
            .settingHour(9)
            .settingMinute(0)
        #expect(clock.instant == iso("2026-07-15T07:00:00Z"))
    }

    @Test func wallClockBuildsCorrectUTCInWinter() {
        // 09:00 on 2026-01-15 in Paris is CET (GMT+1), so 08:00Z. The offset is
        // resolved for the displayed date, not for today.
        let clock = ZonedWallClock(instant: iso("2026-07-01T00:00:00Z"), timeZoneId: "Europe/Paris")
            .settingDateProxy(deviceDate(2026, 1, 15))
            .settingHour(9)
            .settingMinute(0)
        #expect(clock.instant == iso("2026-01-15T08:00:00Z"))
    }

    @Test func offsetLabelFollowsTheDateNotToday() {
        let summer = ZonedWallClock.label(for: "Europe/Paris", at: iso("2026-07-15T12:00:00Z"))
        let winter = ZonedWallClock.label(for: "Europe/Paris", at: iso("2026-01-15T12:00:00Z"))
        #expect(summer == "Paris (GMT+2)")
        #expect(winter == "Paris (GMT+1)")
    }

    @Test func labelsFractionalZonesWithMinutes() {
        #expect(ZonedWallClock.label(for: "Asia/Kolkata", at: iso("2026-07-15T12:00:00Z"))
            == "Kolkata (GMT+5:30)")
    }

    @Test func labelsUTCPlainly() {
        #expect(ZonedWallClock.label(for: "UTC", at: iso("2026-07-15T12:00:00Z")) == "UTC")
    }
}

@Suite("ZonedWallClock instant preservation")
struct ZonedWallClockInstantTests {

    @Test func switchingTimeZonePreservesTheInstant() {
        let paris = ZonedWallClock(instant: iso("2026-01-01T00:00:00Z"), timeZoneId: "Europe/Paris")
            .settingDateProxy(deviceDate(2026, 7, 15))
            .settingHour(9)
            .settingMinute(0)

        let utc = paris.settingTimeZone("UTC")
        #expect(utc.instant == paris.instant)
        #expect(utc.hour == 7)
        #expect(utc.minute == 0)
    }

    /// The bug the old fixed-offset picker could not express: moving the time
    /// backwards across local midnight has to move the UTC day too, not wrap
    /// the clock within the same day.
    @Test func crossingMidnightBackwardsMovesTheDay() {
        // 09:00 Paris on 15 July, moved to 00:00 Paris, is 22:00Z on the 14th.
        let clock = ZonedWallClock(instant: iso("2026-07-15T07:00:00Z"), timeZoneId: "Europe/Paris")
            .settingHour(0)
        #expect(clock.instant == iso("2026-07-14T22:00:00Z"))
        // Still the 15th where the pilot is reading it.
        #expect(clock.dateProxy == deviceDate(2026, 7, 15))
    }

    @Test func crossingMidnightForwardsMovesTheDay() {
        // 23:00 on 31 December in New York is 04:00Z on 1 January.
        let clock = ZonedWallClock(instant: iso("2026-12-31T17:00:00Z"), timeZoneId: "America/New_York")
            .settingHour(23)
            .settingMinute(0)
        #expect(clock.instant == iso("2027-01-01T04:00:00Z"))
    }

    @Test func settingTheDateKeepsTheTimeOfDay() {
        let clock = ZonedWallClock(instant: iso("2026-07-15T07:00:00Z"), timeZoneId: "Europe/Paris")
            .settingDateProxy(deviceDate(2026, 8, 1))
        #expect(clock.hour == 9)
        #expect(clock.minute == 0)
        #expect(clock.instant == iso("2026-08-01T07:00:00Z"))
    }

    @Test func unknownZoneFallsBackToGMTRatherThanTrapping() {
        let clock = ZonedWallClock(instant: iso("2026-07-15T07:00:00Z"), timeZoneId: "Not/AZone")
        #expect(clock.hour == 7)
        #expect(clock.timeZone.secondsFromGMT(for: clock.instant) == 0)
    }

    @Test func minuteOptionSnapsTheDisplayedMinute() {
        let clock = ZonedWallClock(instant: iso("2026-07-15T07:37:00Z"))
        #expect(clock.minute == 37)
        #expect(clock.minuteOption(step: 15) == 30)
        #expect(clock.minuteOption(step: 5) == 35)
    }

    /// Paris leaves summer time on 25 October 2026: 02:00-03:00 happens twice,
    /// first at GMT+2 (00:00-01:00Z) and again at GMT+1 (01:00-02:00Z).
    @Test func editingTheSecondOccurrenceOfARepeatedHourStaysOnIt() {
        let second = ZonedWallClock(instant: iso("2026-10-25T01:30:00Z"), timeZoneId: "Europe/Paris")
        #expect(second.hour == 2)
        #expect(second.settingMinute(45).instant == iso("2026-10-25T01:45:00Z"))
        #expect(second.settingMinute(30).instant == second.instant)
    }

    @Test func editingTheFirstOccurrenceOfARepeatedHourStaysOnIt() {
        let first = ZonedWallClock(instant: iso("2026-10-25T00:30:00Z"), timeZoneId: "Europe/Paris")
        #expect(first.hour == 2)
        #expect(first.settingMinute(45).instant == iso("2026-10-25T00:45:00Z"))
    }

    @Test func leavingTheRepeatedHourStillChangesTheOffset() {
        // From the second 02:30 (GMT+1) to 01:30, which only exists at GMT+2.
        let second = ZonedWallClock(instant: iso("2026-10-25T01:30:00Z"), timeZoneId: "Europe/Paris")
        #expect(second.settingHour(1).instant == iso("2026-10-24T23:30:00Z"))
    }
}

@Suite("ZonedWallClock timezone options")
struct ZonedWallClockOptionsTests {

    @Test func optionsAlwaysLeadWithUTC() {
        let options = ZonedWallClock.timeZoneOptions(
            for: ["Europe/Paris", "Europe/London"],
            at: iso("2026-07-15T12:00:00Z")
        )
        #expect(options.map(\.identifier) == ["UTC", "Europe/Paris", "Europe/London"])
    }

    @Test func optionsDeduplicateAndKeepOrder() {
        let options = ZonedWallClock.timeZoneOptions(
            for: ["Europe/Paris", "Europe/Paris", "UTC", "Europe/London"],
            at: iso("2026-07-15T12:00:00Z")
        )
        #expect(options.map(\.identifier) == ["UTC", "Europe/Paris", "Europe/London"])
    }

    @Test func adoptsThePreferredZoneWhileStillOnTheUTCDefault() {
        let resolved = ZonedWallClock.resolvedTimeZoneId(
            current: "UTC",
            available: ["Europe/Paris", "Europe/London"],
            preferred: "Europe/Paris"
        )
        #expect(resolved == "Europe/Paris")
    }

    @Test func keepsAnExplicitSelectionWhenTheRouteChanges() {
        // The pilot picked London; adding Paris as the new departure must not
        // silently move them off it.
        let resolved = ZonedWallClock.resolvedTimeZoneId(
            current: "Europe/London",
            available: ["Europe/Paris", "Europe/London"],
            preferred: "Europe/Paris"
        )
        #expect(resolved == "Europe/London")
    }

    @Test func fallsBackWhenTheSelectionIsNoLongerOffered() {
        let resolved = ZonedWallClock.resolvedTimeZoneId(
            current: "Europe/Paris",
            available: ["America/New_York"],
            preferred: "America/New_York"
        )
        #expect(resolved == "America/New_York")
    }

    @Test func fallsBackToUTCWhenNothingIsPreferred() {
        #expect(ZonedWallClock.resolvedTimeZoneId(
            current: "Europe/Paris", available: [], preferred: nil) == "UTC")
        // A preferred zone that is not actually on offer is not adopted either.
        #expect(ZonedWallClock.resolvedTimeZoneId(
            current: "Europe/Paris", available: [], preferred: "Europe/Berlin") == "UTC")
    }

    @Test func utcIsAlwaysSelectable() {
        #expect(ZonedWallClock.resolvedTimeZoneId(
            current: "UTC", available: [], preferred: nil) == "UTC")
    }
}
