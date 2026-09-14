# Zoned Date/Time

> `ZonedWallClock`: a timezone-aware wall-clock over an absolute instant, shared
> by the flyfun iOS apps' flight date/time pickers.

Related: [ios-auth.md](./ios-auth.md) (the other Swift-side shared surface).

## Intent

Flight times are absolute moments that pilots read and edit in a *chosen*
timezone: UTC for filing, local for showing up at the airfield. Represent that
as one instant plus a display zone, never as a wall-clock plus a fixed offset.

The type is deliberately small and pure. It holds no state beyond the instant
and a zone identifier, has no `@Observable` wrapper, and requires no
`@MainActor`. A SwiftUI view derives one on each render from a `Binding<Date>`
plus view-local zone state, so there is never a second copy of the time to keep
in sync.

Key exports: `ZonedWallClock`, `ZonedTimeZoneOption`

## The two behaviours that matter

**Switching the timezone preserves the instant.** The displayed hour and minute
change; the flight does not move. This is what makes a picker feel right: the
pilot is re-expressing a time they already chose.

**Editing is DST-correct for the displayed date, not for today.**
`Calendar.date(from:)` and `TimeZone.secondsFromGMT(for:)` both resolve the
offset for the actual date, so a summer `Europe/Paris` is GMT+2 and a winter one
GMT+1 with no special casing. A picker built on `TimeZone.secondsFromGMT()` with
no date argument silently uses *today's* offset and puts every flight planned
across a DST boundary an hour out.

Inside the repeated hour of a fall-back night, an edit keeps the occurrence
being displayed: `Calendar` alone would resolve 02:45 to the *first* 02:45
and move a flight shown at the second one an hour earlier.

## Why not a wall-clock plus an offset

The representation this replaces stored a calendar day and an `"HH:mm"` UTC
string. It cannot express a time edit that crosses midnight: 00:30 local Paris
is 22:30 UTC *on the previous day*, and a picker bound only to the time field
wraps the clock and leaves the date wrong. It also leaves an unanswerable
question at every call site, namely which timezone the stored day is read in,
with no compiler help to keep the answers consistent.

`ZonedWallClock` rebuilds through a full `DateComponents` including the date, so
the day moves with the time.

## API shape

Edits are value transforms, so they compose and never mutate shared state:

```swift
let clock = ZonedWallClock(instant: flight.departureInstant, timeZoneId: "Europe/Paris")
flight.departureInstant = clock.settingHour(9).settingMinute(30).instant
```

- `instant`, `timeZoneId`, `timeZone`
- derived: `hour`, `minute`, `minuteOption(step:)`, `dateProxy`
- transforms: `settingHour`, `settingMinute`, `settingDateProxy`, `settingTimeZone`
- options: `timeZoneOptions(for:at:)`, `resolvedTimeZoneId(current:available:preferred:)`
- formatting: `label(for:at:)`, `formatOffset`
- minutes: `minuteOptions(step:)`, `nearestMinuteOption(_:step:)`

### `dateProxy`

SwiftUI's `DatePicker` always renders in the device's timezone. `dateProxy`
carries the *selected* zone's calendar day re-expressed in the device zone, so
the picker shows the right year/month/day whatever timezone the device is in.
It sits at noon to stay clear of midnight and DST transitions in the device
zone, where a date-only picker could otherwise land on a wall-clock time that
does not exist.

### Timezone options

`timeZoneOptions(for:at:)` always offers UTC first: flight plans and customs
forms are filed in UTC, so it stays reachable whatever the route. Labels carry
the offset resolved at the given instant.

`resolvedTimeZoneId` guarantees the picker's selection is always present in its
options, so the control can never render blank. It moves the selection in two
cases only: when the current one is no longer offered, and when it is still the
untouched UTC default and a preferred zone is available. An explicit choice is
never silently overridden by a route change.

## Consumers

- **flyfun-forms** — `FlightDateTimeField`, used for departure and arrival in
  `FlightEditView` and `NewFlightFlow`.
- **flyfun-weather** — not yet. Its `DepartureTimeModel` predates this type and
  implements the same semantics independently; migrating it is a
  behaviour-neutral follow-up.
