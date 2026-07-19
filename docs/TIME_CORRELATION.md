# Timeline and Server Clock Correlation

## Purpose

Incident systems frequently have the wrong wall clock, wrong configured timezone, or both. The Timeline keeps the source value intact, calculates a defensible UTC instant, and lets an investigator reuse a measured server-clock correction instead of manually subtracting time for every log entry.

## Accepted timestamp input

All clock-style input uses 24-hour time. The preferred human-readable form is:

```text
DD-MM-YYYY HH:mm:ss.SSS
```

Time is optional after the date. Omitted components are zero-filled:

| Input | Interpreted components |
|---|---|
| `18-07-2026` | `18-07-2026 00:00:00.000` |
| `18-07-2026 14` | `18-07-2026 14:00:00.000` |
| `18-07-2026 14:05` | `18-07-2026 14:05:00.000` |
| `18-07-2026 14:05:03` | `18-07-2026 14:05:03.000` |
| `18-07-2026 14:05:03.127` | millisecond precision |

The parser also accepts:

- ISO/RFC 3339 with `Z` or an explicit offset, such as `2026-07-18T07:05:03.127Z`;
- ISO date order for unzoned values, such as `2026-07-18 14:05:03`;
- Unix epoch seconds, including decimal seconds;
- Unix epoch milliseconds;
- Unix epoch microseconds; and
- Unix epoch nanoseconds.

RFC 3339 offsets and Unix epochs define an absolute instant, so the adjacent timezone selection does not reinterpret them.

## Timezone input and display

A timezone may be:

- `UTC`;
- a fixed offset such as `+07:00` or `UTC-05:30`; or
- an IANA timezone such as `Asia/Novosibirsk` or `Europe/London`.

IANA zones apply the historical daylight-saving rule for the event date. A local time that occurs twice during a backward clock transition is rejected until the investigator supplies an explicit RFC 3339/fixed offset. A time skipped by a forward transition is also rejected.

Both corrected incident time and normalized server/evidence time use `DD-MM-YYYY HH:mm:ss.SSS` and show two values:

1. the selected display zone; and
2. UTC, or the workstation's local IANA zone when UTC is selected.

Events without a known corrected time remain in the table but are omitted from the graphical time axis until the correct time is added.

## Optional event times and direct correlation

The server/evidence timestamp and the known real/correct timestamp are independent optional fields. An investigator may save an event with either one, both, or neither and add the missing values later.

- With only server time, the app stores and displays its normalized local/UTC interpretation, but the corrected incident time remains unknown.
- With only correct time, the app records the canonical incident time without claiming a server-clock reading.
- With both, the app calculates and records a direct per-event correction (`correct UTC - server UTC`).
- As an alternative to directly entering correct time, select a saved server-clock profile. A profile requires a server timestamp and cannot be combined with direct correct time on the same event.

## Server clock profile workflow

Create a profile from two observations made at the same real instant:

1. **Server time shown** — the server wall-clock/log value and the timezone in which it should initially be interpreted.
2. **Known-correct time** — the investigator, trusted time source, or reference-system time and its independent timezone.

The correction is:

```text
offset_ms = correct_reference_utc_ms - server_reference_utc_ms
corrected_event_utc_ms = interpreted_server_event_utc_ms + offset_ms
```

Example: if the server displays `10:00:00.000` when the correct time is `10:01:30.000`, the stored correction is `+00:01:30.000`. A later raw event at server time `11:00:00.000` becomes `11:01:30.000` UTC after timezone interpretation.

## Stored and exported data

`clock_profiles` stores both typed reference values, both timezone identifiers, both interpreted UTC values, the calculated millisecond offset, description, and timestamps.

Each `timeline_events` row stores:

- `raw_timestamp` — unchanged investigator/log input;
- `raw_timezone` — selected zone used to interpret an unzoned value;
- `server_timestamp_utc` — normalized server/evidence time before correction;
- `correct_timestamp_raw` and `correct_timezone` — optional directly observed real time and its interpretation zone;
- `clock_profile_id` — optional reusable correction source;
- `clock_offset_ms` — correction copied at the time the event was saved;
- `time_precision` — precision of the server/evidence value;
- `correct_time_precision` — precision of directly entered real time; and
- `timestamp` — corrected canonical UTC RFC 3339 value with milliseconds, or empty while correct time is unknown.

Copying the offset into the event prevents a later profile edit from silently rewriting already recorded evidence. Editing and resaving the event explicitly recalculates it. Clock profiles and timeline fields are included in plain/encrypted snapshots, the read-only text renderer, local audit history, and expert change bundles.

## Forensic boundary

Clock correlation documents an investigator's normalization decision; it does not prove the server clock was constant between reference observations. For drifting or manually changed clocks, create separate profiles for separate periods and document the source of each reference measurement.
