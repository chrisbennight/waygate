//! The one set of operator-facing timestamp formatters.
//!
//! Before this module, `format_ts_abs` was copy-pasted ~21× across
//! `waygate-admin` (plus RFC 3339 variants under three names), and the
//! two `format_ts_rel` shapes had drifted: one rendered a future
//! timestamp as an absolute date, the other clamped it to "0s ago".
//! Every hand-rendered dashboard/API timestamp goes through here; CI
//! fails on any new local `fn format_ts*` definition
//! (`scripts/check-no-local-ts-formatters.sh`).

use time::OffsetDateTime;

/// Absolute timestamp at seconds precision (`2026-07-02 21:14:09Z`) for
/// tooltips, table cells, and drawer headers. Hand-formatted so callers
/// don't each pull in `time::format_description`.
pub fn format_ts_abs(ts: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
        ts.year(),
        u8::from(ts.month()),
        ts.day(),
        ts.hour(),
        ts.minute(),
        ts.second(),
    )
}

/// Relative age (`4m ago` / `2h ago` / `3d ago`) — the density operators
/// expect from a tailable log view.
///
/// Unified contract (resolves a pre-consolidation fork):
/// - a **future** timestamp renders absolute — never `0s ago`, which
///   hid clock skew and future-dated rows;
/// - anything **older than 30 days** renders absolute, so
///   stale-but-queried rows stay unambiguous;
/// - otherwise buckets by seconds / minutes / hours / days.
pub fn format_ts_rel(ts: OffsetDateTime) -> String {
    let now = OffsetDateTime::now_utc();
    let delta = (now - ts).whole_seconds();
    if delta < 0 {
        return format_ts_abs(ts);
    }
    if delta < 60 {
        return format!("{delta}s ago");
    }
    if delta < 3600 {
        return format!("{}m ago", delta / 60);
    }
    if delta < 86_400 {
        return format!("{}h ago", delta / 3600);
    }
    if delta < 30 * 86_400 {
        return format!("{}d ago", delta / 86_400);
    }
    format_ts_abs(ts)
}

/// Strict RFC 3339 (`2026-07-02T21:14:09Z`) for machine-readable API
/// fields. Falls back to the raw unix timestamp on a formatting error
/// (unrepresentable year) rather than panicking in a render path.
pub fn format_ts_rfc3339(ts: OffsetDateTime) -> String {
    ts.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| ts.unix_timestamp().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    #[test]
    fn abs_is_seconds_precision_utc() {
        let ts = OffsetDateTime::from_unix_timestamp(0).unwrap();
        assert_eq!(format_ts_abs(ts), "1970-01-01 00:00:00Z");
    }

    #[test]
    fn rel_buckets_by_age() {
        let now = OffsetDateTime::now_utc();
        // (age, expected suffix) table — pins the bucket boundaries.
        let table = [
            (Duration::seconds(10), "s ago"),
            (Duration::seconds(59), "s ago"),
            (Duration::seconds(60), "m ago"),
            (Duration::minutes(59), "m ago"),
            (Duration::hours(1), "h ago"),
            (Duration::hours(23), "h ago"),
            (Duration::days(1), "d ago"),
            (Duration::days(29), "d ago"),
        ];
        for (age, suffix) in table {
            let out = format_ts_rel(now - age);
            assert!(out.ends_with(suffix), "age {age}: got {out}");
        }
    }

    #[test]
    fn rel_falls_back_to_absolute_past_thirty_days() {
        let now = OffsetDateTime::now_utc();
        let out = format_ts_rel(now - Duration::days(31));
        assert!(out.ends_with('Z'), "expected absolute, got {out}");
    }

    #[test]
    fn rel_renders_future_timestamps_absolute_not_zero_seconds() {
        // The pre-consolidation fork: one copy clamped a future ts to
        // "0s ago", the other fell back to absolute. Absolute wins —
        // "0s ago" hides clock skew and future-dated rows.
        let now = OffsetDateTime::now_utc();
        let out = format_ts_rel(now + Duration::hours(2));
        assert!(out.ends_with('Z'), "expected absolute, got {out}");
    }

    #[test]
    fn rfc3339_shape_and_fallback_are_stable() {
        let ts = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        assert_eq!(format_ts_rfc3339(ts), "2023-11-14T22:13:20Z");
    }
}
