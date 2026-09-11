//! Typed env-var readers for boot-time config.
//!
//! `waygate-server/src/config.rs` hand-rolled the same
//! `env::var → parse → context → default → floor/ceiling bail` chain at ~90
//! sites, each with its own error phrasing. These helpers are the single
//! copy of that chain for the duration family, bool flags, and
//! ranged integers. String-enum vars and the paired-var keyring
//! family intentionally keep their bespoke parsers — their error text /
//! relational validation is the value, not duplication.
//!
//! Contract, matching the shipped behavior exactly: **reject at boot, never
//! clamp**. A garbage or out-of-range value is a configuration error the
//! operator must fix — silently clamping would hide the mistake and run
//! with a value the operator didn't choose. Unset ⇒ the documented default.
//! Per-variable operator guidance (why the floor exists, "use 0 to
//! disable") is passed as `hint` so the boot error stays as rich as the
//! hand-rolled messages were.
//!
//! Errors implement `Display` with the full operator message; callers
//! (anyhow-based `Config::from_env`) bubble them with `?` after an
//! `Into`/`map_err` at the call site.

use std::fmt;
use std::ops::RangeInclusive;
use std::time::Duration;

/// A rejected env value: which variable, what was wrong, and the
/// per-variable operator hint. `Display` is the boot-error message.
#[derive(Debug, thiserror::Error)]
pub struct EnvVarError {
    name: &'static str,
    kind: EnvVarErrorKind,
    /// Extra operator guidance appended in parentheses (e.g. why the floor
    /// exists, or "use 0 to disable"). Empty ⇒ omitted.
    hint: &'static str,
}

#[derive(Debug)]
enum EnvVarErrorKind {
    NotAnInteger {
        value: String,
    },
    OutOfRange {
        secs: u64,
        range: RangeInclusive<u64>,
    },
    BelowFloor {
        secs: u64,
        floor: u64,
    },
}

impl fmt::Display for EnvVarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            EnvVarErrorKind::NotAnInteger { value } => {
                write!(f, "{}={value} is not an integer", self.name)?;
            }
            EnvVarErrorKind::OutOfRange { secs, range } => {
                if *range.end() == u64::MAX {
                    // Floor-only range: "below Ns floor" reads better than a
                    // range whose end is u64::MAX.
                    write!(f, "{}={secs} below {}s floor", self.name, range.start())?;
                } else {
                    write!(
                        f,
                        "{}={secs} out of range ({}..={})",
                        self.name,
                        range.start(),
                        range.end()
                    )?;
                }
            }
            EnvVarErrorKind::BelowFloor { secs, floor } => {
                write!(f, "{}={secs} below {floor}s floor", self.name)?;
            }
        }
        if !self.hint.is_empty() {
            write!(f, " ({})", self.hint)?;
        }
        Ok(())
    }
}

/// Read a required-in-range duration: unset ⇒ `default` seconds; set ⇒ must
/// parse as `u64` and fall inside `range`, else a boot error. `hint` is
/// appended to any rejection (pass `""` for none).
pub fn duration_secs(
    name: &'static str,
    default: u64,
    range: RangeInclusive<u64>,
    hint: &'static str,
) -> Result<Duration, EnvVarError> {
    let secs = read_u64(name, default, hint)?;
    if !range.contains(&secs) {
        return Err(EnvVarError {
            name,
            kind: EnvVarErrorKind::OutOfRange { secs, range },
            hint,
        });
    }
    Ok(Duration::from_secs(secs))
}

/// Read a zero-disables duration: unset ⇒ `default` seconds; `0` ⇒
/// `Ok(None)` (feature disabled); otherwise must be ≥ `floor`, else a boot
/// error. `hint` is appended to any rejection — conventionally it explains
/// the floor and names the `0`-to-disable escape hatch.
pub fn duration_secs_zero_disables(
    name: &'static str,
    default: u64,
    floor: u64,
    hint: &'static str,
) -> Result<Option<Duration>, EnvVarError> {
    let secs = read_u64(name, default, hint)?;
    if secs == 0 {
        return Ok(None);
    }
    if secs < floor {
        return Err(EnvVarError {
            name,
            kind: EnvVarErrorKind::BelowFloor { secs, floor },
            hint,
        });
    }
    Ok(Some(Duration::from_secs(secs)))
}

/// Read a default-OFF boolean flag: truthy values are exactly
/// `1` / `true` / `yes` (the workspace's uniform opt-in grammar); anything
/// else — including unset — is `false`. Never errors: an unrecognized value
/// is "off", matching every hand-rolled site this replaces.
pub fn bool_default_off(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

/// Read a default-ON boolean flag: falsey values are exactly
/// `0` / `false` / `no` / `off`; anything else — including unset — is
/// `true`. The canonical falsey set unifies the two hand-rolled variants
/// (one accepted `off`, one didn't — drift, not intent).
pub fn bool_default_on(name: &str) -> bool {
    std::env::var(name)
        .map(|v| !matches!(v.as_str(), "0" | "false" | "no" | "off"))
        .unwrap_or(true)
}

/// Read an optional free-form string: unset or empty/whitespace-only yields
/// `None`, so callers parse a present value or take their documented
/// default without touching `std::env` directly (the raw-read ratchet's
/// prescribed path for enum-valued settings).
pub fn optional(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Read a comma-separated string list. Unset yields owned copies of
/// `default`; an explicitly empty value yields an empty list. Whitespace and
/// empty entries are removed, while case and ordering are preserved so the
/// caller can apply domain-specific normalization.
pub fn csv_default(name: &str, default: &[&str]) -> Vec<String> {
    match std::env::var(name) {
        Ok(raw) => raw
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::to_owned)
            .collect(),
        Err(_) => default.iter().map(|entry| (*entry).to_owned()).collect(),
    }
}

/// Read a required-in-range integer (the non-duration numeric family:
/// counts, RFC-constrained codes, buffer sizes). Same contract as
/// [`duration_secs`]: unset ⇒ `default`; garbage or out-of-range ⇒ boot
/// error carrying `hint`.
pub fn u64_in(
    name: &'static str,
    default: u64,
    range: RangeInclusive<u64>,
    hint: &'static str,
) -> Result<u64, EnvVarError> {
    let value = read_u64(name, default, hint)?;
    if !range.contains(&value) {
        return Err(EnvVarError {
            name,
            kind: EnvVarErrorKind::OutOfRange { secs: value, range },
            hint,
        });
    }
    Ok(value)
}

fn read_u64(name: &'static str, default: u64, hint: &'static str) -> Result<u64, EnvVarError> {
    match std::env::var(name) {
        Err(_) => Ok(default),
        // No trim: a whitespace-padded value (" 60") is rejected, exactly as
        // the hand-rolled call sites this replaces behaved. Padding usually
        // means a compose/YAML quoting mistake — reject loudly rather than
        // guess (trimming here would silently widen the accepted grammar).
        Ok(raw) => raw.parse::<u64>().map_err(|_| EnvVarError {
            name,
            kind: EnvVarErrorKind::NotAnInteger { value: raw },
            hint,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Env-var tests mutate process-global state; each test uses a UNIQUE
    // variable name so parallel test threads can't race each other.

    #[test]
    fn bool_flags_use_the_exact_flag_grammars() {
        assert!(!bool_default_off("GWENV_TEST_BOOL_OFF_UNSET"));
        std::env::set_var("GWENV_TEST_BOOL_OFF_YES", "yes");
        assert!(bool_default_off("GWENV_TEST_BOOL_OFF_YES"));
        std::env::set_var("GWENV_TEST_BOOL_OFF_JUNK", "enabled");
        assert!(
            !bool_default_off("GWENV_TEST_BOOL_OFF_JUNK"),
            "unrecognized = off"
        );

        assert!(bool_default_on("GWENV_TEST_BOOL_ON_UNSET"));
        std::env::set_var("GWENV_TEST_BOOL_ON_OFF", "off");
        assert!(!bool_default_on("GWENV_TEST_BOOL_ON_OFF"));
        std::env::set_var("GWENV_TEST_BOOL_ON_JUNK", "enabled");
        assert!(
            bool_default_on("GWENV_TEST_BOOL_ON_JUNK"),
            "unrecognized = on"
        );
    }

    #[test]
    fn csv_default_distinguishes_unset_empty_and_populated() {
        assert_eq!(
            csv_default("GWENV_TEST_CSV_UNSET", &["default"]),
            vec!["default"]
        );
        std::env::set_var("GWENV_TEST_CSV_EMPTY", "");
        assert!(csv_default("GWENV_TEST_CSV_EMPTY", &["default"]).is_empty());
        std::env::set_var("GWENV_TEST_CSV_VALUES", " One, ,Two ");
        assert_eq!(
            csv_default("GWENV_TEST_CSV_VALUES", &["default"]),
            vec!["One", "Two"]
        );
    }

    #[test]
    fn u64_in_rejects_out_of_range_with_hint() {
        std::env::set_var("GWENV_TEST_U64_FACILITY", "24");
        let e = u64_in("GWENV_TEST_U64_FACILITY", 16, 0..=23, "RFC 5424 §6.2.1").unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("0..=23") && msg.contains("RFC 5424"), "{msg}");
        assert_eq!(
            u64_in("GWENV_TEST_U64_FACILITY_UNSET", 16, 0..=23, "").unwrap(),
            16
        );
    }

    #[test]
    fn unset_yields_default() {
        let d = duration_secs("GWENV_TEST_DUR_UNSET", 20, 1..=600, "").unwrap();
        assert_eq!(d, Duration::from_secs(20));
        let z = duration_secs_zero_disables("GWENV_TEST_DUR_UNSET_Z", 3600, 60, "").unwrap();
        assert_eq!(z, Some(Duration::from_secs(3600)));
    }

    #[test]
    fn whitespace_padded_value_is_rejected_like_the_hand_rolled_sites() {
        std::env::set_var("GWENV_TEST_DUR_PADDED", " 60");
        let e = duration_secs("GWENV_TEST_DUR_PADDED", 20, 1..=600, "").unwrap_err();
        assert!(e.to_string().contains("not an integer"), "{e}");
    }

    #[test]
    fn garbage_is_rejected_not_defaulted() {
        std::env::set_var("GWENV_TEST_DUR_GARBAGE", "soon");
        let e = duration_secs("GWENV_TEST_DUR_GARBAGE", 20, 1..=600, "").unwrap_err();
        assert!(e.to_string().contains("not an integer"), "{e}");
    }

    #[test]
    fn out_of_range_is_rejected_not_clamped_and_names_the_range() {
        std::env::set_var("GWENV_TEST_DUR_RANGE", "601");
        let e = duration_secs("GWENV_TEST_DUR_RANGE", 20, 1..=600, "").unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("601") && msg.contains("1..=600"), "{msg}");
    }

    #[test]
    fn zero_disables_and_floor_rejects_with_hint() {
        std::env::set_var("GWENV_TEST_DUR_ZERO", "0");
        assert_eq!(
            duration_secs_zero_disables("GWENV_TEST_DUR_ZERO", 3600, 60, "").unwrap(),
            None
        );
        std::env::set_var("GWENV_TEST_DUR_FLOOR", "10");
        let e = duration_secs_zero_disables("GWENV_TEST_DUR_FLOOR", 3600, 60, "use 0 to disable")
            .unwrap_err();
        let msg = e.to_string();
        assert!(
            msg.contains("below 60s floor") && msg.contains("use 0 to disable"),
            "{msg}"
        );
    }
}
