//! Pins the pure guards of out-of-band capture
//! ([`super::record_out_of_band_policy_snapshot`]): drift detection, the
//! in-flight-write defer, and the re-read recordability guard.
use waygate_policy::PolicyPointer;

use super::{policy_disk_drifted_from_active, policy_source_is_recordable, policy_write_in_flight};

// `read_policy_dir` appends one '\n' per file, so a single-file disk set's
// source is `content + "\n"` (the canonical mirror form, asserted by
// `write_then_read_matches_canonical_disk_hash`).
fn disk_source_of(content: &str) -> String {
    format!("{content}\n")
}

#[test]
fn not_drifted_when_active_matches_disk() {
    let c = "permit(principal, action, resource);";
    assert!(!policy_disk_drifted_from_active(c, &disk_source_of(c)));
}

#[test]
fn drifted_when_active_differs_from_disk() {
    let active = "permit(principal, action, resource);";
    let disk = "forbid(principal, action, resource);";
    assert!(policy_disk_drifted_from_active(
        active,
        &disk_source_of(disk)
    ));
}

#[test]
fn not_drifted_for_imported_active_with_trailing_newlines() {
    // `--import-policies` stores `read_policy_dir().source` VERBATIM, which
    // already carries read_policy_dir's per-file `\n` (and `\n\n` when the
    // source file itself ended in a newline). An imported
    // active bundle whose bytes equal disk must NOT read as drift — the old
    // canonical-hash check appended an EXTRA newline and falsely captured a
    // `filesystem` snapshot on every imported deploy's first boot/SIGHUP.
    let content = "permit(principal, action, resource);";
    let imported_one_nl = format!("{content}\n"); // disk file had no own trailing \n
    let imported_two_nl = format!("{content}\n\n"); // disk file had its own trailing \n
    assert!(
        !policy_disk_drifted_from_active(&imported_one_nl, &imported_one_nl),
        "an imported bundle equal to disk (one trailing newline) is not drift",
    );
    assert!(
        !policy_disk_drifted_from_active(&imported_two_nl, &imported_two_nl),
        "an imported bundle equal to disk (file's own + read newline) is not drift",
    );
    // A publish-form bundle (no trailing newline) vs the same single-file disk
    // (one trailing newline) is also not drift — trailing-newline-insensitive.
    assert!(!policy_disk_drifted_from_active(content, &imported_one_nl));
}

#[test]
fn not_drifted_when_active_content_unparseable() {
    // Never synthesize a convergence row off an unparseable ledger row.
    assert!(!policy_disk_drifted_from_active(
        "this is not valid cedar {{{",
        "whatever",
    ));
}

fn pointer_at(updated_at: time::OffsetDateTime) -> PolicyPointer {
    PolicyPointer {
        tenant_id: "default".into(),
        current_hash: "h".into(),
        updated_at,
        updated_by: None,
    }
}

#[test]
fn write_in_flight_for_a_recently_advanced_pointer() {
    let now = time::OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
    let recent = pointer_at(now - time::Duration::seconds(2));
    assert!(policy_write_in_flight(Some(&recent), now));
}

#[test]
fn not_in_flight_for_an_old_pointer_or_absent_pointer() {
    let now = time::OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
    let old = pointer_at(now - time::Duration::seconds(120));
    assert!(!policy_write_in_flight(Some(&old), now));
    assert!(
        !policy_write_in_flight(None, now),
        "an absent pointer (fresh deploy) is not an in-flight write",
    );
}

#[test]
fn recordable_only_for_a_parseable_nonempty_source() {
    assert!(
        policy_source_is_recordable("permit(principal, action, resource);"),
        "a valid, non-empty policy set is recordable",
    );
    assert!(
        !policy_source_is_recordable(""),
        "empty disk must not be recorded into the ledger",
    );
    assert!(
        !policy_source_is_recordable("// only a comment, zero policies\n"),
        "a zero-policy set must not be recorded (deny-all/allow-all hazard)",
    );
    assert!(
        !policy_source_is_recordable("garbage {{{ not cedar"),
        "an unparseable re-read must not be recorded",
    );
}
