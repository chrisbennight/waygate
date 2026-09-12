//! Guard: the workspace `migrations/` directory must hold exactly one file per
//! sqlx version (the leading integer prefix). Test-only — it exists purely to
//! turn a duplicate version into a red `cargo test` instead of a prod boot.
//!
//! The test reads the directory embedded by `sqlx::migrate!` and rejects
//! duplicate versions. Parallel branches can each pass in isolation, so
//! re-check against the latest main before merging a new migration.
//! `scripts/check-migrations.sh` provides the same check without a compiler.

use std::collections::BTreeMap;

/// Parse the leading sqlx version (the integer prefix before the first `_`)
/// from a migration filename, mirroring how sqlx derives `Migration::version`.
/// Returns `None` for a name with no leading-digits-then-`_` prefix.
fn parse_version(filename: &str) -> Option<i64> {
    let (prefix, _rest) = filename.split_once('_')?;
    prefix.parse::<i64>().ok()
}

/// True when `filename` follows the repo convention: a four-digit, zero-padded
/// version prefix immediately followed by `_<name>` (e.g. `0044_secrets.sql`).
/// Stricter than [`parse_version`], which accepts any integer width — pinning
/// the width keeps prefixes lexically sortable and rules out a mixed-width
/// collision such as `0045_a.sql` vs `45_b.sql` (both sqlx version 45) that a
/// string-prefix comparison would miss.
fn has_conventional_prefix(filename: &str) -> bool {
    match filename.split_once('_') {
        Some((prefix, rest)) => {
            !rest.is_empty() && prefix.len() == 4 && prefix.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}

/// Group `.sql` migration filenames by version, keeping only the versions
/// claimed by more than one file (the collision set). An empty map means every
/// version is unique. Non-`.sql` files are ignored; the returned file lists are
/// sorted for deterministic messages.
fn duplicate_versions(filenames: &[String]) -> BTreeMap<i64, Vec<String>> {
    let mut by_version: BTreeMap<i64, Vec<String>> = BTreeMap::new();
    for name in filenames {
        if !name.ends_with(".sql") {
            continue;
        }
        if let Some(version) = parse_version(name) {
            by_version.entry(version).or_default().push(name.clone());
        }
    }
    by_version.retain(|_, files| files.len() > 1);
    for files in by_version.values_mut() {
        files.sort();
    }
    by_version
}

/// Read the filenames in the embedded `migrations/` directory. Resolved at
/// compile time relative to this crate, so it tracks wherever the checkout
/// lives in CI — and is the exact path `sqlx::migrate!` embeds.
fn migrations_dir_filenames() -> Vec<String> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations");
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read migrations dir {dir}: {e}"))
        .map(|entry| {
            entry
                .expect("read migrations dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

#[test]
fn migration_versions_are_unique() {
    let names = migrations_dir_filenames();

    // A misresolved path would yield zero .sql files and the dup check would
    // vacuously pass — fail loudly instead.
    let sql_count = names.iter().filter(|n| n.ends_with(".sql")).count();
    assert!(
        sql_count > 0,
        "no .sql files found under migrations/ — path resolution is wrong, \
         this guard would vacuously pass"
    );

    let dups = duplicate_versions(&names);
    assert!(
        dups.is_empty(),
        "duplicate migration version(s) in migrations/ — sqlx collides on the \
         _sqlx_migrations version key at boot. Renumber so each version maps to one file:\n{}",
        dups.iter()
            .map(|(version, files)| format!("  {version:04}: {}", files.join(", ")))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn every_sql_file_uses_a_four_digit_version_prefix() {
    let bad: Vec<String> = migrations_dir_filenames()
        .into_iter()
        .filter(|n| n.ends_with(".sql"))
        .filter(|n| !has_conventional_prefix(n))
        .collect();
    assert!(
        bad.is_empty(),
        "migration file(s) not matching the `NNNN_<name>.sql` convention \
         (four-digit zero-padded version prefix): {bad:?}"
    );
}

#[test]
fn has_conventional_prefix_requires_exactly_four_digits() {
    assert!(has_conventional_prefix("0044_change_request_secrets.sql"));
    assert!(has_conventional_prefix("0100_foo_bar.sql"));
    assert!(!has_conventional_prefix("45_bar.sql")); // too few digits
    assert!(!has_conventional_prefix("00045_bar.sql")); // too many digits
    assert!(!has_conventional_prefix("004a_bar.sql")); // non-digit in prefix
    assert!(!has_conventional_prefix("notamigration.sql")); // no `_` separator
}

#[test]
fn duplicate_versions_detects_collision() {
    // The guard's own contract, independent of the live directory's (clean)
    // state: files sharing a prefix are reported, distinct ones are not, and
    // non-.sql files are ignored.
    let names = vec![
        "0042_audit_dashboard_indexes.sql".to_string(),
        "0042_change_request_secrets.sql".to_string(),
        "0043_audit_rollup.sql".to_string(),
        "0099_notes.txt".to_string(),
    ];
    let dups = duplicate_versions(&names);
    assert_eq!(dups.len(), 1, "exactly one colliding version expected");
    assert_eq!(
        dups.get(&42).map(Vec::len),
        Some(2),
        "version 42 should list both colliding files"
    );
    assert!(
        !dups.contains_key(&43),
        "version 43 has a single file and must not be flagged"
    );
}

#[test]
fn parse_version_reads_leading_integer() {
    assert_eq!(parse_version("0042_audit.sql"), Some(42));
    assert_eq!(parse_version("0044_change_request_secrets.sql"), Some(44));
    assert_eq!(parse_version("0100_foo_bar.sql"), Some(100));
    assert_eq!(parse_version("notamigration.sql"), None);
    assert_eq!(parse_version("README.md"), None);
}
