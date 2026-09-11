//! Read a directory of `*.cedar` files into a single policy-set
//! source string, ready to be stored as a [`crate::PolicyBundle`].
//!
//! The concatenation matches `waygate_authz::CedarEngine::load_dir`
//! byte-for-byte — files sorted by name, each file's contents followed
//! by a newline — so importing the on-disk `policies/` directory
//! produces exactly the policy set the current file-backed loader
//! would. That's what makes a loader cutover to the store a true
//! no-op rather than a behaviour change.
//!
//! This module is pure filesystem + string work: it does NOT validate
//! the result as Cedar (that needs the evaluator, which lives in
//! `waygate-authz`). The `--import-policies` command validates with
//! `CedarEngine::from_source` before publishing, so a broken policy
//! dir fails the import loudly instead of seeding an unloadable bundle.

use std::path::Path;

/// Concatenated Cedar source read from a policies directory, plus the
/// sorted list of files that contributed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDirContents {
    /// Concatenated policy-set source (matches `CedarEngine::load_dir`).
    pub source: String,
    /// Filenames included, in the order they were concatenated.
    pub files: Vec<String>,
}

impl PolicyDirContents {
    /// True when no `*.cedar` files were found. The import command
    /// refuses an empty import: publishing an empty bundle would, after
    /// the loader cutover, mean deny-by-default for the whole tenant —
    /// a footgun worth a loud error rather than a silent lockout.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// The single machine-owned file a published policy bundle is mirrored to.
/// Sorts first, and is the ONLY `.cedar` file the live dir holds after a
/// dashboard / API publish (the rest are moved below a hidden archive
/// directory), so the loader reads exactly the bundle (`CedarEngine::load_dir`
/// concatenates top-level `*.cedar`).
pub const PUBLISHED_FILE: &str = "00-published.cedar";
const ARCHIVE_PREFIX: &str = ".policy-write-archive.";

/// Failure from a policy-directory write that is conditional on the exact live
/// source hash the caller previously observed.
#[derive(Debug, thiserror::Error)]
pub enum PolicyDirWriteError {
    /// The live policy set changed before the filesystem commit began. No Cedar
    /// file was removed or replaced.
    #[error("the live policy set changed before the filesystem commit")]
    StaleBase,
    /// Filesystem staging, verification, or commit failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Mirror a published policy bundle's concatenated Cedar `content` onto the live
/// `dir` as the single machine-owned [`PUBLISHED_FILE`], moving every other
/// top-level `*.cedar` outside the loader's non-recursive view. Under
/// file-as-truth (server-config redesign §8) the live
/// `policies/` dir is machine-owned: humans edit via the dashboard / API (a
/// publish or rollback rewrites the live dir from the chosen bundle); under
/// the runtime file-authority model, the in-repo synthetic set is an example
/// input for tests and local evaluation, not a deployment seed or git edit
/// path. Live directories are initialized through governed publish/import. A
/// bundle is a single concatenated blob, so it round-trips to one file; the
/// loader concatenates all `*.cedar`, so one file with the full content yields
/// the same policy set.
///
/// Write order is chosen so a concurrent boot/SIGHUP read never observes a
/// DOUBLED set (the new file alongside stale ones — duplicate Cedar policy ids
/// would fail the load): write a unique temp dotfile, move every top-level
/// `*.cedar` into a retained hidden archive, then install the temp with a
/// create-if-absent hard link. The only transient a concurrent reader can see
/// is ZERO `*.cedar` between quarantine and install — which the loader recovers
/// from the (still-old) ledger bundle, never a wrong set. Callers run this
/// BEFORE their ledger transition, so the recoverable ledger bundle during
/// that window is the previous one.
pub fn write_policy_bundle_to_dir(dir: &Path, content: &str) -> std::io::Result<()> {
    match write_policy_bundle_to_dir_inner(dir, content, None, || {}, || {}, || {}) {
        Ok(()) => Ok(()),
        Err(PolicyDirWriteError::Io(error)) => Err(error),
        Err(PolicyDirWriteError::StaleBase) => Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "the live policy set changed during the filesystem commit",
        )),
    }
}

/// Mirror `content` only when the live policy directory still has
/// `expected_base_hash` immediately before the destructive commit.
///
/// The caller may await a cross-replica database turnstile after it first reads
/// the directory. This function stages and syncs the replacement first, then
/// re-reads the complete directory and compares its canonical hash before
/// removing any Cedar file. An out-of-band edit during those earlier waits is
/// therefore preserved and reported as [`PolicyDirWriteError::StaleBase`].
pub fn write_policy_bundle_to_dir_from_base(
    dir: &Path,
    content: &str,
    expected_base_hash: &str,
) -> Result<(), PolicyDirWriteError> {
    write_policy_bundle_to_dir_inner(dir, content, Some(expected_base_hash), || {}, || {}, || {})
}

fn write_policy_bundle_to_dir_inner(
    dir: &Path,
    content: &str,
    expected_base_hash: Option<&str>,
    before_base_check: impl FnOnce(),
    after_base_check: impl FnOnce(),
    after_quarantine: impl FnOnce(),
) -> Result<(), PolicyDirWriteError> {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    std::fs::create_dir_all(dir)?;
    let final_path = dir.join(PUBLISHED_FILE);
    let tmp_path = dir.join(format!(
        ".{PUBLISHED_FILE}.{}.{}.tmp",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed),
    ));

    let commit = (|| -> Result<(), PolicyDirWriteError> {
        // Write to a unique temp dotfile (not matched by the `*.cedar` clear
        // below; `create_new` refuses a planted symlink / stale temp). Sync
        // before the final base check so slow staging cannot reopen a stale-read
        // window.
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)?;
            f.write_all(content.as_bytes())?;
            f.sync_all()?;
        }

        before_base_check();
        if let Some(expected) = expected_base_hash {
            let live = read_policy_dir(dir)?;
            if crate::content_hash(&live.source) != expected {
                return Err(PolicyDirWriteError::StaleBase);
            }
        }
        after_base_check();

        // Move the complete prior set aside without deleting it. A writer that
        // changes an existing file after the base check changes the quarantined
        // inode; a writer that creates a new file leaves it in the live root.
        // The verification below observes either case and restores the prior
        // set instead of silently losing the edit.
        let archive_dir = dir.join(format!("{ARCHIVE_PREFIX}{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&archive_dir)?;

        let transaction = (|| -> Result<(), PolicyDirWriteError> {
            let entries = collect_cedar_entries(std::fs::read_dir(dir)?)?;
            for entry in entries {
                std::fs::rename(entry.path(), archive_dir.join(entry.file_name()))?;
            }

            after_quarantine();

            // `hard_link` is the portable same-filesystem create-if-absent
            // primitive. Unlike rename-over-target, it cannot erase a
            // concurrently created `00-published.cedar`.
            if !hard_link_if_absent(&tmp_path, &final_path)? {
                return Err(PolicyDirWriteError::StaleBase);
            }
            std::fs::remove_file(&tmp_path)?;

            let live = read_policy_dir(dir)?;
            let live_hash = crate::content_hash(&live.source);
            let archive_matches = match expected_base_hash {
                Some(expected) => {
                    let archived = read_policy_dir(&archive_dir)?;
                    crate::content_hash(&archived.source) == expected
                }
                None => true,
            };
            if !archive_matches || live_hash != crate::canonical_policy_disk_hash(content) {
                return Err(PolicyDirWriteError::StaleBase);
            }
            prune_policy_archives(dir, &archive_dir)?;
            Ok(())
        })();

        match transaction {
            Ok(()) => Ok(()),
            Err(error) => {
                rollback_quarantined_policy_write(
                    dir,
                    &archive_dir,
                    crate::canonical_policy_disk_hash(content),
                )
                .map_err(PolicyDirWriteError::Io)?;
                Err(error)
            }
        }
    })();
    if commit.is_err() {
        let _ = std::fs::remove_file(&tmp_path); // best-effort temp cleanup
    }
    commit
}

/// Create a hard link without replacing an existing destination.
fn hard_link_if_absent(source: &Path, target: &Path) -> std::io::Result<bool> {
    match std::fs::hard_link(source, target) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error),
    }
}

/// Rename `source` when it exists, preserving every other filesystem error.
fn rename_if_exists(source: &Path, target: &Path) -> std::io::Result<bool> {
    match std::fs::rename(source, target) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Retain only the current successful write's recovery archive.
///
/// Interrupted or refused writes may leave additional archives, but the next
/// successful commit reclaims them. Unexpected non-directory entries using the
/// reserved prefix fail loudly instead of being deleted.
fn prune_policy_archives(dir: &Path, keep: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path == keep
            || !entry
                .file_name()
                .to_string_lossy()
                .starts_with(ARCHIVE_PREFIX)
        {
            continue;
        }
        if !entry.file_type()?.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("policy archive path is not a directory: {}", path.display()),
            ));
        }
        std::fs::remove_dir_all(path)?;
    }
    Ok(())
}

/// Restore the quarantined base after a conditional write loses a race.
///
/// The archive is retained even after restoration. It is outside the
/// non-recursive `*.cedar` loader, and retaining the original inodes means a
/// writer that already had one open cannot have its bytes destroyed by this
/// transaction.
fn rollback_quarantined_policy_write(
    dir: &Path,
    archive_dir: &Path,
    candidate_hash: String,
) -> std::io::Result<()> {
    let final_path = dir.join(PUBLISHED_FILE);
    let refused_path = archive_dir.join("candidate.refused");
    if rename_if_exists(&final_path, &refused_path)? {
        let source = std::fs::read_to_string(&refused_path)?;
        if crate::canonical_policy_disk_hash(&source) != candidate_hash {
            hard_link_if_absent(&refused_path, &final_path)?;
        }
    }

    let archived = collect_cedar_entries(std::fs::read_dir(archive_dir)?)?;
    for entry in archived {
        let target = dir.join(entry.file_name());
        hard_link_if_absent(&entry.path(), &target)?;
    }
    Ok(())
}

/// The canonical on-disk source a published `content` round-trips to: the exact
/// string [`read_policy_dir`] returns after [`write_policy_bundle_to_dir`]
/// writes `content` as the single [`PUBLISHED_FILE`]. `read_policy_dir`
/// concatenates each `*.cedar` file's contents followed by a `\n`, so a single
/// published file holding `content` reads back as `content` plus one trailing
/// newline. Defining it as one pure function keeps the writer, the reader, and
/// the turnstile hash from drifting apart.
pub fn canonical_policy_source(content: &str) -> String {
    format!("{content}\n")
}

/// The canonical hash of the live on-disk policy set a published `content`
/// produces — the value the turnstile pointer (`policy_pointer`) is
/// CAS-advanced to before a mirror, and the value boot/reconcile compute from
/// disk as `content_hash(read_policy_dir(dir).source)`.
///
/// It MUST hash [`canonical_policy_source`], NOT the raw `content` bytes: a disk
/// read concatenates each file with a trailing newline, so a draft's submitted
/// bytes differ from the on-disk canonical form. Keying the turnstile on raw
/// bytes would advance the pointer to a hash that never matches disk and lose
/// every later CAS. The round-trip is pinned by
/// `write_then_read_matches_canonical_disk_hash`.
pub fn canonical_policy_disk_hash(content: &str) -> String {
    crate::content_hash(&canonical_policy_source(content))
}

/// Whether two policy-source representations contain the same bytes after
/// ignoring trailing newlines added by policy-directory import/read paths.
///
/// A dashboard publish stores submitted content, while `--import-policies`
/// stores [`read_policy_dir`]'s source verbatim. The latter already includes
/// the reader-added newline for each file, so canonicalizing it again would
/// invent a mismatch. This deliberately ignores only trailing `\n` bytes; any
/// other source change remains observable.
pub fn policy_sources_equivalent(left: &str, right: &str) -> bool {
    left.trim_end_matches('\n') == right.trim_end_matches('\n')
}

/// Remove every `*.cedar` file in `dir`, leaving non-`.cedar` files and the
/// directory itself intact. Used to RESTORE an empty on-disk policy set when a
/// publish/rollback's ledger write fails after the disk mirror and the prior
/// disk state had no policies (so [`write_policy_bundle_to_dir`], which refuses
/// to write an empty bundle, can't express the restore). A missing dir is a
/// no-op (nothing to clear) — the caller's resolver already treats a missing
/// dir as unreadable.
pub fn clear_policy_dir(dir: &Path) -> std::io::Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let path = entry?.path();
        let is_cedar = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("cedar"))
            .unwrap_or(false);
        if is_cedar {
            std::fs::remove_file(&path)?;
        }
    }
    Ok(())
}

/// Read every `*.cedar` file in `dir` (case-insensitive extension,
/// sorted by filename) and concatenate into one policy-set source. Any
/// directory-entry or file-read error fails the whole read; this never returns
/// a partial policy snapshot.
pub fn read_policy_dir(dir: &Path) -> std::io::Result<PolicyDirContents> {
    let mut entries = collect_cedar_entries(std::fs::read_dir(dir)?)?;
    entries.sort_by_key(|e| e.file_name());

    let mut source = String::new();
    let mut files = Vec::with_capacity(entries.len());
    for entry in entries {
        let src = std::fs::read_to_string(entry.path())?;
        source.push_str(&src);
        source.push('\n');
        files.push(entry.file_name().to_string_lossy().into_owned());
    }
    Ok(PolicyDirContents { source, files })
}

/// Collect only Cedar files while preserving every directory-iteration error.
/// A partial directory snapshot is unsafe because publishing it would remove
/// every policy whose entry was skipped.
fn collect_cedar_entries(
    entries: impl Iterator<Item = std::io::Result<std::fs::DirEntry>>,
) -> std::io::Result<Vec<std::fs::DirEntry>> {
    let mut cedar = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry
            .path()
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.eq_ignore_ascii_case("cedar"))
            .unwrap_or(false)
        {
            cedar.push(entry);
        }
    }
    Ok(cedar)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// Unique temp dir under the system tmp, cleaned up on drop. Keeps
    /// the test side-effect free (no writes outside an isolated tmpdir).
    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("polimport-{}", uuid::Uuid::now_v7()));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn write(&self, name: &str, body: &str) {
            fs::write(self.0.join(name), body).unwrap();
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn concatenates_cedar_files_sorted_by_name() {
        let d = TmpDir::new();
        // Written out of order; read must sort by filename.
        d.write("20-second.cedar", "permit(principal, action, resource);");
        d.write("10-first.cedar", "forbid(principal, action, resource);");
        d.write("notes.txt", "ignored — not a .cedar file");

        let got = read_policy_dir(&d.0).unwrap();
        assert_eq!(got.files, vec!["10-first.cedar", "20-second.cedar"]);
        // Sorted, each followed by a newline — identical to
        // CedarEngine::load_dir's concatenation.
        assert_eq!(
            got.source,
            "forbid(principal, action, resource);\npermit(principal, action, resource);\n",
        );
        assert!(!got.is_empty());
    }

    #[test]
    fn case_insensitive_extension() {
        let d = TmpDir::new();
        d.write("up.CEDAR", "permit(principal, action, resource);");
        let got = read_policy_dir(&d.0).unwrap();
        assert_eq!(got.files, vec!["up.CEDAR"]);
    }

    #[test]
    fn empty_dir_is_empty() {
        let d = TmpDir::new();
        d.write("readme.md", "no policies here");
        let got = read_policy_dir(&d.0).unwrap();
        assert!(got.is_empty());
        assert_eq!(got.source, "");
    }

    #[test]
    fn missing_dir_is_an_error() {
        let missing = std::env::temp_dir().join(format!("nope-{}", uuid::Uuid::now_v7()));
        assert!(read_policy_dir(&missing).is_err());
    }

    #[test]
    fn directory_entry_error_fails_the_entire_read() {
        let d = TmpDir::new();
        d.write("10-first.cedar", "permit(principal, action, resource);");
        let entry = fs::read_dir(&d.0)
            .unwrap()
            .next()
            .expect("fixture entry")
            .unwrap();
        let entries = [
            Ok(entry),
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected directory entry failure",
            )),
        ]
        .into_iter();

        let error = collect_cedar_entries(entries).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn write_bundle_collapses_dir_to_single_published_file() {
        let d = TmpDir::new();
        // A multi-file live dir, as a git-seeded source tree would have.
        d.write("10-first.cedar", "forbid(principal, action, resource);");
        d.write("20-second.cedar", "permit(principal, action, resource);");
        d.write("notes.txt", "untouched — not a .cedar file");

        let bundle = "forbid(principal, action, resource);\npermit(principal, action, resource);\n";
        write_policy_bundle_to_dir(&d.0, bundle).unwrap();

        // Only the machine-owned published file remains; the source files are
        // cleared so the loader reads exactly the bundle.
        let mut cedar: Vec<String> = fs::read_dir(&d.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".cedar"))
            .collect();
        cedar.sort();
        assert_eq!(cedar, vec![PUBLISHED_FILE.to_string()]);
        // Non-.cedar files are left alone.
        assert!(d.0.join("notes.txt").exists());
        // The published file holds the bundle verbatim.
        assert_eq!(
            fs::read_to_string(d.0.join(PUBLISHED_FILE)).unwrap(),
            bundle
        );
    }

    #[test]
    fn write_bundle_round_trips_through_read_policy_dir() {
        let d = TmpDir::new();
        d.write("10-first.cedar", "permit(principal, action, resource);");
        let bundle = "permit(principal, action, resource);\n";
        write_policy_bundle_to_dir(&d.0, bundle).unwrap();

        let got = read_policy_dir(&d.0).unwrap();
        assert_eq!(got.files, vec![PUBLISHED_FILE.to_string()]);
        // `read_policy_dir` appends exactly one `\n` per file (its documented
        // contract, matching `CedarEngine::load_dir`), so a single published
        // file reads back as the written bundle plus that newline. The loader
        // parses the same policy set — the round-trip is identity modulo a
        // trailing newline. (Canonicalizing the bytes to make read a true
        // inverse belongs with the later reconciliation/hash slice, which —
        // like the manifest path — will hash the re-read form, not raw bytes.)
        assert_eq!(got.source, format!("{bundle}\n"));
        assert_eq!(got.source.trim_end(), bundle.trim_end());
    }

    #[test]
    fn conditional_write_preserves_an_edit_that_lands_after_staging() {
        let d = TmpDir::new();
        let original = "@id(\"original\") permit(principal, action, resource);";
        d.write(PUBLISHED_FILE, original);
        let expected = crate::content_hash(&read_policy_dir(&d.0).unwrap().source);
        let concurrent = "@id(\"concurrent\") forbid(principal, action, resource);";

        let error = write_policy_bundle_to_dir_inner(
            &d.0,
            "@id(\"replacement\") permit(principal, action, resource);",
            Some(&expected),
            || fs::write(d.0.join(PUBLISHED_FILE), concurrent).unwrap(),
            || {},
            || {},
        )
        .unwrap_err();

        assert!(matches!(error, PolicyDirWriteError::StaleBase));
        let live = read_policy_dir(&d.0).unwrap();
        assert_eq!(live.files, vec![PUBLISHED_FILE.to_owned()]);
        assert_eq!(live.source.trim_end(), concurrent);
        assert!(
            fs::read_dir(&d.0).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")),
            "a refused conditional write must clean up its staged temp file"
        );
    }

    #[test]
    fn conditional_write_restores_an_edit_after_the_final_base_check() {
        let d = TmpDir::new();
        let original = "@id(\"original\") permit(principal, action, resource);";
        d.write(PUBLISHED_FILE, original);
        let expected = crate::content_hash(&read_policy_dir(&d.0).unwrap().source);
        let concurrent = "@id(\"concurrent\") forbid(principal, action, resource);";

        let error = write_policy_bundle_to_dir_inner(
            &d.0,
            "@id(\"replacement\") permit(principal, action, resource);",
            Some(&expected),
            || {},
            || fs::write(d.0.join(PUBLISHED_FILE), concurrent).unwrap(),
            || {},
        )
        .unwrap_err();

        assert!(matches!(error, PolicyDirWriteError::StaleBase));
        let live = read_policy_dir(&d.0).unwrap();
        assert_eq!(live.files, vec![PUBLISHED_FILE.to_owned()]);
        assert_eq!(live.source.trim_end(), concurrent);
    }

    #[test]
    fn conditional_write_preserves_a_new_file_after_quarantine() {
        let d = TmpDir::new();
        let original = "@id(\"original\") permit(principal, action, resource);";
        d.write(PUBLISHED_FILE, original);
        let expected = crate::content_hash(&read_policy_dir(&d.0).unwrap().source);
        let concurrent = "@id(\"concurrent\") forbid(principal, action, resource);";

        let error = write_policy_bundle_to_dir_inner(
            &d.0,
            "@id(\"replacement\") permit(principal, action, resource);",
            Some(&expected),
            || {},
            || {},
            || fs::write(d.0.join("90-concurrent.cedar"), concurrent).unwrap(),
        )
        .unwrap_err();

        assert!(matches!(error, PolicyDirWriteError::StaleBase));
        let live = read_policy_dir(&d.0).unwrap();
        assert_eq!(
            live.files,
            vec![PUBLISHED_FILE.to_owned(), "90-concurrent.cedar".to_owned()]
        );
        assert!(live.source.contains("original"));
        assert!(live.source.contains("concurrent"));
        assert!(!live.source.contains("replacement"));
    }

    #[test]
    fn conditional_write_does_not_replace_a_concurrent_published_file() {
        let d = TmpDir::new();
        let original = "@id(\"original\") permit(principal, action, resource);";
        d.write(PUBLISHED_FILE, original);
        let expected = crate::content_hash(&read_policy_dir(&d.0).unwrap().source);
        let concurrent = "@id(\"concurrent\") forbid(principal, action, resource);";

        let error = write_policy_bundle_to_dir_inner(
            &d.0,
            "@id(\"replacement\") permit(principal, action, resource);",
            Some(&expected),
            || {},
            || {},
            || fs::write(d.0.join(PUBLISHED_FILE), concurrent).unwrap(),
        )
        .unwrap_err();

        assert!(matches!(error, PolicyDirWriteError::StaleBase));
        let live = read_policy_dir(&d.0).unwrap();
        assert_eq!(live.files, vec![PUBLISHED_FILE.to_owned()]);
        assert_eq!(live.source.trim_end(), concurrent);
    }

    #[test]
    fn rollback_restores_quarantined_siblings_beside_a_non_candidate_final() {
        let d = TmpDir::new();
        let archive = d.0.join(format!("{ARCHIVE_PREFIX}fixture"));
        fs::create_dir(&archive).unwrap();
        fs::write(
            archive.join("10-unrelated.cedar"),
            "@id(\"unrelated\") forbid(principal, action, resource);",
        )
        .unwrap();
        let concurrent = "@id(\"concurrent\") permit(principal, action, resource);";
        fs::write(d.0.join(PUBLISHED_FILE), concurrent).unwrap();

        rollback_quarantined_policy_write(
            &d.0,
            &archive,
            crate::canonical_policy_disk_hash(
                "@id(\"candidate\") permit(principal, action, resource);",
            ),
        )
        .unwrap();

        let live = read_policy_dir(&d.0).unwrap();
        assert_eq!(
            live.files,
            vec![PUBLISHED_FILE.to_owned(), "10-unrelated.cedar".to_owned()]
        );
        assert!(live.source.contains("unrelated"));
        assert!(live.source.contains("concurrent"));
    }

    #[test]
    fn successful_writes_retain_only_the_latest_archive() {
        let d = TmpDir::new();
        d.write(
            PUBLISHED_FILE,
            "@id(\"first\") permit(principal, action, resource);",
        );
        write_policy_bundle_to_dir(&d.0, "@id(\"second\") permit(principal, action, resource);")
            .unwrap();
        write_policy_bundle_to_dir(&d.0, "@id(\"third\") permit(principal, action, resource);")
            .unwrap();

        let archives: Vec<_> = fs::read_dir(&d.0)
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(ARCHIVE_PREFIX)
            })
            .collect();
        assert_eq!(archives.len(), 1);
    }

    #[test]
    fn archive_reclamation_failure_restores_the_prior_live_set() {
        let d = TmpDir::new();
        let original = "@id(\"original\") permit(principal, action, resource);";
        d.write(PUBLISHED_FILE, original);
        fs::write(
            d.0.join(format!("{ARCHIVE_PREFIX}unexpected")),
            "not a directory",
        )
        .unwrap();

        let error = write_policy_bundle_to_dir(
            &d.0,
            "@id(\"replacement\") permit(principal, action, resource);",
        )
        .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(read_policy_dir(&d.0).unwrap().source.trim_end(), original);
    }

    #[test]
    fn hard_link_if_absent_reports_creation_and_collision() {
        let d = TmpDir::new();
        let source = d.0.join("source");
        let target = d.0.join("target");
        fs::write(&source, "first").unwrap();

        assert!(hard_link_if_absent(&source, &target).unwrap());
        fs::remove_file(&source).unwrap();
        fs::write(&source, "second").unwrap();
        assert!(!hard_link_if_absent(&source, &target).unwrap());
        assert_eq!(fs::read_to_string(target).unwrap(), "first");
    }

    #[test]
    fn hard_link_if_absent_preserves_non_collision_errors() {
        let d = TmpDir::new();
        let error = hard_link_if_absent(&d.0.join("missing"), &d.0.join("target")).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn rename_if_exists_distinguishes_absence_from_other_errors() {
        let d = TmpDir::new();
        assert!(!rename_if_exists(&d.0.join("missing"), &d.0.join("target")).unwrap());

        let source = d.0.join("source");
        let target = d.0.join("target-dir");
        fs::write(&source, "content").unwrap();
        fs::create_dir(&target).unwrap();
        assert!(rename_if_exists(&source, &target).is_err());
    }

    #[test]
    fn conditional_write_public_seam_refuses_a_stale_base() {
        let d = TmpDir::new();
        d.write(
            PUBLISHED_FILE,
            "@id(\"original\") permit(principal, action, resource);",
        );
        let expected = crate::content_hash(&read_policy_dir(&d.0).unwrap().source);
        let concurrent = "@id(\"concurrent\") forbid(principal, action, resource);";
        fs::write(d.0.join(PUBLISHED_FILE), concurrent).unwrap();

        let error = write_policy_bundle_to_dir_from_base(
            &d.0,
            "@id(\"replacement\") permit(principal, action, resource);",
            &expected,
        )
        .unwrap_err();

        assert!(matches!(error, PolicyDirWriteError::StaleBase));
        assert_eq!(read_policy_dir(&d.0).unwrap().source.trim_end(), concurrent);
    }

    #[test]
    fn write_bundle_overwrites_a_prior_published_file() {
        let d = TmpDir::new();
        write_policy_bundle_to_dir(&d.0, "forbid(principal, action, resource);\n").unwrap();
        // A second publish replaces, not appends — no duplicate policy ids.
        write_policy_bundle_to_dir(&d.0, "permit(principal, action, resource);\n").unwrap();

        let cedar: Vec<String> = fs::read_dir(&d.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".cedar"))
            .collect();
        assert_eq!(cedar, vec![PUBLISHED_FILE.to_string()]);
        assert_eq!(
            fs::read_to_string(d.0.join(PUBLISHED_FILE)).unwrap(),
            "permit(principal, action, resource);\n",
        );
    }

    #[test]
    fn write_then_read_matches_canonical_disk_hash() {
        let d = TmpDir::new();
        let content = "permit(principal, action, resource);\nforbid(principal, action, resource);";
        write_policy_bundle_to_dir(&d.0, content).unwrap();
        let disk = read_policy_dir(&d.0).unwrap();
        // The disk read of the single published file equals the canonical source
        // the turnstile hashes, so the pointer the writer CASes to (computed from
        // `content` via canonical_policy_disk_hash) equals what boot/reconcile
        // compute from disk (content_hash(read_policy_dir(dir).source)) — the
        // invariant that keeps the turnstile CAS from permanently losing.
        assert_eq!(disk.source, canonical_policy_source(content));
        assert_eq!(
            crate::content_hash(&disk.source),
            canonical_policy_disk_hash(content),
        );
    }

    #[test]
    fn source_equivalence_ignores_only_reader_added_trailing_newlines() {
        let content = "permit(principal, action, resource);";
        assert!(policy_sources_equivalent(content, &format!("{content}\n")));
        assert!(policy_sources_equivalent(
            &format!("{content}\n"),
            &format!("{content}\n\n")
        ));
        assert!(!policy_sources_equivalent(
            content,
            "forbid(principal, action, resource);\n"
        ));
        assert!(!policy_sources_equivalent(
            content,
            &format!("{content} \n")
        ));
    }

    #[test]
    fn clear_policy_dir_removes_cedar_keeps_others() {
        let d = TmpDir::new();
        d.write("00-published.cedar", "permit(principal, action, resource);");
        d.write("10-extra.cedar", "forbid(principal, action, resource);");
        d.write("notes.txt", "keep me");
        clear_policy_dir(&d.0).unwrap();
        let remaining: Vec<String> = fs::read_dir(&d.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(remaining, vec!["notes.txt".to_string()]);
        // read_policy_dir now sees an empty policy set.
        assert!(read_policy_dir(&d.0).unwrap().is_empty());
    }

    #[test]
    fn clear_policy_dir_missing_is_noop() {
        let missing = std::env::temp_dir().join(format!("polclear-{}", uuid::Uuid::now_v7()));
        clear_policy_dir(&missing).unwrap();
    }

    #[test]
    fn write_bundle_creates_missing_dir() {
        let parent = std::env::temp_dir().join(format!("polwrite-{}", uuid::Uuid::now_v7()));
        let dir = parent.join("policies");
        assert!(!dir.exists());
        write_policy_bundle_to_dir(&dir, "permit(principal, action, resource);\n").unwrap();
        assert!(dir.join(PUBLISHED_FILE).exists());
        let _ = fs::remove_dir_all(&parent);
    }
}
