//! Fail-safe Cedar policy-set content segmenter.
//!
//! Splits a bundle's Cedar source into ordered, `@id`-addressed FRAGMENTS so the
//! dashboard can edit / add / remove ONE policy and recompose the bundle by
//! EXACT concatenation — only the touched statement changes, every other byte
//! (comments, blank lines, hand formatting) is preserved verbatim.
//!
//! `cedar-policy` 4.x exposes no source location on a parsed `Policy`
//! (`to_string()` re-serializes and drops comments), so addressing a single
//! policy in the original text needs our own tokenizer. To make that SAFE, every
//! public entry point **cross-checks the text segmentation against Cedar's own
//! parse**: the set of statements and `@id`s the tokenizer finds must match what
//! `PolicySet::from_str` reports, or the operation returns [`SegmentError`] and
//! the caller falls back to whole-bundle editing. The tokenizer can never
//! silently mis-splice — it either agrees with Cedar or refuses.
//!
//! Cedar lexical facts the tokenizer relies on: statements terminate with a
//! top-level `;`; the only comment form is `//` to end-of-line; string literals
//! are `"…"` with `\` escapes. All the delimiters it scans for (`;`, `"`, `/`,
//! `\`, newline) are ASCII, so byte scanning is UTF-8-safe — a multi-byte char's
//! continuation bytes (≥ 0x80) never collide with them, and every split lands on
//! a char boundary.

use std::ops::Range;
use std::str::FromStr;

use cedar_policy::PolicySet;

/// One top-level statement of a Cedar policy set, addressed by its `@id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFragment {
    /// The `@id("…")` annotation value, or `None` for an un-annotated policy
    /// (which exists in the bundle but isn't per-policy addressable).
    pub id: Option<String>,
    /// Byte range of the leading trivia (whitespace + full-line `//` comments
    /// since the previous statement) in the content.
    pub leading: Range<usize>,
    /// Byte range of the statement itself — the first `@annotation`/keyword
    /// through the terminating `;` (inclusive). This is the editable unit.
    pub statement: Range<usize>,
}

/// Why content can't be safely segmented per-policy; the caller falls back to
/// whole-bundle editing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SegmentError {
    /// The content does not parse as a Cedar policy set.
    Parse(String),
    /// The text tokenizer's statement/`@id` set disagrees with Cedar's parse —
    /// the content has a shape the tokenizer can't address safely.
    Ambiguous,
    /// A per-policy operation named an `@id` that isn't in the bundle.
    NotFound(String),
}

impl std::fmt::Display for SegmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SegmentError::Parse(e) => write!(f, "policy set does not parse as Cedar: {e}"),
            SegmentError::Ambiguous => write!(
                f,
                "policy text could not be safely segmented per-policy (it disagrees with the \
                 parser); edit the whole bundle instead"
            ),
            SegmentError::NotFound(id) => write!(f, "no policy with @id \"{id}\" in this bundle"),
        }
    }
}

impl std::error::Error for SegmentError {}

/// Segment `content` into ordered fragments, cross-checked against Cedar's parse.
///
/// `Ok(fragments)` ⇒ `concat(content[f.leading] + content[f.statement]) +
/// content[tail] == content` and every `@id` Cedar sees is present exactly once.
/// `Err` ⇒ the caller falls back to whole-bundle editing.
pub fn segment_verified(content: &str) -> Result<Vec<PolicyFragment>, SegmentError> {
    // 1. Cedar must parse — it's the authoritative statement/@id set.
    let parsed = PolicySet::from_str(content).map_err(|e| SegmentError::Parse(e.to_string()))?;
    let mut cedar_ids: Vec<String> = parsed
        .policies()
        .filter_map(|p| p.annotation("id").map(str::to_owned))
        .collect();
    let cedar_count = parsed.policies().count();

    // 2. Text-segment.
    let fragments = lex_fragments(content);

    // 3. Cross-check: same number of statements, and the same multiset of @ids.
    let mut seg_ids: Vec<String> = fragments.iter().filter_map(|f| f.id.clone()).collect();
    if fragments.len() != cedar_count {
        return Err(SegmentError::Ambiguous);
    }
    cedar_ids.sort();
    seg_ids.sort();
    if seg_ids != cedar_ids {
        return Err(SegmentError::Ambiguous);
    }
    // 4. Reject duplicate @ids. Cedar treats `@id` as metadata — `PolicySet::
    //    from_str` does NOT require it unique (only `CedarEngine::from_source`'s
    //    reidentify rejects dups, downstream). But per-policy addressing is BY
    //    @id, so a duplicate means an @id can't pick out one policy; `find_by_id`
    //    would silently address the first. Refuse here so the segmenter's
    //    addressing invariant holds on its own — the caller falls back to
    //    whole-bundle editing rather than edit/remove an ambiguous target.
    if seg_ids.windows(2).any(|w| w[0] == w[1]) {
        return Err(SegmentError::Ambiguous);
    }
    Ok(fragments)
}

/// The editable source text of the policy with `@id == id` (its statement, with
/// comments/formatting preserved), or an error if it's not addressable.
pub fn policy_statement(content: &str, id: &str) -> Result<String, SegmentError> {
    let fragments = segment_verified(content)?;
    let frag = find_by_id(&fragments, id)?;
    Ok(content[frag.statement.clone()].to_string())
}

/// Replace the statement of the policy with `@id == id` by `new_statement`,
/// returning the recomposed bundle content. Leading trivia (comments/blank
/// lines) is preserved; only the statement bytes change. The result is NOT
/// re-validated here — the caller validates the whole bundle (so a broken edit
/// is refused by the normal publish/validate path).
pub fn replace_policy(
    content: &str,
    id: &str,
    new_statement: &str,
) -> Result<String, SegmentError> {
    let fragments = segment_verified(content)?;
    let frag = find_by_id(&fragments, id)?;
    let mut out = String::with_capacity(content.len() + new_statement.len());
    out.push_str(&content[..frag.statement.start]);
    out.push_str(new_statement);
    out.push_str(&content[frag.statement.end..]);
    Ok(out)
}

/// Remove the policy with `@id == id` — its leading trivia, the statement, AND a
/// trailing inline comment on the statement's own line (`…; // note`) — returning
/// the recomposed content. The trailing-comment sweep keeps a removed policy's
/// own `// note` from being orphaned onto the next policy.
pub fn remove_policy(content: &str, id: &str) -> Result<String, SegmentError> {
    let fragments = segment_verified(content)?;
    let frag = find_by_id(&fragments, id)?;
    let end = trailing_comment_end(content.as_bytes(), frag.statement.end);
    let mut out = String::with_capacity(content.len());
    out.push_str(&content[..frag.leading.start]);
    out.push_str(&content[end..]);
    Ok(out)
}

/// Append `new_statement` to the bundle (a new policy), separated from the prior
/// content by a blank line, returning the recomposed content. `content` is still
/// segment-verified first so an unparseable/ambiguous bundle falls back.
///
/// The EXISTING content is preserved byte-for-byte — separation is achieved by
/// only ADDING newlines, never trimming the bundle's tail — so `add` keeps the
/// same "every untouched byte is preserved verbatim" guarantee as edit/remove
/// (existing trailing blank lines are kept, not collapsed). Only the appended
/// statement itself is trimmed (it's the new, touched content).
pub fn append_policy(content: &str, new_statement: &str) -> Result<String, SegmentError> {
    let _ = segment_verified(content)?;
    let stmt = new_statement.trim();
    if content.is_empty() {
        return Ok(format!("{stmt}\n"));
    }
    let mut out = content.to_string();
    // Guarantee exactly a blank-line boundary by ADDING newlines as needed —
    // without deleting any existing byte. If the bundle already ends with a
    // blank line (or several), those are kept verbatim.
    if !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.ends_with("\n\n") {
        out.push('\n');
    }
    out.push_str(stmt);
    out.push('\n');
    Ok(out)
}

/// Enforce the per-policy edit/add contract: `text` must be EXACTLY ONE Cedar
/// policy. Without this, a submitted "statement" could smuggle in extra
/// policies (the splice/append is verbatim and only the recomposed bundle is
/// validated), so an "edit one policy" could silently add or drop policies.
///
/// When `expected_id` is `Some`, the single policy's `@id` must equal it — an
/// edit may not rename or un-`@id` the policy it targets (rename = remove + add).
/// Returns an operator-facing message on violation.
pub fn ensure_single_policy(text: &str, expected_id: Option<&str>) -> Result<(), String> {
    let frags =
        segment_verified(text).map_err(|e| format!("the submitted policy text is invalid: {e}"))?;
    if frags.len() != 1 {
        return Err(format!(
            "expected exactly one policy, found {}",
            frags.len()
        ));
    }
    if let Some(want) = expected_id {
        match frags[0].id.as_deref() {
            Some(got) if got == want => {}
            Some(got) => {
                return Err(format!(
                    "the edited policy's @id must stay \"{want}\", got \"{got}\""
                ))
            }
            None => {
                return Err(format!("the edited policy must keep its @id(\"{want}\")"));
            }
        }
    }
    Ok(())
}

fn find_by_id<'a>(
    fragments: &'a [PolicyFragment],
    id: &str,
) -> Result<&'a PolicyFragment, SegmentError> {
    fragments
        .iter()
        .find(|f| f.id.as_deref() == Some(id))
        .ok_or_else(|| SegmentError::NotFound(id.to_owned()))
}

/// Tokenize content into fragments (leading trivia + statement) by splitting on
/// top-level `;`, skipping `//` comments and `"…"` strings. Pure text; the
/// cross-check in [`segment_verified`] decides whether to trust the result.
fn lex_fragments(content: &str) -> Vec<PolicyFragment> {
    let bytes = content.as_bytes();
    let n = bytes.len();
    let mut out = Vec::new();
    let mut seg_start = 0usize;
    loop {
        let stmt_start = skip_trivia(bytes, seg_start);
        if stmt_start >= n {
            break; // only trailing trivia remains
        }
        match find_statement_end(bytes, stmt_start) {
            Some(semi) => {
                let statement = stmt_start..(semi + 1);
                let id = statement_id(&content[statement.clone()]);
                out.push(PolicyFragment {
                    id,
                    leading: seg_start..stmt_start,
                    statement: statement.clone(),
                });
                seg_start = semi + 1;
            }
            // No terminating `;` — a malformed tail. Cedar won't have parsed
            // this content, so segment_verified already failed; stop.
            None => break,
        }
    }
    out
}

/// From `i` (the byte just past a statement's terminating `;`), if the rest of
/// that SAME line is whitespace followed by a `//` comment, return the index past
/// that comment's newline (so removing the statement also removes its trailing
/// `// note`). Otherwise return `i` unchanged. Only same-line comments are
/// consumed — a comment on the next line belongs to the following policy.
fn trailing_comment_end(bytes: &[u8], i: usize) -> usize {
    let n = bytes.len();
    let mut j = i;
    while j < n && (bytes[j] == b' ' || bytes[j] == b'\t') {
        j += 1;
    }
    if j + 1 < n && bytes[j] == b'/' && bytes[j + 1] == b'/' {
        while j < n && bytes[j] != b'\n' {
            j += 1;
        }
        if j < n {
            j += 1; // include the trailing newline
        }
        j
    } else {
        i
    }
}

/// Advance past whitespace and full-line `//` comments from `i`; return the first
/// "real" (non-trivia) byte index, or `bytes.len()`.
fn skip_trivia(bytes: &[u8], mut i: usize) -> usize {
    let n = bytes.len();
    while i < n {
        let c = bytes[i];
        if c.is_ascii_whitespace() {
            i += 1;
        } else if c == b'/' && i + 1 < n && bytes[i + 1] == b'/' {
            i += 2;
            while i < n && bytes[i] != b'\n' {
                i += 1;
            }
        } else {
            break;
        }
    }
    i
}

/// From `i` (a statement start), return the index of the first TOP-LEVEL `;`
/// (outside strings and `//` comments), or `None` if there is none.
fn find_statement_end(bytes: &[u8], mut i: usize) -> Option<usize> {
    let n = bytes.len();
    let mut in_string = false;
    while i < n {
        let c = bytes[i];
        if in_string {
            if c == b'\\' {
                i += 2; // skip the escaped byte
                continue;
            }
            if c == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' => {
                in_string = true;
                i += 1;
            }
            b'/' if i + 1 < n && bytes[i + 1] == b'/' => {
                i += 2;
                while i < n && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b';' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// Extract the `@id("…")` annotation value from a statement's text, skipping
/// strings and `//` comments so an `@id(` appearing inside a string literal or
/// comment isn't mistaken for the annotation. `None` when the statement has no
/// `@id`.
fn statement_id(stmt: &str) -> Option<String> {
    let bytes = stmt.as_bytes();
    let n = bytes.len();
    let mut i = 0usize;
    let mut in_string = false;
    while i < n {
        let c = bytes[i];
        if in_string {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if c == b'"' {
            in_string = true;
            i += 1;
            continue;
        }
        if c == b'/' && i + 1 < n && bytes[i + 1] == b'/' {
            i += 2;
            while i < n && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // `@id` is ASCII and we're outside strings/comments, so byte index `i`
        // is a char boundary here — slicing is safe.
        if bytes[i] == b'@' && stmt[i..].starts_with("@id") {
            let after = stmt[i + 3..].trim_start();
            if let Some(rest) = after.strip_prefix('(') {
                let rest = rest.trim_start();
                if let Some(rest) = rest.strip_prefix('"') {
                    if let Some(end) = rest.find('"') {
                        return Some(rest[..end].to_string());
                    }
                }
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: the join contract — recomposing the fragments + tail reproduces
    /// the original content byte-for-byte.
    fn assert_join_roundtrips(content: &str) {
        let frags = segment_verified(content).expect("should segment");
        let mut joined = String::new();
        let mut cursor = 0usize;
        for f in &frags {
            // leading then statement, contiguous and in order.
            assert_eq!(f.leading.start, cursor, "fragments must be contiguous");
            joined.push_str(&content[f.leading.clone()]);
            joined.push_str(&content[f.statement.clone()]);
            cursor = f.statement.end;
        }
        joined.push_str(&content[cursor..]); // tail trivia
        assert_eq!(joined, content, "join(fragments)+tail must equal content");
    }

    const SIMPLE: &str = "@id(\"a\")\npermit(principal, action, resource);\n\
        @id(\"b\")\nforbid(principal, action, resource);\n";

    #[test]
    fn segments_simple_two_policies() {
        let frags = segment_verified(SIMPLE).unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].id.as_deref(), Some("a"));
        assert_eq!(frags[1].id.as_deref(), Some("b"));
        assert_join_roundtrips(SIMPLE);
    }

    #[test]
    fn preserves_comments_and_blank_lines() {
        let content = "// file header\n\n\
            @id(\"a\")\n// describes a\npermit(principal, action, resource);\n\n\n\
            @id(\"b\") @layer(\"x\")\nforbid(principal, action, resource); // trailing\n";
        let frags = segment_verified(content).unwrap();
        assert_eq!(frags.len(), 2);
        // The file header + blank line precedes the first statement → leading trivia.
        assert!(content[frags[0].leading.clone()].contains("file header"));
        // A comment BETWEEN `@id` and `permit` is mid-statement (the statement
        // starts at the first `@id` token), so it travels with the statement.
        assert!(content[frags[0].statement.clone()].contains("describes a"));
        // The whole thing recomposes byte-for-byte regardless of the split point.
        assert_join_roundtrips(content);
    }

    #[test]
    fn semicolon_inside_string_does_not_split() {
        // A `;` inside a string literal must NOT terminate the statement.
        let content =
            "@id(\"a\")\npermit(principal, action, resource)\nwhen { resource.name == \"a;b;c\" };\n";
        let frags = segment_verified(content).unwrap();
        assert_eq!(frags.len(), 1, "the string's semicolons must not split");
        assert_eq!(frags[0].id.as_deref(), Some("a"));
        assert_join_roundtrips(content);
    }

    #[test]
    fn at_id_inside_string_is_not_the_annotation() {
        // `@id(` inside a string must not be mistaken for the annotation.
        let content = "@id(\"real\")\npermit(principal, action, resource)\n\
            when { resource.name == \"@id(\\\"fake\\\")\" };\n";
        let frags = segment_verified(content).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(
            frags[0].id.as_deref(),
            Some("real"),
            "the real @id, not the one in the string"
        );
    }

    #[test]
    fn replace_changes_only_that_statement() {
        let updated = replace_policy(
            SIMPLE,
            "a",
            "@id(\"a\")\npermit(principal, action, resource) when { true };",
        )
        .unwrap();
        // Policy b is byte-identical; only a changed.
        assert!(updated.contains("when { true }"));
        assert!(updated.contains("@id(\"b\")\nforbid(principal, action, resource);"));
        // The result still parses + still segments to two policies.
        let frags = segment_verified(&updated).unwrap();
        assert_eq!(frags.len(), 2);
    }

    #[test]
    fn remove_drops_the_policy_and_its_leading_trivia() {
        let content = "@id(\"a\")\npermit(principal, action, resource);\n\
            // keep me with b\n@id(\"b\")\nforbid(principal, action, resource);\n";
        let updated = remove_policy(content, "a").unwrap();
        assert!(!updated.contains("@id(\"a\")"));
        assert!(updated.contains("@id(\"b\")"));
        // b's own leading comment survives.
        assert!(updated.contains("keep me with b"));
        segment_verified(&updated).unwrap();
    }

    #[test]
    fn remove_takes_the_trailing_inline_comment_with_it() {
        // A removed policy's OWN trailing `// note` (same line as its `;`) goes
        // with it — it isn't orphaned onto the next policy. A next-LINE comment,
        // which belongs to the following policy, stays.
        let content = "@id(\"a\")\npermit(principal, action, resource); // note for a\n\
            // header for b\n@id(\"b\")\nforbid(principal, action, resource);\n";
        let updated = remove_policy(content, "a").unwrap();
        assert!(
            !updated.contains("note for a"),
            "trailing inline comment removed with a"
        );
        assert!(
            updated.contains("header for b"),
            "b's own line-comment kept"
        );
        assert!(updated.contains("@id(\"b\")"));
        // Still valid + the result re-segments cleanly.
        segment_verified(&updated).unwrap();
    }

    #[test]
    fn append_adds_a_policy() {
        let updated =
            append_policy(SIMPLE, "@id(\"c\")\npermit(principal, action, resource);").unwrap();
        let frags = segment_verified(&updated).unwrap();
        assert_eq!(frags.len(), 3);
        assert_eq!(frags[2].id.as_deref(), Some("c"));
    }

    #[test]
    fn append_preserves_existing_bytes_verbatim() {
        // The existing bundle — including a tail comment and trailing blank lines
        // — is preserved byte-for-byte (a prefix of the result); add only ADDS
        // newlines + the new policy, never trims the bundle's tail.
        let content = "@id(\"a\")\npermit(principal, action, resource);\n// tail comment\n\n\n";
        let updated =
            append_policy(content, "@id(\"b\")\nforbid(principal, action, resource);").unwrap();
        assert!(
            updated.starts_with(content),
            "existing content must be preserved verbatim as a prefix; got:\n{updated}"
        );
        assert!(updated.contains("@id(\"b\")"));
        assert_eq!(segment_verified(&updated).unwrap().len(), 2);
    }

    #[test]
    fn unparseable_content_errors() {
        assert!(matches!(
            segment_verified("this is not cedar {{{"),
            Err(SegmentError::Parse(_))
        ));
    }

    #[test]
    fn unknown_id_is_not_found() {
        assert!(matches!(
            replace_policy(SIMPLE, "nope", "permit(principal, action, resource);"),
            Err(SegmentError::NotFound(_))
        ));
    }

    #[test]
    fn un_annotated_policy_segments_but_is_unaddressable() {
        // A policy with no @id: it's counted (so the cross-check passes) but has
        // id=None, so per-policy edit can't target it (whole-bundle still works).
        let content = "permit(principal, action, resource);\n\
            @id(\"b\")\nforbid(principal, action, resource);\n";
        let frags = segment_verified(content).unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].id, None);
        assert_eq!(frags[1].id.as_deref(), Some("b"));
        assert!(replace_policy(
            content,
            "b",
            "@id(\"b\")\npermit(principal, action, resource);"
        )
        .is_ok());
    }

    #[test]
    fn empty_and_whitespace_only_segment_to_nothing() {
        assert_eq!(segment_verified("").unwrap().len(), 0);
        assert_eq!(
            segment_verified("\n  \n// just a comment\n").unwrap().len(),
            0
        );
    }

    #[test]
    fn duplicate_id_is_ambiguous_not_silently_first() {
        // Two policies share @id("dup"). `PolicySet::from_str` accepts it (@id is
        // metadata), so the count + @id multiset would match — but addressing by
        // "dup" can't pick one policy. The segmenter must refuse rather than
        // silently address the first match.
        let content = "@id(\"dup\")\npermit(principal, action, resource);\n\
            @id(\"dup\")\nforbid(principal, action, resource);\n";
        assert!(matches!(
            segment_verified(content),
            Err(SegmentError::Ambiguous)
        ));
        // Every addressing entry point inherits the refusal → callers fall back.
        assert!(matches!(
            policy_statement(content, "dup"),
            Err(SegmentError::Ambiguous)
        ));
        assert!(matches!(
            replace_policy(
                content,
                "dup",
                "@id(\"dup\")\npermit(principal, action, resource);"
            ),
            Err(SegmentError::Ambiguous)
        ));
        assert!(matches!(
            remove_policy(content, "dup"),
            Err(SegmentError::Ambiguous)
        ));
    }

    #[test]
    fn ensure_single_policy_enforces_the_contract() {
        // Exactly one policy with the expected @id → ok.
        assert!(ensure_single_policy(
            "@id(\"a\")\npermit(principal, action, resource);",
            Some("a"),
        )
        .is_ok());
        // A leading comment + trailing whitespace is still one policy.
        assert!(ensure_single_policy(
            "// describe\n@id(\"a\")\npermit(principal, action, resource);\n",
            Some("a"),
        )
        .is_ok());
        // Two policies in an "edit one" payload → rejected.
        let err = ensure_single_policy(
            "@id(\"a\")\npermit(principal, action, resource);\n\
             @id(\"b\")\nforbid(principal, action, resource);",
            Some("a"),
        )
        .unwrap_err();
        assert!(err.contains("exactly one policy"), "got: {err}");
        // Renaming the target @id → rejected (rename = remove + add).
        let err = ensure_single_policy(
            "@id(\"renamed\")\npermit(principal, action, resource);",
            Some("a"),
        )
        .unwrap_err();
        assert!(err.contains("must stay \"a\""), "got: {err}");
        // Dropping the @id on an edit → rejected.
        let err =
            ensure_single_policy("permit(principal, action, resource);", Some("a")).unwrap_err();
        assert!(err.contains("must keep its @id"), "got: {err}");
        // Add path (no expected id): one policy ok, zero or many rejected.
        assert!(ensure_single_policy("permit(principal, action, resource);", None).is_ok());
        assert!(ensure_single_policy("// only a comment\n", None)
            .unwrap_err()
            .contains("exactly one policy"));
        assert!(ensure_single_policy("not valid cedar {{{", None)
            .unwrap_err()
            .contains("invalid"));
    }

    /// Round-trip every representative policy fixture — the ultimate fidelity
    /// check. Each file has rich `//` comments, `@id`/`@layer`/
    /// `@description`/`@tags` annotations, and multi-line `when`/`unless` bodies
    /// with string literals. The segmenter must reproduce each one byte-for-byte
    /// and agree with Cedar on the `@id` set, or it isn't safe to splice.
    #[test]
    fn round_trips_representative_policy_fixtures() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/policies");
        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read policies dir {}: {e}", dir.display()))
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("cedar"))
            .collect();
        entries.sort();
        assert!(
            !entries.is_empty(),
            "no policies/*.cedar found at {}",
            dir.display()
        );

        for path in &entries {
            let content = std::fs::read_to_string(path).unwrap();
            let frags = match segment_verified(&content) {
                Ok(f) => f,
                // A file the segmenter can't verify must fail SAFE: the caller
                // falls back to whole-bundle editing. Surface it loudly so we
                // know which real file the tokenizer can't address.
                Err(e) => panic!("segment {} failed: {e}", path.display()),
            };
            // join(fragments) + tail == content, byte-for-byte.
            let mut joined = String::new();
            let mut cursor = 0usize;
            for f in &frags {
                assert_eq!(
                    f.leading.start,
                    cursor,
                    "non-contiguous in {}",
                    path.display()
                );
                joined.push_str(&content[f.leading.clone()]);
                joined.push_str(&content[f.statement.clone()]);
                cursor = f.statement.end;
            }
            joined.push_str(&content[cursor..]);
            assert_eq!(joined, content, "round-trip mismatch in {}", path.display());
        }

        // And the whole bundle, concatenated the way the loader composes it.
        let bundle = entries
            .iter()
            .map(|p| std::fs::read_to_string(p).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let frags = segment_verified(&bundle).expect("concatenated bundle should segment");
        // Every fragment that Cedar gave an @id is individually addressable +
        // its statement is a non-empty slice of the original bundle.
        for f in &frags {
            if let Some(id) = &f.id {
                let stmt = policy_statement(&bundle, id).unwrap();
                assert!(!stmt.trim().is_empty(), "empty statement for @id {id}");
            }
        }
    }
}
