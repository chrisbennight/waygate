//! Tamper-evidence hash chain helpers for
//! `audit_log`.
//!
//! Each new audit row carries:
//! - `prev_hash`: the immediately-previous row's `row_hash` in
//!   the same `tenant_id` chain (NULL for the genesis row).
//! - `row_hash`: `sha256(prev_hash || \x00 || canonical-audit
//!   bytes)`, hex-encoded.
//!
//! Verification ([`crate::chain_verify`]) walks each tenant's chain in
//! `chain_seq ASC` order: for every row with a non-NULL
//! `row_hash`, recompute the digest from the durable columns
//! and compare to the stored value; check `prev_hash` equals
//! the previous row's `row_hash`. A mismatch is the tamper
//! indicator.
//!
//! ## Format: length-prefixed, collision-free
//!
//! The canonical-bytes encoding has
//! to round-trip every column value distinguishably. Two
//! distinct rows MUST produce distinct bytes. The format below
//! is a length-prefixed serialization that achieves this
//! structurally — no separator characters are reserved (so
//! arbitrary string content can't collide via the separator),
//! and every length is recorded so a missing field can't be
//! masked by an adjacent field's content.
//!
//! Per-field encoding:
//! - Required string `s`: `len(s):u64-LE` followed by the UTF-8
//!   bytes.
//! - Optional string `Option<s>`: `N` for None; `S` followed by
//!   `len(s):u64-LE` and the bytes for Some. Distinguishes
//!   `None` from `Some("")` — `principal_sub NULL` and
//!   `principal_sub ''` produce different bytes.
//! - Optional bool `Option<b>`: `t` / `f` / `N`.
//! - Optional i64 `Option<n>`: `N` for None; `S` followed by
//!   the 8 bytes of `n:i64-LE` for Some.
//! - `Vec<String>`: `count:u64-LE` followed by, for each
//!   element, `len(s):u64-LE` and the UTF-8 bytes. Different
//!   element counts produce different leading bytes regardless
//!   of element content — `["a\x01b"]` (count=1) can never
//!   collide with `["a","b"]` (count=2).
//! - `Uuid`: 16-byte canonical form (fixed size, no length
//!   prefix needed).
//! - `OffsetDateTime`: `unix_timestamp_micros:i128-LE`, pre-
//!   truncated from nanos to match Postgres TIMESTAMPTZ
//!   storage so the verifier rehashing from the durable column
//!   gets the same bytes.
//!
//! The leading `"audit-v1"` tag pins this format so a future
//! evolution can stay compatible by bumping the prefix.

use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use waygate_core::InvocationHierarchy;

fn write_required_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u64).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn write_opt_str(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        None => out.push(b'N'),
        Some(v) => {
            out.push(b'S');
            out.extend_from_slice(&(v.len() as u64).to_le_bytes());
            out.extend_from_slice(v.as_bytes());
        }
    }
}

fn write_opt_bool(out: &mut Vec<u8>, b: Option<bool>) {
    out.push(match b {
        Some(true) => b't',
        Some(false) => b'f',
        None => b'N',
    });
}

fn write_opt_i64(out: &mut Vec<u8>, n: Option<i64>) {
    match n {
        None => out.push(b'N'),
        Some(v) => {
            out.push(b'S');
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
}

fn write_str_vec(out: &mut Vec<u8>, vs: &[String]) {
    out.extend_from_slice(&(vs.len() as u64).to_le_bytes());
    for s in vs {
        out.extend_from_slice(&(s.len() as u64).to_le_bytes());
        out.extend_from_slice(s.as_bytes());
    }
}

/// Stable per-row byte representation that the chain hashes
/// over. Recorder calls this with `event.*` values just before
/// INSERT; the verifier calls it with the durable
/// row's columns. Both produce identical bytes for the same
/// row by construction — no serde reconstruction round-trip,
/// and no separator-based collision risk.
///
/// See the module docstring for the per-field encoding rules.
#[allow(clippy::too_many_arguments)]
pub fn canonical_audit_bytes(
    id: Uuid,
    ts: OffsetDateTime,
    category: &str,
    tenant: &str,
    action: &str,
    outcome: &str,
    principal_sub: Option<&str>,
    principal_email: Option<&str>,
    principal_groups: &[String],
    issuer: Option<&str>,
    server: Option<&str>,
    tool: Option<&str>,
    risk_level: Option<&str>,
    pii: Option<bool>,
    policy_ids: &[String],
    reason: Option<&str>,
    trace_id: Option<&str>,
    latency_ms: Option<i64>,
) -> Vec<u8> {
    // Thin delegate so legacy callers
    // (tests + pre-SCIM code paths) keep their signature.
    // SCIM-aware production callers (PgAuditSink insert +
    // chain_verify reader) call `canonical_audit_bytes_with_scim`
    // directly with the JSON column value. Because the extension
    // contributes zero bytes when SCIM is absent, the delegate
    // output is byte-identical to the pre-SCIM function.
    canonical_audit_bytes_with_scim(
        id,
        ts,
        category,
        tenant,
        action,
        outcome,
        principal_sub,
        principal_email,
        principal_groups,
        issuer,
        server,
        tool,
        risk_level,
        pii,
        policy_ids,
        reason,
        trace_id,
        latency_ms,
        None,
        &[],
    )
}

/// Canonical audit bytes
/// with the `scim_active` + `scim_groups` columns included in
/// the chain coverage. New SCIM-aware callers go through this
/// function; legacy callers continue to use
/// [`canonical_audit_bytes`] which delegates with `None`/`&[]`.
///
/// Typed primitives (not a JSON string) so producer and verifier
/// hash the same way as every other audit column —
/// `write_opt_bool` + `write_str_vec` — with no JSON
/// canonicalisation step that could drift between the recorder
/// and the reader.
///
/// Semantics:
/// - `scim_active == None && scim_groups.is_empty()` ⇒ no SCIM
///   on the row. Contributes ZERO bytes to the tail so pre-SCIM
///   rows hash byte-identically under both functions. Legacy
///   chain stays verifiable.
/// - Either is present ⇒ tail = sentinel byte `b'X'` ("scim
///   eXtension") + `write_opt_bool(scim_active)` +
///   `write_str_vec(scim_groups)`. The sentinel disambiguates
///   "row had SCIM" from a hypothetical legacy row whose
///   trailing column bytes happen to look like SCIM bytes.
///
/// Any change to either column (add / remove / flip) alters the
/// byte sequence and trips the chain walker on the next verify.
///
/// Thin delegate over [`canonical_audit_bytes_with_ext`] passing
/// `target = None`, so its output is byte-identical to the
/// pre-`target` function for every existing caller and chained row.
#[allow(clippy::too_many_arguments)]
pub fn canonical_audit_bytes_with_scim(
    id: Uuid,
    ts: OffsetDateTime,
    category: &str,
    tenant: &str,
    action: &str,
    outcome: &str,
    principal_sub: Option<&str>,
    principal_email: Option<&str>,
    principal_groups: &[String],
    issuer: Option<&str>,
    server: Option<&str>,
    tool: Option<&str>,
    risk_level: Option<&str>,
    pii: Option<bool>,
    policy_ids: &[String],
    reason: Option<&str>,
    trace_id: Option<&str>,
    latency_ms: Option<i64>,
    scim_active: Option<bool>,
    scim_groups: &[String],
) -> Vec<u8> {
    canonical_audit_bytes_with_ext(
        id,
        ts,
        category,
        tenant,
        action,
        outcome,
        principal_sub,
        principal_email,
        principal_groups,
        issuer,
        server,
        tool,
        risk_level,
        pii,
        policy_ids,
        reason,
        trace_id,
        latency_ms,
        scim_active,
        scim_groups,
        None,
    )
}

/// Canonical audit bytes with both the SCIM columns and the `target`
/// column included in the chain coverage. Thin delegate over
/// [`canonical_audit_bytes_with_ext2`] passing the decision-input
/// columns as `&[] / None / &[] / None`, so its output is byte-identical
/// to the pre-decision-inputs function for every existing caller and
/// chained row.
/// [`canonical_audit_bytes`] and [`canonical_audit_bytes_with_scim`] are
/// in turn thin delegates over this one.
///
/// `target` is appended as a tail extension AFTER the SCIM block, with
/// the same zero-bytes-when-absent contract:
/// - `target == None` ⇒ contributes ZERO bytes, so every pre-`target`
///   row (and every row that simply has no target) hashes byte-
///   identically to what it hashed before the column existed. The
///   legacy chain stays verifiable across the column-add migration —
///   the same guarantee migration 0022 gave the SCIM columns.
/// - `target == Some(t)` ⇒ tail = sentinel byte `b'T'` ("target
///   eXtension") + `write_required_str(t)`. The sentinel sits AFTER the
///   (self-delimiting) SCIM block, so presence/absence of `target` is
///   unambiguous regardless of whether SCIM is present.
///
/// Any change to `target` (add / remove / edit) alters the byte
/// sequence and trips the chain walker on the next verify.
#[allow(clippy::too_many_arguments)]
pub fn canonical_audit_bytes_with_ext(
    id: Uuid,
    ts: OffsetDateTime,
    category: &str,
    tenant: &str,
    action: &str,
    outcome: &str,
    principal_sub: Option<&str>,
    principal_email: Option<&str>,
    principal_groups: &[String],
    issuer: Option<&str>,
    server: Option<&str>,
    tool: Option<&str>,
    risk_level: Option<&str>,
    pii: Option<bool>,
    policy_ids: &[String],
    reason: Option<&str>,
    trace_id: Option<&str>,
    latency_ms: Option<i64>,
    scim_active: Option<bool>,
    scim_groups: &[String],
    target: Option<&str>,
) -> Vec<u8> {
    canonical_audit_bytes_with_ext2(
        id,
        ts,
        category,
        tenant,
        action,
        outcome,
        principal_sub,
        principal_email,
        principal_groups,
        issuer,
        server,
        tool,
        risk_level,
        pii,
        policy_ids,
        reason,
        trace_id,
        latency_ms,
        scim_active,
        scim_groups,
        target,
        &[],
        None,
        &[],
        None,
    )
}

/// Canonical audit bytes with the SCIM columns, the `target` column, AND
/// the authorization-decision INPUTS
/// (`req_scopes` / `auth_method` / `req_roles` / `side_effects`) included
/// in the chain coverage. This is the full producer/verifier function;
/// [`canonical_audit_bytes`], [`canonical_audit_bytes_with_scim`], and
/// [`canonical_audit_bytes_with_ext`] are thin delegates that pass
/// `None`/`&[]` for the columns they predate.
///
/// The four decision inputs are appended as a NEW tail extension AFTER the
/// `target` block (migration 0046), led by sentinel byte `b'D'` ("decision
/// inputs"), with the same zero-bytes-when-absent contract migrations 0022
/// (SCIM, `b'X'`) and 0046 (`target`, `b'T'`) used:
///
/// - ALL four absent (`req_scopes` empty, `auth_method == None`,
///   `req_roles` empty, `side_effects == None`) ⇒ contributes ZERO bytes,
///   so every pre-0062 row (NULL columns) hashes byte-identically to what
///   it hashed before the columns existed. The legacy chain stays
///   verifiable across the column-add migration. THIS IS LOAD-BEARING:
///   if it ever stops being zero-bytes-when-absent, every existing
///   audit_log row fails verification post-migration.
/// - Any one present ⇒ tail = `b'D'` + `write_str_vec(req_scopes)` +
///   `write_opt_str(auth_method)` + `write_str_vec(req_roles)` +
///   `write_opt_bool(side_effects)`, in that fixed order. The sentinel
///   sits AFTER the (self-delimiting) `target` block, so presence/absence
///   of the decision inputs is unambiguous regardless of whether SCIM or
///   `target` are present.
///
/// Any change to any of the four inputs (add / remove / edit / flip)
/// alters the byte sequence and trips the chain walker on the next verify,
/// so a tamper that rewrites a recorded decision's inputs is detectable.
#[allow(clippy::too_many_arguments)]
pub fn canonical_audit_bytes_with_ext2(
    id: Uuid,
    ts: OffsetDateTime,
    category: &str,
    tenant: &str,
    action: &str,
    outcome: &str,
    principal_sub: Option<&str>,
    principal_email: Option<&str>,
    principal_groups: &[String],
    issuer: Option<&str>,
    server: Option<&str>,
    tool: Option<&str>,
    risk_level: Option<&str>,
    pii: Option<bool>,
    policy_ids: &[String],
    reason: Option<&str>,
    trace_id: Option<&str>,
    latency_ms: Option<i64>,
    scim_active: Option<bool>,
    scim_groups: &[String],
    target: Option<&str>,
    // Decision inputs (migration 0062). Order is fixed and
    // documented above: req_scopes, auth_method, req_roles, side_effects.
    req_scopes: &[String],
    auth_method: Option<&str>,
    req_roles: &[String],
    side_effects: Option<bool>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"audit-v1");
    out.extend_from_slice(id.as_bytes());
    let ts_micros: i128 = ts.unix_timestamp_nanos() / 1_000;
    out.extend_from_slice(&ts_micros.to_le_bytes());
    write_required_str(&mut out, category);
    write_required_str(&mut out, tenant);
    write_required_str(&mut out, action);
    write_required_str(&mut out, outcome);
    write_opt_str(&mut out, principal_sub);
    write_opt_str(&mut out, principal_email);
    write_str_vec(&mut out, principal_groups);
    write_opt_str(&mut out, issuer);
    write_opt_str(&mut out, server);
    write_opt_str(&mut out, tool);
    write_opt_str(&mut out, risk_level);
    write_opt_bool(&mut out, pii);
    write_str_vec(&mut out, policy_ids);
    write_opt_str(&mut out, reason);
    write_opt_str(&mut out, trace_id);
    write_opt_i64(&mut out, latency_ms);
    if scim_active.is_some() || !scim_groups.is_empty() {
        out.push(b'X');
        write_opt_bool(&mut out, scim_active);
        write_str_vec(&mut out, scim_groups);
    }
    if let Some(t) = target {
        out.push(b'T');
        write_required_str(&mut out, t);
    }
    // Decision-inputs tail. Gated on "any of the four present" so a row
    // with none contributes zero bytes (legacy-row byte-compat). Ordered
    // deterministically; the per-field helpers are the same self-delimiting
    // primitives every other column uses.
    if !req_scopes.is_empty()
        || auth_method.is_some()
        || !req_roles.is_empty()
        || side_effects.is_some()
    {
        out.push(b'D');
        write_str_vec(&mut out, req_scopes);
        write_opt_str(&mut out, auth_method);
        write_str_vec(&mut out, req_roles);
        write_opt_bool(&mut out, side_effects);
    }
    out
}

/// Canonical audit bytes with the SCIM columns, the `target` column, the
/// decision inputs, AND the `acting_agent` column
/// included in the chain coverage. This is the full producer/verifier function
/// as of migration 0068; the producer (`PgAuditSink::insert`) and the verifier
/// (`chain_verify`) call this one.
///
/// Implemented as a thin wrapper that takes [`canonical_audit_bytes_with_ext2`]'s
/// output and appends `acting_agent` as a NEW tail extension AFTER the decision-
/// inputs block (migration 0062), led by sentinel byte `b'A'` ("acting agent"),
/// with the same zero-bytes-when-absent contract migrations 0022 (SCIM, `b'X'`),
/// 0046 (`target`, `b'T'`), and 0062 (decision inputs, `b'D'`) used:
///
/// - `acting_agent == None` ⇒ contributes ZERO bytes, so `ext3(.., None)` is
///   byte-identical to `ext2(..)` and every pre-0068 row (NULL column) hashes
///   exactly as before. The legacy chain stays verifiable across the column-add
///   migration. THIS IS LOAD-BEARING: if it ever stops being zero-bytes-when-
///   absent, every existing audit_log row fails verification post-migration.
/// - `acting_agent == Some(a)` ⇒ tail = `b'A'` + `write_required_str(a)`. The
///   sentinel sits AFTER the (self-delimiting) decision-inputs block, so the
///   presence/absence of `acting_agent` is unambiguous regardless of which
///   earlier extensions are present.
///
/// Any change to `acting_agent` (add / remove / edit) alters the byte sequence
/// and trips the chain walker on the next verify, so a tamper that rewrites who
/// (which agent) acted is detectable.
#[allow(clippy::too_many_arguments)]
pub fn canonical_audit_bytes_with_ext3(
    id: Uuid,
    ts: OffsetDateTime,
    category: &str,
    tenant: &str,
    action: &str,
    outcome: &str,
    principal_sub: Option<&str>,
    principal_email: Option<&str>,
    principal_groups: &[String],
    issuer: Option<&str>,
    server: Option<&str>,
    tool: Option<&str>,
    risk_level: Option<&str>,
    pii: Option<bool>,
    policy_ids: &[String],
    reason: Option<&str>,
    trace_id: Option<&str>,
    latency_ms: Option<i64>,
    scim_active: Option<bool>,
    scim_groups: &[String],
    target: Option<&str>,
    req_scopes: &[String],
    auth_method: Option<&str>,
    req_roles: &[String],
    side_effects: Option<bool>,
    // Acting-agent attribution (migration 0068).
    acting_agent: Option<&str>,
) -> Vec<u8> {
    let mut out = canonical_audit_bytes_with_ext2(
        id,
        ts,
        category,
        tenant,
        action,
        outcome,
        principal_sub,
        principal_email,
        principal_groups,
        issuer,
        server,
        tool,
        risk_level,
        pii,
        policy_ids,
        reason,
        trace_id,
        latency_ms,
        scim_active,
        scim_groups,
        target,
        req_scopes,
        auth_method,
        req_roles,
        side_effects,
    );
    if let Some(a) = acting_agent {
        out.push(b'A');
        write_required_str(&mut out, a);
    }
    out
}

/// Canonical audit bytes including nested invocation hierarchy.
///
/// An absent hierarchy contributes zero bytes, preserving every existing row
/// hash. A present hierarchy appends one self-identifying tail containing the
/// parent execution UUID, ordered step, stable call UUID, and attempt.
#[allow(clippy::too_many_arguments)]
pub fn canonical_audit_bytes_with_ext4(
    id: Uuid,
    ts: OffsetDateTime,
    category: &str,
    tenant: &str,
    action: &str,
    outcome: &str,
    principal_sub: Option<&str>,
    principal_email: Option<&str>,
    principal_groups: &[String],
    issuer: Option<&str>,
    server: Option<&str>,
    tool: Option<&str>,
    risk_level: Option<&str>,
    pii: Option<bool>,
    policy_ids: &[String],
    reason: Option<&str>,
    trace_id: Option<&str>,
    latency_ms: Option<i64>,
    scim_active: Option<bool>,
    scim_groups: &[String],
    target: Option<&str>,
    req_scopes: &[String],
    auth_method: Option<&str>,
    req_roles: &[String],
    side_effects: Option<bool>,
    acting_agent: Option<&str>,
    invocation_hierarchy: Option<&InvocationHierarchy>,
) -> Vec<u8> {
    let mut out = canonical_audit_bytes_with_ext3(
        id,
        ts,
        category,
        tenant,
        action,
        outcome,
        principal_sub,
        principal_email,
        principal_groups,
        issuer,
        server,
        tool,
        risk_level,
        pii,
        policy_ids,
        reason,
        trace_id,
        latency_ms,
        scim_active,
        scim_groups,
        target,
        req_scopes,
        auth_method,
        req_roles,
        side_effects,
        acting_agent,
    );
    if let Some(hierarchy) = invocation_hierarchy {
        out.push(b'H');
        out.extend_from_slice(hierarchy.parent_execution_id.as_bytes());
        out.extend_from_slice(&hierarchy.step.get().to_le_bytes());
        out.extend_from_slice(hierarchy.call_id.as_bytes());
        out.extend_from_slice(&hierarchy.attempt.get().to_le_bytes());
    }
    out
}

/// Thin delegate over [`canonical_audit_bytes_with_ext4`] adding the operation
/// a call selected.
///
/// The operation contributes zero bytes when absent, so every row written
/// before tools carried operations — and every row for a tool classified by
/// name alone — hashes exactly as it did. Only a row that actually recorded an
/// operation gains bytes, and no such row can predate this function.
///
/// The value is length-prefixed rather than terminated. An operation is caller
/// text and may contain any byte, so a terminator would be ambiguous the moment
/// a further extension appends after this one — the next field's bytes would be
/// indistinguishable from a continuation of the operation.
#[allow(clippy::too_many_arguments)]
pub fn canonical_audit_bytes_with_ext5(
    id: Uuid,
    ts: OffsetDateTime,
    category: &str,
    tenant: &str,
    action: &str,
    outcome: &str,
    principal_sub: Option<&str>,
    principal_email: Option<&str>,
    principal_groups: &[String],
    issuer: Option<&str>,
    server: Option<&str>,
    tool: Option<&str>,
    risk_level: Option<&str>,
    pii: Option<bool>,
    policy_ids: &[String],
    reason: Option<&str>,
    trace_id: Option<&str>,
    latency_ms: Option<i64>,
    scim_active: Option<bool>,
    scim_groups: &[String],
    target: Option<&str>,
    req_scopes: &[String],
    auth_method: Option<&str>,
    req_roles: &[String],
    side_effects: Option<bool>,
    acting_agent: Option<&str>,
    invocation_hierarchy: Option<&InvocationHierarchy>,
    operation: Option<&str>,
) -> Vec<u8> {
    let mut out = canonical_audit_bytes_with_ext4(
        id,
        ts,
        category,
        tenant,
        action,
        outcome,
        principal_sub,
        principal_email,
        principal_groups,
        issuer,
        server,
        tool,
        risk_level,
        pii,
        policy_ids,
        reason,
        trace_id,
        latency_ms,
        scim_active,
        scim_groups,
        target,
        req_scopes,
        auth_method,
        req_roles,
        side_effects,
        acting_agent,
        invocation_hierarchy,
    );
    if let Some(operation) = operation {
        out.push(b'P');
        let bytes = operation.as_bytes();
        out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(bytes);
    }
    out
}

/// Compute the chain hash for an audit row.
///
/// `prev_hash` is the previous row's `row_hash` (or `None` for
/// the genesis row of a tenant's chain). `audit_bytes` is the
/// output of [`canonical_audit_bytes`].
///
/// Layout: `sha256(prev_hash_or_empty || \x00 || audit_bytes)`,
/// hex-encoded. The `\x00` separator prevents the `("ab","cd")`
/// vs `("abcd","")` concatenation collision.
pub fn compute_row_hash(prev_hash: Option<&str>, audit_bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(prev_hash.unwrap_or("").as_bytes());
    h.update(b"\x00");
    h.update(audit_bytes);
    let digest = h.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bytes() -> Vec<u8> {
        canonical_audit_bytes(
            Uuid::from_u128(0x1234),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            "invocation",
            "default",
            "CallTool",
            "success",
            Some("alice@example.com"),
            None,
            &["mcp-users".to_owned()],
            Some("https://idp.example.com"),
            Some("example-messages"),
            Some("send"),
            Some("high"),
            Some(false),
            &["p0".to_owned()],
            None,
            None,
            Some(42),
        )
    }

    /// The hash function must be deterministic on the same inputs.
    #[test]
    fn compute_row_hash_is_deterministic() {
        let bytes = sample_bytes();
        let h1 = compute_row_hash(Some("deadbeef"), &bytes);
        let h2 = compute_row_hash(Some("deadbeef"), &bytes);
        assert_eq!(h1, h2);
        let g1 = compute_row_hash(None, &bytes);
        let g2 = compute_row_hash(None, &bytes);
        assert_eq!(g1, g2);
    }

    /// Different `prev_hash` MUST produce different `row_hash` —
    /// chaining property.
    #[test]
    fn compute_row_hash_depends_on_prev() {
        let bytes = sample_bytes();
        let a = compute_row_hash(Some("abc"), &bytes);
        let b = compute_row_hash(Some("xyz"), &bytes);
        let g = compute_row_hash(None, &bytes);
        assert_ne!(a, b);
        assert_ne!(a, g);
        assert_ne!(b, g);
    }

    /// Separator pin for the outer hash:
    /// `(prev="ab", body="cd")` vs `(prev="abcd", body="")`.
    #[test]
    fn compute_row_hash_separator_no_collision() {
        let a = compute_row_hash(Some("ab"), b"cd");
        let b = compute_row_hash(Some("abcd"), b"");
        assert_ne!(a, b);
    }

    /// canonical_audit_bytes must be deterministic.
    #[test]
    fn canonical_audit_bytes_is_deterministic() {
        let a = sample_bytes();
        let b = sample_bytes();
        assert_eq!(a, b);
    }

    /// `None` and `Some("")` MUST
    /// produce different bytes. Without this, a row where
    /// `principal_sub IS NULL` and a row where
    /// `principal_sub = ''` hash to the same value — verifier
    /// can't detect a NULL→empty-string mutation.
    #[test]
    fn canonical_audit_bytes_distinguishes_null_from_empty_string() {
        let with_none = canonical_audit_bytes(
            Uuid::nil(),
            OffsetDateTime::from_unix_timestamp(0).unwrap(),
            "c",
            "t",
            "a",
            "o",
            None, // principal_sub
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
            &[],
            None,
            None,
            None,
        );
        let with_empty = canonical_audit_bytes(
            Uuid::nil(),
            OffsetDateTime::from_unix_timestamp(0).unwrap(),
            "c",
            "t",
            "a",
            "o",
            Some(""), // principal_sub
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
            &[],
            None,
            None,
            None,
        );
        assert_ne!(
            with_none, with_empty,
            "NULL vs empty-string must hash distinctly",
        );
    }

    /// Vec encoding must be
    /// collision-free across element-boundary games. Length-
    /// prefixed encoding kills this structurally: `["a\x01b"]`
    /// (count=1, one 3-byte element) cannot produce the same
    /// bytes as `["a","b"]` (count=2, two 1-byte elements)
    /// because the leading count differs.
    #[test]
    fn canonical_audit_bytes_vec_no_separator_collision() {
        // Crafted vec that would have collided under the prior
        // `\x01`-join encoding.
        let one_with_sep = vec!["a\x01b".to_owned()];
        let two_no_sep = vec!["a".to_owned(), "b".to_owned()];
        let a = canonical_audit_bytes(
            Uuid::nil(),
            OffsetDateTime::from_unix_timestamp(0).unwrap(),
            "c",
            "t",
            "a",
            "o",
            None,
            None,
            &one_with_sep,
            None,
            None,
            None,
            None,
            None,
            &[],
            None,
            None,
            None,
        );
        let b = canonical_audit_bytes(
            Uuid::nil(),
            OffsetDateTime::from_unix_timestamp(0).unwrap(),
            "c",
            "t",
            "a",
            "o",
            None,
            None,
            &two_no_sep,
            None,
            None,
            None,
            None,
            None,
            &[],
            None,
            None,
            None,
        );
        assert_ne!(
            a, b,
            "length-prefixed Vec encoding must distinguish element splits",
        );
    }

    /// Every column input must affect the output — spot-check a
    /// few across the type space (Uuid / ts / required string /
    /// optional string / Option<bool> / Option<i64> / Vec).
    #[test]
    fn canonical_audit_bytes_sensitive_to_every_column() {
        let base = sample_bytes();
        // id
        let other = canonical_audit_bytes(
            Uuid::from_u128(0xFFFF),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            "invocation",
            "default",
            "CallTool",
            "success",
            Some("alice@example.com"),
            None,
            &["mcp-users".to_owned()],
            Some("https://idp.example.com"),
            Some("example-messages"),
            Some("send"),
            Some("high"),
            Some(false),
            &["p0".to_owned()],
            None,
            None,
            Some(42),
        );
        assert_ne!(base, other, "id change must alter canonical bytes");
        // outcome
        let other = canonical_audit_bytes(
            Uuid::from_u128(0x1234),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            "invocation",
            "default",
            "CallTool",
            "denied",
            Some("alice@example.com"),
            None,
            &["mcp-users".to_owned()],
            Some("https://idp.example.com"),
            Some("example-messages"),
            Some("send"),
            Some("high"),
            Some(false),
            &["p0".to_owned()],
            None,
            None,
            Some(42),
        );
        assert_ne!(base, other, "outcome change must alter canonical bytes");
        // pii
        let other = canonical_audit_bytes(
            Uuid::from_u128(0x1234),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            "invocation",
            "default",
            "CallTool",
            "success",
            Some("alice@example.com"),
            None,
            &["mcp-users".to_owned()],
            Some("https://idp.example.com"),
            Some("example-messages"),
            Some("send"),
            Some("high"),
            Some(true), // flipped
            &["p0".to_owned()],
            None,
            None,
            Some(42),
        );
        assert_ne!(base, other, "pii flip must alter canonical bytes");
        // latency_ms
        let other = canonical_audit_bytes(
            Uuid::from_u128(0x1234),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            "invocation",
            "default",
            "CallTool",
            "success",
            Some("alice@example.com"),
            None,
            &["mcp-users".to_owned()],
            Some("https://idp.example.com"),
            Some("example-messages"),
            Some("send"),
            Some("high"),
            Some(false),
            &["p0".to_owned()],
            None,
            None,
            Some(0),
        );
        assert_ne!(base, other, "latency_ms change must alter canonical bytes");
    }

    /// Vec ordering matters — swapping elements MUST produce
    /// different bytes.
    #[test]
    fn canonical_audit_bytes_preserves_array_order() {
        let a = canonical_audit_bytes(
            Uuid::nil(),
            OffsetDateTime::from_unix_timestamp(0).unwrap(),
            "c",
            "t",
            "a",
            "o",
            None,
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
            &["p0".to_owned(), "p1".to_owned()],
            None,
            None,
            None,
        );
        let b = canonical_audit_bytes(
            Uuid::nil(),
            OffsetDateTime::from_unix_timestamp(0).unwrap(),
            "c",
            "t",
            "a",
            "o",
            None,
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
            &["p1".to_owned(), "p0".to_owned()],
            None,
            None,
            None,
        );
        assert_ne!(a, b);
    }

    /// Microsecond truncation parity with Postgres TIMESTAMPTZ.
    #[test]
    fn canonical_audit_bytes_truncates_ts_to_microseconds() {
        let ts0 = OffsetDateTime::from_unix_timestamp_nanos(1_700_000_000_000_001_000).unwrap();
        let ts1 = OffsetDateTime::from_unix_timestamp_nanos(1_700_000_000_000_001_999).unwrap();
        let a = bytes_with_ts(ts0);
        let b = bytes_with_ts(ts1);
        assert_eq!(
            a, b,
            "ts within same microsecond must hash equally (Postgres-storage parity)",
        );
        let ts2 = OffsetDateTime::from_unix_timestamp_nanos(1_700_000_000_000_002_000).unwrap();
        let c = bytes_with_ts(ts2);
        assert_ne!(a, c);
    }

    fn bytes_with_ts(ts: OffsetDateTime) -> Vec<u8> {
        canonical_audit_bytes(
            Uuid::nil(),
            ts,
            "invocation",
            "default",
            "CallTool",
            "success",
            None,
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
            &[],
            None,
            None,
            None,
        )
    }

    /// Pins the load-bearing chain-compat
    /// invariant — a row with no SCIM facts MUST hash to the
    /// exact same bytes under `canonical_audit_bytes_with_scim`
    /// as it does under `canonical_audit_bytes`. Without this,
    /// every legacy row in production would fail the verifier
    /// after the SCIM column-add migration (0022).
    #[test]
    fn scim_extension_is_zero_bytes_when_absent() {
        let legacy = canonical_audit_bytes(
            Uuid::from_u128(0x1234),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            "invocation",
            "default",
            "CallTool",
            "success",
            Some("alice@example.com"),
            None,
            &["mcp-users".to_owned()],
            Some("https://idp.example.com"),
            Some("example-messages"),
            Some("send"),
            Some("high"),
            Some(false),
            &["p0".to_owned()],
            None,
            None,
            Some(42),
        );
        let extended = canonical_audit_bytes_with_scim(
            Uuid::from_u128(0x1234),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            "invocation",
            "default",
            "CallTool",
            "success",
            Some("alice@example.com"),
            None,
            &["mcp-users".to_owned()],
            Some("https://idp.example.com"),
            Some("example-messages"),
            Some("send"),
            Some("high"),
            Some(false),
            &["p0".to_owned()],
            None,
            None,
            Some(42),
            None,
            &[],
        );
        assert_eq!(
            legacy, extended,
            "no-SCIM extension call MUST produce byte-identical canonical bytes \
             to the legacy function, otherwise every pre-SCIM audit_log row \
             fails verification post-migration",
        );
    }

    /// Pin that SCIM contributions are
    /// actually IN the hash — a row with SCIM facts must hash
    /// differently than the same row without, otherwise a tamper
    /// adding/removing SCIM would go undetected.
    #[test]
    fn scim_extension_changes_bytes_when_present() {
        let without = canonical_audit_bytes_with_scim(
            Uuid::from_u128(0x1234),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            "invocation",
            "default",
            "CallTool",
            "success",
            Some("alice@example.com"),
            None,
            &["mcp-users".to_owned()],
            Some("https://idp.example.com"),
            Some("example-messages"),
            Some("send"),
            Some("high"),
            Some(false),
            &["p0".to_owned()],
            None,
            None,
            Some(42),
            None,
            &[],
        );
        let with_scim = canonical_audit_bytes_with_scim(
            Uuid::from_u128(0x1234),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            "invocation",
            "default",
            "CallTool",
            "success",
            Some("alice@example.com"),
            None,
            &["mcp-users".to_owned()],
            Some("https://idp.example.com"),
            Some("example-messages"),
            Some("send"),
            Some("high"),
            Some(false),
            &["p0".to_owned()],
            None,
            None,
            Some(42),
            Some(true),
            &["admins".to_owned()],
        );
        assert_ne!(
            without, with_scim,
            "SCIM contribution must be in the canonical bytes, otherwise \
             a tamper adding scim_active=true would not trip the chain walker",
        );

        // Flipping scim_active must also change the bytes —
        // protects against a tamper that toggles active from
        // true to false while leaving groups intact.
        let with_inactive = canonical_audit_bytes_with_scim(
            Uuid::from_u128(0x1234),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            "invocation",
            "default",
            "CallTool",
            "success",
            Some("alice@example.com"),
            None,
            &["mcp-users".to_owned()],
            Some("https://idp.example.com"),
            Some("example-messages"),
            Some("send"),
            Some("high"),
            Some(false),
            &["p0".to_owned()],
            None,
            None,
            Some(42),
            Some(false),
            &["admins".to_owned()],
        );
        assert_ne!(
            with_scim, with_inactive,
            "flipping scim_active must change canonical bytes",
        );
    }

    /// Migration 0046, load-bearing chain-compat invariant (mirrors
    /// `scim_extension_is_zero_bytes_when_absent`): a row with no `target`
    /// MUST hash to the exact same bytes under
    /// `canonical_audit_bytes_with_ext` as under the legacy
    /// `canonical_audit_bytes`. Without this, every pre-0046 audit_log row
    /// fails the verifier after the column-add migration.
    #[test]
    fn target_extension_is_zero_bytes_when_absent() {
        let legacy = canonical_audit_bytes(
            Uuid::from_u128(0x1234),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            "api_key_lifecycle",
            "default",
            "ApiKeyMinted",
            "success",
            Some("operator@example.com"),
            None,
            &["mcp-users".to_owned()],
            Some("https://idp.example.com"),
            None,
            None,
            None,
            None,
            &["p0".to_owned()],
            Some("name=foo sub=bar"),
            None,
            None,
        );
        let extended = canonical_audit_bytes_with_ext(
            Uuid::from_u128(0x1234),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            "api_key_lifecycle",
            "default",
            "ApiKeyMinted",
            "success",
            Some("operator@example.com"),
            None,
            &["mcp-users".to_owned()],
            Some("https://idp.example.com"),
            None,
            None,
            None,
            None,
            &["p0".to_owned()],
            Some("name=foo sub=bar"),
            None,
            None,
            None, // scim_active
            &[],  // scim_groups
            None, // target
        );
        assert_eq!(
            legacy, extended,
            "a no-target extension call MUST produce byte-identical canonical \
             bytes to the legacy function, otherwise every pre-0046 audit_log \
             row fails verification post-migration",
        );
    }

    /// Migration 0046: pin that `target` is actually IN the hash — adding a
    /// target, and changing it, must alter the bytes, otherwise a tamper
    /// that edits the recorded subject would go undetected by the chain
    /// walker.
    #[test]
    fn target_extension_changes_bytes_when_present() {
        let bytes_for = |target: Option<&str>| {
            canonical_audit_bytes_with_ext(
                Uuid::from_u128(0x1234),
                OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
                "api_key_lifecycle",
                "default",
                "ApiKeyMinted",
                "success",
                Some("operator@example.com"),
                None,
                &["mcp-users".to_owned()],
                Some("https://idp.example.com"),
                None,
                None,
                None,
                None,
                &["p0".to_owned()],
                Some("r"),
                None,
                None,
                None,
                &[],
                target,
            )
        };
        let none = bytes_for(None);
        let svc_a = bytes_for(Some("svc:example-triage"));
        let svc_b = bytes_for(Some("workstation@example.test"));
        assert_ne!(
            none, svc_a,
            "adding a target must change canonical bytes, else a tamper \
             setting target would not trip the chain walker",
        );
        assert_ne!(
            svc_a, svc_b,
            "different targets must hash distinctly so the verifier detects a \
             target mutation",
        );
    }

    /// Migration 0062, load-bearing chain-compat invariant (mirrors
    /// `scim_extension_is_zero_bytes_when_absent` /
    /// `target_extension_is_zero_bytes_when_absent`): a row with NONE of the
    /// four decision inputs MUST hash to the exact same bytes under
    /// `canonical_audit_bytes_with_ext2` as under the legacy
    /// `canonical_audit_bytes`. Without this, every pre-0062 audit_log row
    /// fails the verifier after the column-add migration.
    #[test]
    fn decision_inputs_extension_is_zero_bytes_when_absent() {
        let legacy = canonical_audit_bytes(
            Uuid::from_u128(0x1234),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            "invocation",
            "default",
            "CallTool",
            "success",
            Some("alice@example.com"),
            None,
            &["mcp-users".to_owned()],
            Some("https://idp.example.com"),
            Some("example-messages"),
            Some("send"),
            Some("high"),
            Some(false),
            &["p0".to_owned()],
            None,
            None,
            Some(42),
        );
        let extended = canonical_audit_bytes_with_ext2(
            Uuid::from_u128(0x1234),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            "invocation",
            "default",
            "CallTool",
            "success",
            Some("alice@example.com"),
            None,
            &["mcp-users".to_owned()],
            Some("https://idp.example.com"),
            Some("example-messages"),
            Some("send"),
            Some("high"),
            Some(false),
            &["p0".to_owned()],
            None,
            None,
            Some(42),
            None, // scim_active
            &[],  // scim_groups
            None, // target
            &[],  // req_scopes
            None, // auth_method
            &[],  // req_roles
            None, // side_effects
        );
        assert_eq!(
            legacy, extended,
            "a no-decision-inputs ext2 call MUST produce byte-identical canonical \
             bytes to the legacy function, otherwise every pre-0062 audit_log row \
             fails verification post-migration",
        );
    }

    /// Migration 0062: pin that EACH of the four decision inputs is actually
    /// IN the hash — setting or changing any one alters the bytes, otherwise
    /// a tamper rewriting a recorded decision's inputs would go undetected by
    /// the chain walker (and decision replay would re-evaluate against
    /// forged inputs without the chain noticing).
    #[test]
    fn decision_inputs_extension_changes_bytes_when_present() {
        // Helper: all-absent baseline, then each field toggled individually.
        let bytes_for = |req_scopes: &[String],
                         auth_method: Option<&str>,
                         req_roles: &[String],
                         side_effects: Option<bool>| {
            canonical_audit_bytes_with_ext2(
                Uuid::from_u128(0x1234),
                OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
                "invocation",
                "default",
                "CallTool",
                "success",
                Some("alice@example.com"),
                None,
                &["mcp-users".to_owned()],
                Some("https://idp.example.com"),
                Some("example-messages"),
                Some("send"),
                Some("high"),
                Some(false),
                &["p0".to_owned()],
                None,
                None,
                Some(42),
                None,
                &[],
                None,
                req_scopes,
                auth_method,
                req_roles,
                side_effects,
            )
        };

        let absent = bytes_for(&[], None, &[], None);

        // req_scopes present.
        let with_scopes = bytes_for(&["mcp:invoke".to_owned()], None, &[], None);
        assert_ne!(
            absent, with_scopes,
            "adding req_scopes must change canonical bytes",
        );

        // auth_method present.
        let with_auth = bytes_for(&[], Some("api_key"), &[], None);
        assert_ne!(
            absent, with_auth,
            "adding auth_method must change canonical bytes",
        );
        // and a different auth_method hashes distinctly.
        let with_auth_oauth = bytes_for(&[], Some("oauth"), &[], None);
        assert_ne!(
            with_auth, with_auth_oauth,
            "a different auth_method must hash distinctly",
        );

        // req_roles present.
        let with_roles = bytes_for(&[], None, &["tenant_admin".to_owned()], None);
        assert_ne!(
            absent, with_roles,
            "adding req_roles must change canonical bytes",
        );

        // side_effects present, and flipping it.
        let with_se_true = bytes_for(&[], None, &[], Some(true));
        let with_se_false = bytes_for(&[], None, &[], Some(false));
        assert_ne!(
            absent, with_se_true,
            "setting side_effects must change canonical bytes",
        );
        assert_ne!(
            with_se_true, with_se_false,
            "flipping side_effects must change canonical bytes",
        );

        // The sentinel disambiguates an empty-but-present case: side_effects=Some
        // with everything else empty must differ from all-absent (covered above)
        // AND from a req_scopes-only row, proving the fields don't collapse.
        assert_ne!(
            with_se_true, with_scopes,
            "distinct decision-input fields must produce distinct bytes",
        );
    }

    /// Migration 0068, load-bearing chain-compat invariant (mirrors the SCIM /
    /// `target` / decision-input zero-bytes-when-absent tests): a row with no
    /// `acting_agent` MUST hash to the exact same bytes under
    /// `canonical_audit_bytes_with_ext3` as under `canonical_audit_bytes_with_ext2`
    /// (and therefore the legacy `canonical_audit_bytes`). Without this, every
    /// pre-0068 audit_log row fails the verifier after the column-add migration.
    #[test]
    fn acting_agent_extension_is_zero_bytes_when_absent() {
        let ext2 = canonical_audit_bytes_with_ext2(
            Uuid::from_u128(0x1234),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            "invocation",
            "default",
            "CallTool",
            "success",
            Some("alice@example.com"),
            None,
            &["mcp-users".to_owned()],
            Some("https://idp.example.com"),
            Some("example-messages"),
            Some("send"),
            Some("high"),
            Some(false),
            &["p0".to_owned()],
            None,
            None,
            Some(42),
            None,
            &[],
            None,
            &["mcp:invoke".to_owned()],
            Some("oauth"),
            &[],
            Some(true),
        );
        let ext3_none = canonical_audit_bytes_with_ext3(
            Uuid::from_u128(0x1234),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            "invocation",
            "default",
            "CallTool",
            "success",
            Some("alice@example.com"),
            None,
            &["mcp-users".to_owned()],
            Some("https://idp.example.com"),
            Some("example-messages"),
            Some("send"),
            Some("high"),
            Some(false),
            &["p0".to_owned()],
            None,
            None,
            Some(42),
            None,
            &[],
            None,
            &["mcp:invoke".to_owned()],
            Some("oauth"),
            &[],
            Some(true),
            None, // acting_agent
        );
        assert_eq!(
            ext2, ext3_none,
            "a no-acting_agent ext3 call MUST produce byte-identical canonical \
             bytes to ext2, otherwise every pre-0068 audit_log row fails \
             verification post-migration",
        );
    }

    /// One audit row through the encoding that predates the operation field.
    fn ext4_sample() -> Vec<u8> {
        canonical_audit_bytes_with_ext4(
            Uuid::from_u128(0x1234),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            "invocation",
            "default",
            "CallTool",
            "success",
            Some("alice@example.com"),
            None,
            &["mcp-users".to_owned()],
            Some("https://idp.example.com"),
            Some("example-messages"),
            Some("send"),
            Some("high"),
            Some(false),
            &["p0".to_owned()],
            None,
            None,
            Some(42),
            None,
            &[],
            None,
            &[],
            None,
            &[],
            None,
            None,
            None,
        )
    }

    /// The same row through the encoding that carries it.
    fn ext5_sample(operation: Option<&str>) -> Vec<u8> {
        canonical_audit_bytes_with_ext5(
            Uuid::from_u128(0x1234),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            "invocation",
            "default",
            "CallTool",
            "success",
            Some("alice@example.com"),
            None,
            &["mcp-users".to_owned()],
            Some("https://idp.example.com"),
            Some("example-messages"),
            Some("send"),
            Some("high"),
            Some(false),
            &["p0".to_owned()],
            None,
            None,
            Some(42),
            None,
            &[],
            None,
            &[],
            None,
            &[],
            None,
            None,
            None,
            operation,
        )
    }

    /// An operation-free row must hash exactly as it did before the column
    /// existed, or every audit_log row already written fails chain
    /// verification the moment the verifier starts calling the wider function.
    #[test]
    fn operation_extension_is_byte_identical_when_absent() {
        assert_eq!(
            ext4_sample(),
            ext5_sample(None),
            "a no-operation ext5 call MUST produce byte-identical canonical bytes \
             to ext4, otherwise every existing audit_log row fails verification",
        );
    }

    /// The operation has to be IN the hash: a tamper rewriting which operation
    /// a call performed would otherwise pass the chain walker, and for an
    /// executor the tool name alone does not say what ran.
    #[test]
    fn operation_extension_changes_bytes_when_present() {
        assert_ne!(
            ext5_sample(None),
            ext5_sample(Some("projects.list")),
            "recording an operation must alter the bytes",
        );
        assert_ne!(
            ext5_sample(Some("projects.list")),
            ext5_sample(Some("secrets.reveal")),
            "rewriting which operation ran must alter the bytes",
        );
    }

    /// Migration 0068: pin that `acting_agent` is actually IN the hash — adding
    /// it, and changing it, must alter the bytes, otherwise a tamper that
    /// rewrites which agent acted on a human's behalf would go undetected by the
    /// chain walker.
    #[test]
    fn acting_agent_extension_changes_bytes_when_present() {
        let bytes_for = |acting_agent: Option<&str>| {
            canonical_audit_bytes_with_ext3(
                Uuid::from_u128(0x1234),
                OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
                "invocation",
                "default",
                "CallTool",
                "success",
                Some("alice@example.com"),
                None,
                &["mcp-users".to_owned()],
                Some("https://idp.example.com"),
                Some("example-messages"),
                Some("send"),
                Some("high"),
                Some(false),
                &["p0".to_owned()],
                None,
                None,
                Some(42),
                None,
                &[],
                None,
                &[],
                None,
                &[],
                None,
                acting_agent,
            )
        };
        let none = bytes_for(None);
        let agent_a = bytes_for(Some("agent:ops-chat"));
        let agent_b = bytes_for(Some("agent:policy-review"));
        assert_ne!(
            none, agent_a,
            "adding acting_agent must change canonical bytes, else a tamper \
             setting acting_agent would not trip the chain walker",
        );
        assert_ne!(
            agent_a, agent_b,
            "different acting_agents must hash distinctly so the verifier detects \
             an actor mutation",
        );
    }

    #[test]
    fn invocation_hierarchy_extension_is_compatible_and_chain_covered() {
        use std::num::NonZeroU32;

        let bytes_for = |hierarchy: Option<&InvocationHierarchy>| {
            canonical_audit_bytes_with_ext4(
                Uuid::from_u128(0x1234),
                OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
                "invocation",
                "default",
                "CallTool",
                "success",
                Some("alice@example.com"),
                None,
                &["mcp-users".to_owned()],
                Some("https://idp.example.com"),
                Some("example-messages"),
                Some("send"),
                Some("high"),
                Some(false),
                &["p0".to_owned()],
                None,
                None,
                Some(42),
                None,
                &[],
                None,
                &[],
                None,
                &[],
                None,
                Some("agent:ops-chat"),
                hierarchy,
            )
        };
        let ext3 = canonical_audit_bytes_with_ext3(
            Uuid::from_u128(0x1234),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            "invocation",
            "default",
            "CallTool",
            "success",
            Some("alice@example.com"),
            None,
            &["mcp-users".to_owned()],
            Some("https://idp.example.com"),
            Some("example-messages"),
            Some("send"),
            Some("high"),
            Some(false),
            &["p0".to_owned()],
            None,
            None,
            Some(42),
            None,
            &[],
            None,
            &[],
            None,
            &[],
            None,
            Some("agent:ops-chat"),
        );
        let first = InvocationHierarchy::new(
            Uuid::from_u128(0x10),
            NonZeroU32::new(1).unwrap(),
            Uuid::from_u128(0x20),
            NonZeroU32::new(1).unwrap(),
        );
        let retry = InvocationHierarchy::new(
            first.parent_execution_id,
            first.step,
            first.call_id,
            NonZeroU32::new(2).unwrap(),
        );
        let changed_parent = InvocationHierarchy::new(
            Uuid::from_u128(0x11),
            first.step,
            first.call_id,
            first.attempt,
        );
        let changed_step = InvocationHierarchy::new(
            first.parent_execution_id,
            NonZeroU32::new(2).unwrap(),
            first.call_id,
            first.attempt,
        );
        let changed_call = InvocationHierarchy::new(
            first.parent_execution_id,
            first.step,
            Uuid::from_u128(0x21),
            first.attempt,
        );

        assert_eq!(bytes_for(None), ext3);
        assert_ne!(bytes_for(Some(&first)), ext3);
        let baseline = bytes_for(Some(&first));
        for changed in [changed_parent, changed_step, changed_call, retry] {
            assert_ne!(baseline, bytes_for(Some(&changed)));
        }
    }
}
