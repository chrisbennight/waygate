//! Tamper-evidence verifier for the audit_log
//! hash chain built at insert time.
//!
//! Each chain-bearing row (`row_hash IS NOT NULL`) was hashed as
//! `sha256(prev_hash || \x00 || canonical_audit_bytes(...))` with
//! `prev_hash` pointing at the row immediately previous in the
//! same `tenant_id` chain (NULL for that tenant's genesis row).
//! See `crate::hashchain` for the byte format.
//!
//! Verification rehashes every chain-bearing row from its durable
//! columns and checks two invariants:
//!
//! 1. `row_hash` (durable) equals the recomputed digest. Detects
//!    any in-place mutation of column values — the column itself
//!    can be edited by an operator with DB privileges that bypass
//!    the BEFORE-UPDATE trigger (e.g. dropping the trigger
//!    then re-inserting via direct SQL), but the recomputed
//!    digest won't match.
//! 2. `prev_hash` (durable) equals the prior row's stored
//!    `row_hash`. Detects insertion or deletion of rows in the
//!    middle of a chain — a missing row would make the next
//!    row's `prev_hash` point at a `row_hash` that's no longer
//!    the prior row's; an inserted row breaks both halves.
//!
//! The verification is split into a pure walker (this module's
//! [`verify_chain_rows`]) and a Postgres adapter (the
//! `verify_chain` method on [`crate::AuditReader`]). The pure
//! walker is the unit-tested core; the adapter just selects the
//! rows and hands them off.
//!
//! ## Windowing
//!
//! The endpoint accepts `from/to` ts predicates and an
//! `after_chain_seq` strict-after pagination cursor: `ts`
//! is caller-assigned and can be
//! out-of-order with
//! `chain_seq`, so applying ts to the walk SELECT skips
//! interior chain rows and produces false `BrokenLink`
//! reports. The adapter therefore translates any ts predicate
//! into a `chain_seq` range (via `MIN(chain_seq)`/`MAX(chain_seq)`
//! over rows matching ts) and walks every chain-bearing row
//! within that range — never ts directly. Operators retain the
//! "verify rows touching this time window" intent; the chain
//! links stay intact.
//!
//! ## Truncation and pagination
//!
//! The adapter caps the walk at `limit` (default 1000, clamp
//! 10_000). When the cap is hit, status is [`ChainVerifyStatus::Incomplete`]
//! (not `Ok`) and `next_after_chain_seq` is set, so an operator
//! can paginate forward. `Ok` means the walk completed without
//! truncation. A tamper past the
//! cap could otherwise be silently missed under `Ok`.
//!
//! ## Known limitations
//!
//! - **Tail-deletion is not detectable from the verifier
//!   alone.** An attacker who drops the BEFORE-mutate triggers
//!   on `audit_log`, `DELETE`s the tail rows, then re-installs
//!   the triggers leaves the surviving prefix internally
//!   consistent — the verifier sees a shorter chain and reports
//!   `Ok`. Mitigation: every report carries `chain_head`
//!   (`MAX(chain_seq)` + its `row_hash`); operators can record
//!   it externally between verifier runs and a regression on
//!   either field is the detection signal. A real
//!   Merkle-root attestation that doesn't depend on the same
//!   DB is a follow-up beyond this slice.

use serde::Serialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::hashchain::{canonical_audit_bytes_with_ext5, compute_row_hash};

/// One durable audit row, exactly as needed to recompute its
/// canonical bytes and check both chain invariants.
///
/// Field order mirrors the audit_log column projection the
/// Postgres adapter SELECTs — keeping the projection list, this
/// struct, and the call into `canonical_audit_bytes` lined up
/// makes the verifier easy to audit by reading the file
/// top-to-bottom.
#[derive(Debug, Clone)]
pub struct ChainVerifyRow {
    pub id: Uuid,
    pub chain_seq: i64,
    pub ts: OffsetDateTime,
    pub category: String,
    pub tenant_id: String,
    pub action: String,
    pub outcome: String,
    pub principal_sub: Option<String>,
    pub principal_email: Option<String>,
    pub principal_groups: Vec<String>,
    pub issuer: Option<String>,
    pub server: Option<String>,
    pub tool: Option<String>,
    pub risk_level: Option<String>,
    pub pii: Option<bool>,
    pub policy_ids: Vec<String>,
    pub reason: Option<String>,
    pub trace_id: Option<String>,
    pub latency_ms: Option<i64>,
    pub prev_hash: Option<String>,
    pub row_hash: String,
    /// SCIM `active` flag column. `None`
    /// for legacy rows + for principals that weren't SCIM-
    /// enriched. Chain coverage handled via
    /// [`canonical_audit_bytes_with_scim`] — legacy rows hash
    /// byte-identically under the extended function.
    pub scim_active: Option<bool>,
    /// SCIM group names column. Empty
    /// for legacy rows + for principals that weren't SCIM-
    /// enriched.
    pub scim_groups: Vec<String>,
    /// Migration 0046: the structured `target` column. `None` for
    /// legacy rows + rows with no target. Chain coverage handled
    /// via [`canonical_audit_bytes_with_ext`] — a `None` target
    /// contributes zero tail bytes, so legacy rows hash
    /// byte-identically under the extended function.
    pub target: Option<String>,
    /// Migration 0062: the four authorization-decision
    /// input columns. `None` / empty for legacy rows + non-decision rows.
    /// Chain coverage handled via [`canonical_audit_bytes_with_ext2`] —
    /// all-absent contributes zero tail bytes, so legacy rows hash
    /// byte-identically under the extended function and keep verifying.
    /// The verifier MUST read and thread these or a post-0062 row with the
    /// inputs present would fail Invariant-2 (BadRowHash) spuriously.
    pub req_scopes: Vec<String>,
    pub auth_method: Option<String>,
    pub req_roles: Vec<String>,
    pub side_effects: Option<bool>,
    /// Agent attribution (migration 0068): the agent that acted on behalf
    /// of the principal. `None` for legacy rows + direct human actions ⇒ the
    /// ext3 tail contributes zero bytes ⇒ hash equals the pre-0068 value. The
    /// verifier MUST read and thread it or a post-0068 row carrying it would
    /// fail Invariant-2 (BadRowHash) spuriously.
    pub acting_agent: Option<String>,
    /// The operation an invocation selected. Legacy rows decode `None`, which
    /// contributes zero bytes, so their stored hashes still verify.
    pub operation: Option<String>,
    /// Nested invocation attribution. Absent on legacy rows and direct calls;
    /// present values are covered by the canonical hash tail.
    pub invocation_hierarchy: Option<waygate_core::InvocationHierarchy>,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for ChainVerifyRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            id: row.try_get("id")?,
            chain_seq: row.try_get("chain_seq")?,
            ts: row.try_get("ts")?,
            // `category` is NOT NULL for chain-bearing rows
            // (the recorder always populates it on the
            // transactional path) but the column is
            // nullable for best-effort rows. The
            // partial index + `WHERE row_hash IS NOT NULL`
            // already filters those out before this row
            // reaches us; we double-check with a default to
            // empty string so a hypothetical NULL doesn't
            // crash the query — it would simply not match
            // the recomputed digest, surfacing as a
            // BadRowHash mismatch, which is the correct
            // operator signal.
            category: row
                .try_get::<Option<String>, _>("category")?
                .unwrap_or_default(),
            tenant_id: row.try_get("tenant_id")?,
            action: row.try_get("action")?,
            outcome: row.try_get("outcome")?,
            principal_sub: row.try_get("principal_sub")?,
            principal_email: row.try_get("principal_email")?,
            principal_groups: row.try_get("principal_groups")?,
            issuer: row.try_get("issuer")?,
            server: row.try_get("server")?,
            tool: row.try_get("tool")?,
            risk_level: row.try_get("risk_level")?,
            pii: row.try_get("pii")?,
            policy_ids: row.try_get("policy_ids")?,
            reason: row.try_get("reason")?,
            trace_id: row.try_get("trace_id")?,
            latency_ms: row.try_get("latency_ms")?,
            prev_hash: row.try_get("prev_hash")?,
            row_hash: row.try_get("row_hash")?,
            // Nullable columns. Legacy
            // rows have NULL / NULL — both decode to the empty
            // value here, which canonical_audit_bytes_with_scim
            // treats as "no SCIM extension" (zero tail bytes),
            // matching the earlier chain hash for those rows.
            scim_active: row.try_get("scim_active").ok().flatten(),
            scim_groups: row
                .try_get::<Option<Vec<String>>, _>("scim_groups")
                .ok()
                .flatten()
                .unwrap_or_default(),
            // Migration 0046: nullable; legacy rows decode to None,
            // which contributes zero tail bytes — matching the
            // pre-0046 chain hash for those rows.
            target: row.try_get("target").ok().flatten(),
            // Migration 0062: nullable decision-input
            // columns. Legacy rows decode to None / empty ⇒ the ext2 tail
            // contributes zero bytes ⇒ hash equals the pre-0062 value, so
            // existing audit_log rows continue to verify cleanly.
            req_scopes: row
                .try_get::<Option<Vec<String>>, _>("req_scopes")
                .ok()
                .flatten()
                .unwrap_or_default(),
            auth_method: row.try_get("auth_method").ok().flatten(),
            req_roles: row
                .try_get::<Option<Vec<String>>, _>("req_roles")
                .ok()
                .flatten()
                .unwrap_or_default(),
            side_effects: row.try_get("side_effects").ok().flatten(),
            // Migration 0068: nullable; legacy rows
            // decode to None ⇒ the ext3 tail contributes zero bytes ⇒ hash
            // equals the pre-0068 value, so existing rows keep verifying.
            acting_agent: row.try_get("acting_agent").ok().flatten(),
            operation: row.try_get("operation").ok().flatten(),
            invocation_hierarchy: crate::audit::invocation_hierarchy_from_row(row)?,
        })
    }
}

/// Outcome of walking a tenant's chain over a request window.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ChainVerifyReport {
    pub tenant_id: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub from: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub to: Option<OffsetDateTime>,
    pub rows_walked: u64,
    pub status: ChainVerifyStatus,
    /// First detected mismatch, if any. Present iff
    /// `status == Mismatch`. We stop at the first mismatch
    /// because every subsequent row's prev_hash check would
    /// cascade from the same break — reporting them would just
    /// be noise.
    pub first_mismatch: Option<ChainMismatch>,
    /// True when the walk hit the `limit` cap and more rows
    /// remain past it. Paired with `next_after_chain_seq` so
    /// an operator can paginate forward. When `truncated`
    /// is true, status is `Incomplete` (never `Ok`) — a
    /// tamper past the cap could be hidden under `Ok`
    /// otherwise.
    pub truncated: bool,
    /// `chain_seq` of the last walked row when `truncated`
    /// is true; `None` otherwise. Pass back as the
    /// `after_chain_seq` query param on the next call to
    /// continue.
    pub next_after_chain_seq: Option<i64>,
    /// (`chain_seq`, `row_hash`) of the tenant's tail row at
    /// query time — the `MAX(chain_seq)` chain-bearing row,
    /// regardless of the request window. Operators record
    /// this externally between verifier runs; a regression
    /// on either field detects a tail-deletion attack the
    /// in-DB verifier can't otherwise see (see module
    /// docstring's KNOWN LIMITATIONS).
    pub chain_head: Option<ChainHead>,
}

/// (`chain_seq`, `row_hash`) of the tenant's
/// highest-chain_seq chain-bearing row at query time.
/// Independent of the request window.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ChainHead {
    pub chain_seq: i64,
    pub row_hash: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChainVerifyStatus {
    /// Every walked row passed both invariants AND the walk
    /// was not truncated by `limit`. This is the "the chain
    /// is intact in one call" verdict the endpoint promises.
    Ok,
    /// At least one row failed; details in `first_mismatch`.
    /// Takes precedence over `Incomplete` (a found tamper is
    /// always reported, even if the walk was capped after
    /// it).
    Mismatch,
    /// Window matched zero chain-bearing rows. Unchained audit rows may still
    /// exist in the same window, so this is not a full-audit completeness
    /// verdict.
    Empty,
    /// Every walked row passed both invariants, but the walk
    /// was truncated by `limit`. Paginate forward with
    /// `next_after_chain_seq` to continue. A tamper past
    /// the cap could otherwise
    /// hide under `Ok`.
    Incomplete,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ChainMismatch {
    pub row_id: Uuid,
    pub chain_seq: i64,
    pub kind: MismatchKind,
    /// Hex digest the verifier computed / was expected.
    pub expected: String,
    /// Hex digest the row actually carried.
    pub actual: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MismatchKind {
    /// `prev_hash` on the row didn't match the prior walked
    /// row's `row_hash` (or the supplied `prev_head` for the
    /// first row in the window). Indicates a deleted or
    /// inserted neighbour. A
    /// `BrokenLink` is reported only when no chain of
    /// admitted `RetentionSweep` markers BRIDGES the gap
    /// from the prior walked row's `row_hash` to the current
    /// row's `prev_hash` — markers attest `(prev_hash,
    /// row_hash)` segments and the walker stitches them via
    /// the bridge index. Gaps fully bridged by admitted
    /// markers are accepted as legitimate retention spans.
    BrokenLink,
    /// Recomputed `sha256(prev_hash || \x00 || canonical
    /// bytes)` didn't match the stored `row_hash`. Indicates
    /// an in-place column mutation on this row.
    BadRowHash,
}

/// Parsed payload of a `RetentionSweep` marker
/// row. The sweep writes a chain-bearing
/// audit_log row with `category = "retention_sweep"` and
/// `reason` set to the JSON serialization of this struct
/// immediately before it DELETEs the rows attested in `deleted_rows` and
/// `deleted_unchained_rows`. The verifier consumes the chained fingerprints when
/// walking the chain so a deletion gap doesn't trigger
/// `BrokenLink` for a legitimately-retained span.
///
/// Encoded as JSON in the `reason` TEXT column — reason is
/// the only free-form column in audit_log, so we don't need
/// a schema migration to carry the marker payload. The
/// `kind: "retention_sweep"` discriminator guards against
/// unrelated rows whose reason text happens to look
/// JSON-shaped.
///
/// Each entry in `deleted_rows`
/// carries the deleted row's `(prev_hash, row_hash)` so the
/// walker can verify a multi-row gap is a CONTIGUOUS chain
/// segment, not just a set of orphan hashes. Round-4's flat
/// `Vec<String>` let an under-reporting marker (claim only
/// the last deleted hash; omit the middle) authorise a gap
/// the verifier couldn't independently detect was incomplete.
/// With `(prev_hash, row_hash)` pairs, the walker stitches
/// from the prior surviving row's `row_hash` through the
/// marker's chain to the next surviving row's `prev_hash`;
/// if the chain doesn't reach the boundary, gap is rejected.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RetentionMarker {
    /// Discriminator. Always the literal `"retention_sweep"`.
    /// Verifier checks this before consuming `deleted_rows`
    /// so an attacker can't forge a marker by setting reason
    /// to a JSON shape that looks like a marker without the
    /// matching category.
    pub kind: String,
    /// Ordered chain-segment attestation of the deleted rows.
    /// Each entry carries the deleted row's `prev_hash` and
    /// `row_hash` exactly as they were stored before the
    /// DELETE. Walker uses these to BRIDGE gaps in the chain:
    /// the first entry's `prev_hash` links to the prior
    /// surviving row's `row_hash`; the last entry's `row_hash`
    /// links to the next surviving row's `prev_hash`; and each
    /// adjacent entry chains via `next.prev_hash == prior.row_hash`.
    ///
    /// Walker-side gap acceptance
    /// requires a complete bridge from the surviving boundary
    /// rows through marker entries. An under-reporting marker
    /// fails the boundary stitch and the gap surfaces as
    /// `BrokenLink`.
    pub deleted_rows: Vec<DeletedRow>,
    /// Unchained best-effort rows deleted in the same transaction. They create
    /// no hash-chain gap, but recording their identity makes the deletion visible
    /// and lets the SECURITY DEFINER function require marker coverage before
    /// it removes them.
    #[serde(default)]
    pub deleted_unchained_rows: Vec<DeletedUnchainedRow>,
    /// Optional context for human readers / external audit:
    /// inclusive `chain_seq` range of the deleted span.
    /// Not used by the verifier (the chain stitch in
    /// `deleted_rows` is authoritative); recorded so an
    /// investigator reading the marker sees what was removed
    /// without re-correlating against `chain_seq`.
    #[serde(default)]
    pub deleted_chain_seq_min: Option<i64>,
    #[serde(default)]
    pub deleted_chain_seq_max: Option<i64>,
    /// Optional human-readable policy identifier (e.g.
    /// "default/invocation @90d"). Audit-context only.
    #[serde(default)]
    pub policy: Option<String>,
}

/// One deleted row's chain
/// fingerprint, recorded by the sweep BEFORE the DELETE so
/// the verifier can reconstruct chain continuity across a
/// retention gap without seeing the deleted row itself. The
/// pair is what walker stitching needs: `prev_hash` links
/// backward to the prior chain row's `row_hash`, and
/// `row_hash` is what the next row's `prev_hash` points at.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct DeletedRow {
    /// The deleted row's stored `prev_hash`. `None` only when
    /// the deleted row was the tenant's chain genesis (no
    /// prior chain row existed). Walker uses this to anchor
    /// the marker's bridge to the prior surviving row.
    pub prev_hash: Option<String>,
    /// The deleted row's stored `row_hash`. Hex digest.
    /// Walker uses this both to chain to the next entry
    /// within the marker AND to satisfy the next surviving
    /// row's `prev_hash` requirement at the gap boundary.
    pub row_hash: String,
}

/// Identity snapshot for an unchained row removed by retention. `chain_seq`
/// prevents an old marker from covering a later row that deliberately reuses a
/// previously deleted UUID.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct DeletedUnchainedRow {
    pub id: Uuid,
    pub chain_seq: i64,
}

/// Recompute a row's expected `row_hash` from its durable
/// columns. The storage adapter
/// calls this per marker before admitting it to the bridge
/// graph — only markers whose recomputed hash matches the
/// stored value (invariant 2) get to authorise gaps. This
/// is the same computation the main walker does inline;
/// lifted to a public helper so the adapter can apply it
/// out-of-band to markers that sit outside the walked
/// slice. Rounds 6–7: marker payload format evolved from
/// a flat `deleted_row_hashes: Vec<String>` to
/// `deleted_rows: Vec<DeletedRow>` carrying
/// `(prev_hash, row_hash)` pairs for chain-stitched gap
/// bridging; the recompute helper is unchanged.
pub fn recompute_row_hash(row: &ChainVerifyRow) -> String {
    let bytes = canonical_audit_bytes_with_ext5(
        row.id,
        row.ts,
        &row.category,
        &row.tenant_id,
        &row.action,
        &row.outcome,
        row.principal_sub.as_deref(),
        row.principal_email.as_deref(),
        &row.principal_groups,
        row.issuer.as_deref(),
        row.server.as_deref(),
        row.tool.as_deref(),
        row.risk_level.as_deref(),
        row.pii,
        &row.policy_ids,
        row.reason.as_deref(),
        row.trace_id.as_deref(),
        row.latency_ms,
        // Include SCIM in chain coverage.
        // Legacy rows decode scim_active=None + scim_groups=[]
        // ⇒ extension contributes zero bytes ⇒ hash equals the
        // earlier value, so existing audit_log rows continue
        // to verify cleanly without a migration of stored hashes.
        row.scim_active,
        &row.scim_groups,
        // Migration 0046: include `target` in chain coverage. Legacy
        // rows decode target=None ⇒ extension contributes zero tail
        // bytes ⇒ hash equals the pre-0046 value, so existing
        // audit_log rows continue to verify cleanly.
        row.target.as_deref(),
        // Migration 0062: include the four decision
        // inputs in chain coverage. Legacy rows decode all-absent ⇒
        // extension contributes zero tail bytes ⇒ hash equals the
        // pre-0062 value; a post-0062 decision row carrying the inputs
        // is hashed WITH them at write time, so the verifier MUST thread
        // them here or it would report a spurious BadRowHash.
        &row.req_scopes,
        row.auth_method.as_deref(),
        &row.req_roles,
        row.side_effects,
        // Migration 0068: include acting_agent in chain coverage. Legacy rows
        // decode acting_agent=None ⇒ zero tail bytes ⇒ hash equals the pre-0068
        // value; a post-0068 row carrying it is hashed WITH it at write time, so
        // the verifier MUST thread it here or report a spurious BadRowHash.
        row.acting_agent.as_deref(),
        row.invocation_hierarchy.as_ref(),
        // Legacy rows decode operation=None, contributing zero tail bytes, so
        // their stored hashes still verify without a rewrite.
        row.operation.as_deref(),
    );
    compute_row_hash(row.prev_hash.as_deref(), &bytes)
}

impl RetentionMarker {
    /// Discriminator value used in `kind`. Verifier checks
    /// this before trusting any other field.
    pub const KIND: &'static str = "retention_sweep";

    /// Try to parse a marker from an audit row's `reason`
    /// text. Returns `Some` iff the text deserialises as a
    /// well-formed marker AND the `kind` discriminator
    /// matches AND the payload passes [`Self::validate`].
    /// Returns `None` on parse failure, discriminator
    /// mismatch, or self-inconsistent payload — the row was
    /// tagged `RetentionSweep` but its reason isn't a
    /// trustworthy marker; the verifier treats it as a
    /// non-marker chain row (still passes the prev_hash +
    /// row_hash checks for the marker row itself, but its
    /// claimed deletions don't authorise any gap).
    pub fn from_reason(reason: &str) -> Option<Self> {
        let parsed: RetentionMarker = serde_json::from_str(reason).ok()?;
        if parsed.kind != Self::KIND {
            return None;
        }
        if !parsed.validate() {
            return None;
        }
        Some(parsed)
    }

    /// Self-consistency check the
    /// adapter applies to every parsed marker before adding
    /// it to the walker's bridge index. Validates the
    /// properties walker stitching DEPENDS on but does not
    /// itself check (because it's payload-internal, not
    /// chain-relative):
    ///
    /// - At least one chained fingerprint or unchained id is present.
    /// - Adjacent entries chain via
    ///   `next.prev_hash == Some(prior.row_hash)`. Without
    ///   this property the marker would attest a
    ///   discontinuous "deletion span," which walker
    ///   stitching can't safely use to authorise a single
    ///   contiguous gap.
    /// - No duplicate `row_hash` entries within the marker.
    ///   The same row can't be "deleted twice" in one sweep
    ///   cycle; a duplicate is a malformed payload — drop.
    ///
    /// Returns `true` iff the marker is internally
    /// consistent. Returns `false` for malformed payloads;
    /// the caller (adapter or `from_reason`) discards.
    pub fn validate(&self) -> bool {
        if self.kind != Self::KIND {
            return false;
        }
        if self.deleted_rows.is_empty() && self.deleted_unchained_rows.is_empty() {
            return false;
        }
        // Internal chain: each entry's prev_hash links to the
        // prior entry's row_hash. The first entry's prev_hash
        // anchors at the gap boundary (walker checks against
        // the prior surviving row at bridge time, not here).
        for window in self.deleted_rows.windows(2) {
            let prior = &window[0];
            let next = &window[1];
            if next.prev_hash.as_deref() != Some(prior.row_hash.as_str()) {
                return false;
            }
        }
        // Reject duplicate row_hashes within the marker.
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for d in &self.deleted_rows {
            if !seen.insert(d.row_hash.as_str()) {
                return false;
            }
        }
        let mut seen_unchained = std::collections::HashSet::new();
        for row in &self.deleted_unchained_rows {
            if !seen_unchained.insert(row.id) {
                return false;
            }
        }
        true
    }

    /// Render the payload back to the canonical JSON text the
    /// sweep writes to the `reason` column. Stable encoding
    /// so the same input always produces the same row_hash.
    /// (The retention sweep calls this.)
    pub fn to_reason(&self) -> String {
        // Sorted keys + no indentation; deterministic across
        // serde_json versions for the chain-hash input.
        serde_json::to_string(self).expect("RetentionMarker serializes infallibly")
    }

    pub(crate) fn bridge(&self) -> Option<RetentionBridge> {
        Some(RetentionBridge {
            start: self.deleted_rows.first()?.prev_hash.clone(),
            end: self.deleted_rows.last()?.row_hash.clone(),
        })
    }
}

/// Compact form retained after a marker row's hash and payload have been
/// validated. Verification needs only the deleted segment's boundary hashes;
/// keeping the full row and JSON payload for permanent marker history would
/// make memory proportional to all deleted-row attestations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RetentionBridge {
    pub(crate) start: Option<String>,
    pub(crate) end: String,
}

/// One compact marker awaiting invariant-1 admission.
pub(crate) struct RetentionBridgeCandidate {
    pub(crate) bridge: RetentionBridge,
    pub(crate) expected_prev: Option<String>,
    pub(crate) marker_prev: Option<String>,
}

/// Return only the broken-link jobs a bounded row window needs retention
/// markers to resolve. The storage adapter uses these `(cursor, target)` pairs
/// as recursive-query seeds instead of loading unrelated permanent markers.
pub(crate) fn verification_gap_jobs(
    prev_head: Option<&str>,
    rows: &[ChainVerifyRow],
) -> Vec<(Option<String>, Option<String>)> {
    let mut expected_prev = prev_head.map(str::to_owned);
    let mut jobs = Vec::new();
    for row in rows {
        if row.prev_hash != expected_prev {
            jobs.push((expected_prev.clone(), row.prev_hash.clone()));
        }
        expected_prev = Some(row.row_hash.clone());
    }
    jobs.sort_unstable();
    jobs.dedup();
    jobs
}

/// Compute the least fixed point of valid marker bridges without repeatedly
/// rebuilding the bridge index. Each candidate is traced through the complete
/// functional graph once to identify its dependencies; a queue then admits a
/// candidate only after every bridge it depends on has itself been admitted.
/// Cycles without an independently valid bridge remain unadmitted. Duplicate
/// starts are excluded because they make the bridge graph ambiguous.
pub(crate) fn admit_retention_bridges(
    candidates: &[RetentionBridgeCandidate],
) -> Vec<RetentionBridge> {
    let mut duplicate_start = vec![false; candidates.len()];
    let mut bridge_index: std::collections::HashMap<Option<&str>, usize> =
        std::collections::HashMap::with_capacity(candidates.len());
    for (index, candidate) in candidates.iter().enumerate() {
        if let Some(previous) = bridge_index.insert(candidate.bridge.start.as_deref(), index) {
            duplicate_start[previous] = true;
            duplicate_start[index] = true;
        }
    }
    for (index, candidate) in candidates.iter().enumerate() {
        if duplicate_start[index] {
            bridge_index.remove(&candidate.bridge.start.as_deref());
        }
    }

    let mut remaining = vec![usize::MAX; candidates.len()];
    let mut dependents = vec![Vec::new(); candidates.len()];
    for (index, candidate) in candidates.iter().enumerate() {
        if duplicate_start[index] {
            continue;
        }
        let mut cursor = candidate.expected_prev.as_deref();
        if cursor == candidate.marker_prev.as_deref() {
            remaining[index] = 0;
            continue;
        }

        let mut dependencies = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut reached = false;
        for _ in 0..bridge_index.len() {
            let Some(&next) = bridge_index.get(&cursor) else {
                break;
            };
            if !seen.insert(next) {
                break;
            }
            if next != index {
                dependencies.push(next);
            }
            cursor = Some(candidates[next].bridge.end.as_str());
            if cursor == candidate.marker_prev.as_deref() {
                reached = true;
                break;
            }
        }
        if !reached {
            continue;
        }
        remaining[index] = dependencies.len();
        for dependency in dependencies {
            dependents[dependency].push(index);
        }
    }

    let mut queue: std::collections::VecDeque<usize> = remaining
        .iter()
        .enumerate()
        .filter_map(|(index, count)| (*count == 0).then_some(index))
        .collect();
    let mut admitted = vec![false; candidates.len()];
    while let Some(index) = queue.pop_front() {
        if admitted[index] {
            continue;
        }
        admitted[index] = true;
        for &dependent in &dependents[index] {
            remaining[dependent] -= 1;
            if remaining[dependent] == 0 {
                queue.push_back(dependent);
            }
        }
    }

    candidates
        .iter()
        .zip(admitted)
        .filter(|(_, admitted)| *admitted)
        .map(|(candidate, _)| candidate.bridge.clone())
        .collect()
}

/// Follow a finite marker bridge graph from `start` to `target`.
///
/// A bridge index has at most one outgoing edge per start hash. A legitimate
/// path therefore reaches its target within the number of available edges;
/// needing another hop proves the path is cyclic or repeats an overwritten
/// start. `fallback` is the admission candidate's provisional self-bootstrap
/// edge and is absent during the final chain walk.
pub(crate) fn marker_bridge_reaches(
    start: Option<&str>,
    target: Option<&str>,
    bridge_index: &std::collections::HashMap<Option<&str>, &RetentionBridge>,
    fallback: Option<&RetentionBridge>,
) -> bool {
    let mut cursor = start.map(str::to_owned);
    let max_hops = bridge_index.len() + usize::from(fallback.is_some());
    if cursor.as_deref() == target {
        return true;
    }
    for _ in 0..max_hops {
        let next = bridge_index
            .get(&cursor.as_deref())
            .copied()
            .or_else(|| fallback.filter(|bridge| bridge.start.as_deref() == cursor.as_deref()));
        let Some(bridge) = next else {
            return false;
        };
        cursor = Some(bridge.end.clone());
        if cursor.as_deref() == target {
            return true;
        }
    }
    false
}

/// Pure verifier — given the row immediately before the window
/// (if any) and the rows IN the window in `chain_seq ASC`
/// order, walk and check both invariants. Retention gaps are
/// bridged using `markers` (the adapter pre-validates each
/// marker; this walker trusts the supplied set).
///
/// `prev_head` is the stored `row_hash` of the row at
/// `chain_seq = (first walked row).chain_seq - 1` for the same
/// tenant. `None` means either "this window starts at the
/// tenant's genesis row" (whose `prev_hash` is NULL) or "no
/// row precedes the window in the durable table." The Postgres
/// adapter is responsible for distinguishing those cases
/// before calling — if the window starts mid-chain and the
/// prior row exists, the adapter MUST pass its `row_hash`
/// here. Calling with `None` against a window whose first row
/// has a non-NULL `prev_hash` will (correctly) report a
/// `BrokenLink` mismatch on row 1 unless a marker bridges the
/// genesis-to-first-walked gap.
///
/// `markers` is the full-tenant set of [`RetentionMarker`]
/// payloads the adapter has already filtered by invariants
/// 1 + 2 + self-consistency (see [`RetentionMarker::validate`]
/// and `PgAuditSink::verify_chain`). The walker indexes them
/// by `deleted_rows[0].prev_hash` and stitches gaps by
/// following the chain hash-by-hash to the next surviving
/// row's `prev_hash`.
pub fn verify_chain_rows(
    tenant_id: &str,
    from: Option<OffsetDateTime>,
    to: Option<OffsetDateTime>,
    prev_head: Option<&str>,
    rows: &[ChainVerifyRow],
    markers: &[RetentionMarker],
) -> ChainVerifyReport {
    let bridges: Vec<RetentionBridge> =
        markers.iter().filter_map(RetentionMarker::bridge).collect();
    verify_chain_rows_with_bridges(tenant_id, from, to, prev_head, rows, &bridges)
}

pub(crate) fn verify_chain_rows_with_bridges(
    tenant_id: &str,
    from: Option<OffsetDateTime>,
    to: Option<OffsetDateTime>,
    prev_head: Option<&str>,
    rows: &[ChainVerifyRow],
    bridges: &[RetentionBridge],
) -> ChainVerifyReport {
    // Construct the skeleton once with the storage-adapter
    // fields (truncated / next_after_chain_seq / chain_head)
    // defaulted — the adapter overwrites them after the
    // walk. The walker itself only owns rows_walked /
    // status / first_mismatch.
    let mut report = ChainVerifyReport {
        tenant_id: tenant_id.to_owned(),
        from,
        to,
        rows_walked: 0,
        status: ChainVerifyStatus::Empty,
        first_mismatch: None,
        truncated: false,
        next_after_chain_seq: None,
        chain_head: None,
    };

    if rows.is_empty() {
        return report;
    }

    // Bridge index. A marker's
    // `deleted_rows[0].prev_hash` is the anchor it claims to
    // chain from — that's where the bridge starts. The
    // walker, upon a `prev_hash` mismatch, looks up by the
    // CURRENT expected_prev (the prior surviving row's
    // row_hash) and follows the marker's chain to its end.
    // If the chain ends at the current row's `prev_hash`,
    // gap is bridged. Else: traverse to the next marker
    // whose start equals the previous marker's end (multi-
    // cycle stitching) and continue. Traversal is bounded by the finite
    // bridge graph so adversarial cycles terminate without imposing a fixed
    // maximum on legitimate retention history.
    //
    // The storage adapter rejects duplicate starts while admitting marker
    // bridges because they make the graph ambiguous. Callers of this pure
    // helper are responsible for supplying the same unambiguous set.
    let bridge_index: std::collections::HashMap<Option<&str>, &RetentionBridge> = bridges
        .iter()
        .map(|bridge| (bridge.start.as_deref(), bridge))
        .collect();

    // Threaded between iterations: the `row_hash` of the row
    // we just verified, used as the next row's expected
    // `prev_hash`. Seeded from `prev_head` for the very first
    // row.
    let mut expected_prev: Option<String> = prev_head.map(|s| s.to_owned());

    for row in rows {
        // Invariant 1: prev_hash links to the prior row's
        // row_hash (or to prev_head / NULL for the first row).
        //
        // A mismatch is accepted iff a
        // chain of markers BRIDGES `expected_prev` to
        // `row.prev_hash`. The bridge is built iteratively:
        // start from expected_prev, look up a marker keyed
        // by it, jump to the marker's `deleted_rows[last]
        // .row_hash`, repeat until match or no marker. Every jump consumes an
        // edge from the finite bridge graph. A path
        // longer than that graph is cyclic and is rejected.
        //
        // After accepting, `expected_prev` is overwritten by
        // `row.row_hash` at the end-of-iter line below; no
        // explicit reset to `row.prev_hash` needed.
        if row.prev_hash.as_deref() != expected_prev.as_deref() {
            let bridged = marker_bridge_reaches(
                expected_prev.as_deref(),
                row.prev_hash.as_deref(),
                &bridge_index,
                None,
            );
            if !bridged {
                report.status = ChainVerifyStatus::Mismatch;
                report.first_mismatch = Some(ChainMismatch {
                    row_id: row.id,
                    chain_seq: row.chain_seq,
                    kind: MismatchKind::BrokenLink,
                    expected: expected_prev.unwrap_or_default(),
                    actual: row.prev_hash.clone().unwrap_or_default(),
                });
                return report;
            }
        }

        // Invariant 2: recomputed sha256(prev || \x00 ||
        // canonical_bytes) matches the stored row_hash. MUST use the
        // SAME canonical function as the producer (`record_required` →
        // `canonical_audit_bytes_with_ext2`) and as `recompute_row_hash`,
        // threading the row's SCIM + `target` + decision-input columns. A
        // row with `scim`/`target`/decision-inputs present is hashed WITH
        // those bytes at write time, so recomputing here without them would
        // report a spurious `BadRowHash` for a legitimately-written row
        // (the `target` column; migration 0062 extends the same
        // contract to the four decision inputs). For legacy rows (scim,
        // target, and all four decision inputs absent) every extension
        // contributes zero bytes, so this is byte-identical to the prior
        // `canonical_audit_bytes` call — no regression for existing chains.
        let bytes = canonical_audit_bytes_with_ext5(
            row.id,
            row.ts,
            &row.category,
            &row.tenant_id,
            &row.action,
            &row.outcome,
            row.principal_sub.as_deref(),
            row.principal_email.as_deref(),
            &row.principal_groups,
            row.issuer.as_deref(),
            row.server.as_deref(),
            row.tool.as_deref(),
            row.risk_level.as_deref(),
            row.pii,
            &row.policy_ids,
            row.reason.as_deref(),
            row.trace_id.as_deref(),
            row.latency_ms,
            row.scim_active,
            &row.scim_groups,
            row.target.as_deref(),
            &row.req_scopes,
            row.auth_method.as_deref(),
            &row.req_roles,
            row.side_effects,
            // Migration 0068: include acting_agent in chain coverage (see
            // recompute_row_hash for the zero-bytes-when-absent rationale).
            row.acting_agent.as_deref(),
            row.invocation_hierarchy.as_ref(),
            row.operation.as_deref(),
        );
        let expected_hash = compute_row_hash(row.prev_hash.as_deref(), &bytes);
        if expected_hash != row.row_hash {
            report.status = ChainVerifyStatus::Mismatch;
            report.first_mismatch = Some(ChainMismatch {
                row_id: row.id,
                chain_seq: row.chain_seq,
                kind: MismatchKind::BadRowHash,
                expected: expected_hash,
                actual: row.row_hash.clone(),
            });
            return report;
        }

        // Increment per-row
        // AFTER both invariants pass. On a mismatch return,
        // `rows_walked` then correctly reflects how many
        // rows passed cleanly *before* the failing row —
        // operator sees "rows_walked=N, mismatch at
        // chain_seq=N+1" which is the truthful walk count.
        // A previous implementation only assigned
        // `rows.len()` at the end, so mismatch reports
        // claimed `rows_walked=0` regardless of how far
        // the walker actually got.
        report.rows_walked += 1;
        expected_prev = Some(row.row_hash.clone());
    }

    report.status = ChainVerifyStatus::Ok;
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    // `canonical_audit_bytes` is the legacy (no-extension) helper, used
    // only by these tests to build pre-0046/pre-SCIM/pre-0062 fixture rows.
    // The production verifier above hashes via `canonical_audit_bytes_with_ext2`
    // (threading SCIM + target + the four decision inputs), so the
    // top-level `use` no longer needs the legacy helper.
    use crate::hashchain::canonical_audit_bytes;
    // Some verifier tests build expected bytes via ext2 (SCIM + target + the
    // four decision inputs, no acting_agent); production now hashes via ext3.
    // ext3 with acting_agent=None is byte-identical to ext2, so these fixtures
    // stay valid against the production walker.
    use crate::hashchain::canonical_audit_bytes_with_ext2;

    /// Helper for tests that don't simulate retention sweeps.
    /// The walker accepts a slice of validated markers; non-
    /// retention tests pass an empty slice to keep the
    /// gap-bridging behaviour off.
    const NO_MARKERS: &[RetentionMarker] = &[];

    fn row(chain_seq: i64, prev_hash: Option<&str>) -> ChainVerifyRow {
        // Build a row whose row_hash is the correctly-computed
        // hash for itself. Used as the seed for the
        // "well-formed chain" tests.
        let id = Uuid::from_u128(chain_seq as u128);
        let ts = OffsetDateTime::from_unix_timestamp(1_700_000_000 + chain_seq).unwrap();
        let category = "invocation".to_owned();
        let tenant_id = "default".to_owned();
        let action = "CallTool".to_owned();
        let outcome = "success".to_owned();
        let bytes = canonical_audit_bytes(
            id,
            ts,
            &category,
            &tenant_id,
            &action,
            &outcome,
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
        );
        let row_hash = compute_row_hash(prev_hash, &bytes);
        ChainVerifyRow {
            operation: None,
            id,
            chain_seq,
            ts,
            category,
            tenant_id,
            action,
            outcome,
            principal_sub: None,
            principal_email: None,
            principal_groups: vec![],
            issuer: None,
            server: None,
            tool: None,
            risk_level: None,
            pii: None,
            policy_ids: vec![],
            reason: None,
            trace_id: None,
            latency_ms: None,
            prev_hash: prev_hash.map(|s| s.to_owned()),
            row_hash,
            scim_active: None,
            scim_groups: Vec::new(),
            target: None,
            req_scopes: Vec::new(),
            auth_method: None,
            req_roles: Vec::new(),
            side_effects: None,
            acting_agent: None,
            invocation_hierarchy: None,
        }
    }

    /// Two correctly-chained rows starting from the tenant's
    /// genesis (prev_hash = NULL on row 1).
    fn well_formed_chain() -> Vec<ChainVerifyRow> {
        let r1 = row(1, None);
        let r2 = row(2, Some(r1.row_hash.as_str()));
        vec![r1, r2]
    }

    fn bridge_candidate(
        start: Option<&str>,
        end: &str,
        expected_prev: Option<&str>,
        marker_prev: Option<&str>,
    ) -> RetentionBridgeCandidate {
        RetentionBridgeCandidate {
            bridge: RetentionBridge {
                start: start.map(str::to_owned),
                end: end.to_owned(),
            },
            expected_prev: expected_prev.map(str::to_owned),
            marker_prev: marker_prev.map(str::to_owned),
        }
    }

    #[test]
    fn marker_lookup_is_seeded_only_by_broken_links() {
        let r1 = row(1, None);
        let r2 = row(2, Some(r1.row_hash.as_str()));
        let r3 = row(3, Some(r2.row_hash.as_str()));

        assert!(verification_gap_jobs(None, &[r1.clone(), r2.clone()]).is_empty());
        assert_eq!(
            verification_gap_jobs(None, &[r1.clone(), r3]),
            vec![(Some(r1.row_hash), Some(r2.row_hash))],
            "a retained gap contributes one recursive bridge job",
        );
    }

    #[test]
    fn marker_admission_accepts_self_bootstrap() {
        let candidates = [bridge_candidate(Some("a"), "b", Some("a"), Some("b"))];

        assert_eq!(
            admit_retention_bridges(&candidates),
            vec![RetentionBridge {
                start: Some("a".to_owned()),
                end: "b".to_owned(),
            }]
        );
    }

    #[test]
    fn marker_admission_waits_for_later_dependency() {
        let candidates = [
            bridge_candidate(Some("x"), "y", Some("a"), Some("y")),
            bridge_candidate(Some("a"), "x", Some("a"), Some("x")),
        ];

        assert_eq!(admit_retention_bridges(&candidates).len(), 2);
    }

    #[test]
    fn marker_admission_rejects_ungrounded_cycle() {
        let candidates = [
            bridge_candidate(Some("a"), "b", Some("c"), Some("b")),
            bridge_candidate(Some("c"), "a", Some("a"), Some("b")),
        ];

        assert!(admit_retention_bridges(&candidates).is_empty());
    }

    #[test]
    fn marker_admission_rejects_ambiguous_duplicate_starts() {
        let candidates = [
            bridge_candidate(Some("a"), "b", Some("a"), Some("b")),
            bridge_candidate(Some("a"), "c", Some("a"), Some("c")),
        ];

        assert!(admit_retention_bridges(&candidates).is_empty());
    }

    /// Like [`row`] but carries a `target` and computes its `row_hash`
    /// the way the PRODUCER (`record_required`) does — via
    /// `canonical_audit_bytes_with_ext2` INCLUDING the target bytes (and the
    /// four decision inputs left absent, matching a target-bearing
    /// lifecycle row that carries no decision inputs).
    fn row_with_target(chain_seq: i64, prev_hash: Option<&str>, target: &str) -> ChainVerifyRow {
        let id = Uuid::from_u128(chain_seq as u128);
        let ts = OffsetDateTime::from_unix_timestamp(1_700_000_000 + chain_seq).unwrap();
        let category = "api_key_lifecycle".to_owned();
        let tenant_id = "default".to_owned();
        let action = "ApiKeyMinted".to_owned();
        let outcome = "success".to_owned();
        let bytes = canonical_audit_bytes_with_ext2(
            id,
            ts,
            &category,
            &tenant_id,
            &action,
            &outcome,
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
            None,
            &[],
            Some(target),
            &[],
            None,
            &[],
            None,
        );
        let row_hash = compute_row_hash(prev_hash, &bytes);
        ChainVerifyRow {
            operation: None,
            id,
            chain_seq,
            ts,
            category,
            tenant_id,
            action,
            outcome,
            principal_sub: None,
            principal_email: None,
            principal_groups: vec![],
            issuer: None,
            server: None,
            tool: None,
            risk_level: None,
            pii: None,
            policy_ids: vec![],
            reason: None,
            trace_id: None,
            latency_ms: None,
            prev_hash: prev_hash.map(|s| s.to_owned()),
            row_hash,
            scim_active: None,
            scim_groups: Vec::new(),
            target: Some(target.to_owned()),
            req_scopes: Vec::new(),
            auth_method: None,
            req_roles: Vec::new(),
            side_effects: None,
            acting_agent: None,
            invocation_hierarchy: None,
        }
    }

    /// Violated security/integrity contract: the
    /// producer hashes a chain row's bytes WITH its `target` column, so
    /// the verifier's Invariant-2 recompute MUST include `target` too. A
    /// genesis row carrying a target must verify as `Ok`, not
    /// `BadRowHash`. Before the fix, `verify_chain_rows` recomputed with
    /// the legacy no-target helper and flagged every legitimate
    /// target-bearing chain row as a tamper.
    #[test]
    fn target_bearing_chain_row_verifies_ok() {
        let rows = vec![row_with_target(1, None, "svc:example-triage")];
        let report = verify_chain_rows("default", None, None, None, &rows, NO_MARKERS);
        assert_eq!(
            report.status,
            ChainVerifyStatus::Ok,
            "a target-bearing row hashed by the producer must verify Ok; a \
             BadRowHash here means the verifier recompute dropped `target`",
        );
        assert!(report.first_mismatch.is_none());
    }

    #[test]
    fn empty_window_reports_empty() {
        let report = verify_chain_rows("default", None, None, None, &[], NO_MARKERS);
        assert_eq!(report.status, ChainVerifyStatus::Empty);
        assert_eq!(report.rows_walked, 0);
        assert!(report.first_mismatch.is_none());
        assert!(!report.truncated);
        assert!(report.next_after_chain_seq.is_none());
        assert!(report.chain_head.is_none());
    }

    /// Truncation is a storage-adapter concern. The walker
    /// itself always returns `truncated: false` (and the
    /// adapter overwrites it after the walk). This test
    /// pins that contract: a fully-passing walk produces
    /// `Ok` with `truncated == false`, leaving the adapter
    /// free to set `Incomplete` based on whether the cap
    /// was hit.
    #[test]
    fn walker_does_not_set_truncated_or_chain_head() {
        let rows = well_formed_chain();
        let report = verify_chain_rows("default", None, None, None, &rows, NO_MARKERS);
        assert_eq!(report.status, ChainVerifyStatus::Ok);
        assert!(
            !report.truncated,
            "walker is truncation-agnostic; adapter owns the flag",
        );
        assert!(report.next_after_chain_seq.is_none());
        assert!(report.chain_head.is_none());
    }

    // Simulate the storage
    // adapter's two-page paginated walk on a 3-row chain
    // with limit=1. The adapter's `chain_seq > $cursor`
    // predicate ensures page 2 sees [r2] (not [r1, r2]),
    // and page 3 sees [r3]. The walker, given each slice
    // plus the prior row's row_hash as prev_head, must
    // verify each page Ok. This pins the contract the
    // adapter relies on: the walker's first-row check is
    // prev_hash == prev_head, so as long as the adapter
    // correctly hands the prior row_hash (via the
    // `SELECT row_hash WHERE chain_seq < first.chain_seq`
    // lookup), pagination is correct end-to-end. The
    // negative pin below also catches a future regression
    // to a `>=` cursor: with prev_head=r1.row_hash and a
    // slice that starts at r1, the walker's first-row
    // check fails (r1.prev_hash=None != Some(r1.row_hash))
    // and reports BrokenLink, which the assertion catches.
    #[test]
    fn paginated_walk_with_strict_after_cursor_advances() {
        let r1 = row(1, None);
        let r2 = row(2, Some(r1.row_hash.as_str()));
        let r3 = row(3, Some(r2.row_hash.as_str()));

        // Page 1: window starts at genesis, walks [r1].
        let p1 = verify_chain_rows(
            "default",
            None,
            None,
            None,
            std::slice::from_ref(&r1),
            NO_MARKERS,
        );
        assert_eq!(p1.status, ChainVerifyStatus::Ok);

        // Page 2: cursor was r1.chain_seq. Adapter's
        // `chain_seq > 1` selects [r2]; adapter's
        // `prev_head` lookup returns r1.row_hash.
        let p2 = verify_chain_rows(
            "default",
            None,
            None,
            Some(r1.row_hash.as_str()),
            std::slice::from_ref(&r2),
            NO_MARKERS,
        );
        assert_eq!(
            p2.status,
            ChainVerifyStatus::Ok,
            "page 2 must verify with the prior row's row_hash as prev_head; the strict-after cursor guarantees the slice starts AFTER the previously walked row",
        );

        // Page 3: cursor was r2.chain_seq. Adapter selects
        // [r3]; prev_head = r2.row_hash.
        let p3 = verify_chain_rows(
            "default",
            None,
            None,
            Some(r2.row_hash.as_str()),
            std::slice::from_ref(&r3),
            NO_MARKERS,
        );
        assert_eq!(p3.status, ChainVerifyStatus::Ok);

        // Negative pin for the round-2 bug: if the adapter
        // used `>= cursor` instead of `>`, page 2 would
        // re-include r1 (slice = [r1, r2]) AND prev_head
        // would still be r1.row_hash. The walker's first
        // row check would compare r1.prev_hash (None)
        // against prev_head (Some(r1.row_hash)) → BrokenLink.
        let p2_buggy_reselect = verify_chain_rows(
            "default",
            None,
            None,
            Some(r1.row_hash.as_str()),
            &[r1.clone(), r2.clone()],
            NO_MARKERS,
        );
        assert_eq!(
            p2_buggy_reselect.status,
            ChainVerifyStatus::Mismatch,
            "the round-2 cursor bug (reselecting the previously walked row) would be detected here as a BrokenLink — keeping this negative pin so a future regression to `>=` fails this test loudly",
        );
        assert_eq!(
            p2_buggy_reselect
                .first_mismatch
                .expect("mismatch reported")
                .kind,
            MismatchKind::BrokenLink,
        );
    }

    #[test]
    fn well_formed_chain_verifies_ok() {
        let rows = well_formed_chain();
        let report = verify_chain_rows("default", None, None, None, &rows, NO_MARKERS);
        assert_eq!(report.status, ChainVerifyStatus::Ok);
        assert_eq!(report.rows_walked, 2);
        assert!(report.first_mismatch.is_none());
    }

    /// Mid-chain window: rows 2..=3 with `prev_head` supplied
    /// from row 1's row_hash. Mirrors the production adapter
    /// path when the operator narrows by ts and the window
    /// doesn't start at genesis.
    #[test]
    fn mid_chain_window_with_prev_head_verifies_ok() {
        let r1 = row(1, None);
        let r2 = row(2, Some(r1.row_hash.as_str()));
        let r3 = row(3, Some(r2.row_hash.as_str()));
        let window = vec![r2.clone(), r3];
        let report = verify_chain_rows(
            "default",
            None,
            None,
            Some(r1.row_hash.as_str()),
            &window,
            NO_MARKERS,
        );
        assert_eq!(report.status, ChainVerifyStatus::Ok);
        assert_eq!(report.rows_walked, 2);
    }

    /// Mid-chain window WITHOUT the supplied prev_head — the
    /// first row's non-NULL prev_hash trips a BrokenLink
    /// mismatch on row 1 (not row 2). This is the contract
    /// the adapter relies on: forgetting to pass prev_head is
    /// a verifier-detectable error, not a silent pass.
    #[test]
    fn mid_chain_window_without_prev_head_reports_broken_link() {
        let r1 = row(1, None);
        let r2 = row(2, Some(r1.row_hash.as_str()));
        let report = verify_chain_rows(
            "default",
            None,
            None,
            None,
            std::slice::from_ref(&r2),
            NO_MARKERS,
        );
        assert_eq!(report.status, ChainVerifyStatus::Mismatch);
        let m = report.first_mismatch.expect("mismatch reported");
        assert_eq!(m.kind, MismatchKind::BrokenLink);
        assert_eq!(m.chain_seq, 2);
        assert_eq!(m.expected, "");
        assert_eq!(m.actual, r1.row_hash);
    }

    /// In-place column mutation: tamper with `outcome` after
    /// the row is built. The stored row_hash now disagrees
    /// with the recomputed digest → BadRowHash on that row.
    #[test]
    fn column_mutation_reports_bad_row_hash() {
        let r1 = row(1, None);
        let r2_original = row(2, Some(r1.row_hash.as_str()));
        let mut r2_tampered = r2_original.clone();
        // Flip outcome — row_hash and prev_hash are NOT updated,
        // mimicking what an operator running raw SQL
        // (`UPDATE audit_log SET outcome='denied' WHERE id=...`)
        // would produce.
        r2_tampered.outcome = "denied".to_owned();
        let report = verify_chain_rows(
            "default",
            None,
            None,
            None,
            &[r1, r2_tampered.clone()],
            NO_MARKERS,
        );
        assert_eq!(report.status, ChainVerifyStatus::Mismatch);
        let m = report.first_mismatch.clone().expect("mismatch reported");
        assert_eq!(m.kind, MismatchKind::BadRowHash);
        assert_eq!(m.chain_seq, 2);
        assert_eq!(m.actual, r2_tampered.row_hash);
        // Recomputed bytes for the tampered row will produce a
        // different digest — the report's `expected` is that
        // recomputed value.
        assert_ne!(m.expected, m.actual);
        // rows_walked must
        // reflect the count of rows that PASSED before the
        // mismatch fired — here, r1 passed cleanly, then
        // r2 tripped BadRowHash. So rows_walked == 1, not
        // 0 (the prior bug) and not 2 (the mismatching row
        // didn't fully verify).
        assert_eq!(
            report.rows_walked, 1,
            "rows_walked must count rows that passed before the mismatch, not 0",
        );
    }

    /// Row deleted from the middle of a chain: the next row's
    /// prev_hash now points at a row_hash that's no longer the
    /// prior walked row's row_hash. The walker reports
    /// BrokenLink at that next row.
    #[test]
    fn deleted_middle_row_reports_broken_link() {
        let r1 = row(1, None);
        let r2 = row(2, Some(r1.row_hash.as_str()));
        let r3 = row(3, Some(r2.row_hash.as_str()));
        // Skip r2 — simulate deletion.
        let walked = vec![r1.clone(), r3.clone()];
        let report = verify_chain_rows("default", None, None, None, &walked, NO_MARKERS);
        assert_eq!(report.status, ChainVerifyStatus::Mismatch);
        let m = report.first_mismatch.expect("mismatch reported");
        assert_eq!(m.kind, MismatchKind::BrokenLink);
        assert_eq!(m.chain_seq, 3);
        assert_eq!(m.expected, r1.row_hash);
        assert_eq!(m.actual, r2.row_hash);
    }

    /// Inserted row in the middle: a forged row gets dropped
    /// between r1 and r2 with a fabricated prev_hash matching
    /// r1.row_hash. Its own row_hash field can't both satisfy
    /// its recomputed digest AND match the next row's
    /// prev_hash unless the attacker also has the right
    /// canonical bytes — and recomputing the digest will
    /// detect the mismatch. We construct a forged row that
    /// claims a row_hash it doesn't actually compute to → the
    /// walker reports BadRowHash on the forged row.
    #[test]
    fn forged_inserted_row_reports_bad_row_hash() {
        let r1 = row(1, None);
        let mut forged = row(99, Some(r1.row_hash.as_str()));
        // Overwrite row_hash with a value the recomputed
        // digest won't match — what an attacker fabricates.
        forged.row_hash =
            "0000000000000000000000000000000000000000000000000000000000000000".to_owned();
        let report = verify_chain_rows(
            "default",
            None,
            None,
            None,
            &[r1, forged.clone()],
            NO_MARKERS,
        );
        assert_eq!(report.status, ChainVerifyStatus::Mismatch);
        let m = report.first_mismatch.expect("mismatch reported");
        assert_eq!(m.kind, MismatchKind::BadRowHash);
        assert_eq!(m.chain_seq, 99);
        assert_eq!(m.actual, forged.row_hash);
    }

    // --- Retention-marker tests ----------------------

    /// Build a chain-bearing `RetentionSweep` marker row whose
    /// `reason` carries the JSON-serialised `RetentionMarker`
    /// payload attesting `deleted_rows`. The marker's own
    /// `row_hash` is correctly computed from its (prev_hash,
    /// canonical_bytes) so it walks cleanly. Used by the
    /// retention-gap tests.
    ///
    /// `deleted_rows` must form a
    /// contiguous chain — first entry anchored at whatever
    /// hash the test wants to bridge from; each subsequent
    /// entry's prev_hash matches the prior entry's row_hash.
    /// Tests construct these explicitly so the boundary
    /// stitch and per-step linkage are visible at the call
    /// site.
    fn marker_row(
        chain_seq: i64,
        prev_hash: Option<&str>,
        deleted_rows: Vec<DeletedRow>,
    ) -> ChainVerifyRow {
        let payload = RetentionMarker {
            kind: RetentionMarker::KIND.to_owned(),
            deleted_rows: deleted_rows.clone(),
            deleted_unchained_rows: Vec::new(),
            deleted_chain_seq_min: deleted_rows.first().map(|_| 1),
            deleted_chain_seq_max: deleted_rows.last().map(|_| chain_seq - 1),
            policy: Some("test".to_owned()),
        };
        let reason_text = payload.to_reason();
        let id = Uuid::from_u128(chain_seq as u128);
        let ts = OffsetDateTime::from_unix_timestamp(1_700_000_000 + chain_seq).unwrap();
        let category = "retention_sweep".to_owned();
        let tenant_id = "default".to_owned();
        let action = "RetentionSweep".to_owned();
        let outcome = "success".to_owned();
        let bytes = canonical_audit_bytes(
            id,
            ts,
            &category,
            &tenant_id,
            &action,
            &outcome,
            None,
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
            &[],
            Some(reason_text.as_str()),
            None,
            None,
        );
        let row_hash = compute_row_hash(prev_hash, &bytes);
        ChainVerifyRow {
            operation: None,
            id,
            chain_seq,
            ts,
            category,
            tenant_id,
            action,
            outcome,
            principal_sub: None,
            principal_email: None,
            principal_groups: vec![],
            issuer: None,
            server: None,
            tool: None,
            risk_level: None,
            pii: None,
            policy_ids: vec![],
            reason: Some(reason_text),
            trace_id: None,
            latency_ms: None,
            prev_hash: prev_hash.map(|s| s.to_owned()),
            row_hash,
            scim_active: None,
            scim_groups: Vec::new(),
            target: None,
            req_scopes: Vec::new(),
            auth_method: None,
            req_roles: Vec::new(),
            side_effects: None,
            acting_agent: None,
            invocation_hierarchy: None,
        }
    }

    /// Convenience to build a marker payload from a literal
    /// list of `(prev_hash, row_hash)` pairs.
    fn marker_payload(rows: &[(Option<&str>, &str)]) -> RetentionMarker {
        RetentionMarker {
            kind: RetentionMarker::KIND.to_owned(),
            deleted_rows: rows
                .iter()
                .map(|(p, h)| DeletedRow {
                    prev_hash: p.map(|s| s.to_owned()),
                    row_hash: (*h).to_owned(),
                })
                .collect(),
            deleted_unchained_rows: Vec::new(),
            deleted_chain_seq_min: None,
            deleted_chain_seq_max: None,
            policy: Some("test".to_owned()),
        }
    }

    /// Round-trip serde for the marker payload — sanity that
    /// `from_reason(to_reason(x))` returns x and that the
    /// discriminator guard + self-consistency rejects
    /// unrelated or malformed JSON.
    #[test]
    fn retention_marker_serde_round_trip() {
        // Well-formed chain: r1.row_hash → r2.row_hash.
        let m = marker_payload(&[(Some("r0_hash"), "r1_hash"), (Some("r1_hash"), "r2_hash")]);
        let text = m.to_reason();
        let parsed = RetentionMarker::from_reason(&text).expect("round-trips");
        assert_eq!(parsed.deleted_rows.len(), 2);
        assert_eq!(parsed.deleted_rows[0].row_hash, "r1_hash");
        assert_eq!(parsed.deleted_rows[1].prev_hash.as_deref(), Some("r1_hash"));
        assert_eq!(parsed.kind, RetentionMarker::KIND);

        // Wrong discriminator: refuses.
        let bad = r#"{"kind":"not_a_marker","deleted_rows":[]}"#;
        assert!(RetentionMarker::from_reason(bad).is_none());

        // Garbage: refuses.
        assert!(RetentionMarker::from_reason("not json at all").is_none());

        // A parseable
        // marker that fails `validate()` (here: broken
        // internal chain) is also rejected by `from_reason`,
        // so the adapter never indexes it.
        let broken_chain = marker_payload(&[
            (Some("a"), "b"),
            (Some("c"), "d"), // c != b → broken
        ]);
        assert!(RetentionMarker::from_reason(&broken_chain.to_reason()).is_none());
    }

    /// Sweep cycle simulation: chain was r1, r2, r3, r4; sweep
    /// deletes r2 and r3 and writes a marker; surviving rows
    /// in the walk are r1, r4 (which kept its old prev_hash
    /// pointing at r3.row_hash). Walker accepts the gap by
    /// stitching r1.row_hash → r2.row_hash → r3.row_hash and
    /// matching r4.prev_hash.
    #[test]
    fn retention_marker_accepts_legitimate_gap() {
        let r1 = row(1, None);
        let r2 = row(2, Some(r1.row_hash.as_str()));
        let r3 = row(3, Some(r2.row_hash.as_str()));
        // r4 is the next regular row written AFTER the sweep;
        // its prev_hash still points at the now-deleted
        // r3.row_hash (the chain wasn't rewritten — the
        // marker authorises the gap instead).
        let r4 = row(4, Some(r3.row_hash.as_str()));
        // The marker attests the
        // contiguous chain r1.row_hash → r2 → r3. Walker
        // stitches by bridge index keyed on the first
        // entry's prev_hash.
        let marker = marker_payload(&[
            (Some(r1.row_hash.as_str()), r2.row_hash.as_str()),
            (Some(r2.row_hash.as_str()), r3.row_hash.as_str()),
        ]);
        // Walked slice mirrors what the real adapter SELECTs
        // for an old-rows page — [r1, r4] (r2, r3 deleted;
        // the marker is at chain_seq=10 on the LATEST page,
        // not in this slice). Markers list is supplied
        // externally by the adapter from its full-tenant
        // marker fetch.
        let walked = vec![r1.clone(), r4.clone()];
        let markers = vec![marker];
        let report = verify_chain_rows("default", None, None, None, &walked, &markers);
        assert_eq!(
            report.status,
            ChainVerifyStatus::Ok,
            "verifier must accept the retention gap bridged by the marker chain",
        );
        assert_eq!(report.rows_walked, 2);
        assert!(report.first_mismatch.is_none());
    }

    /// Negative pin: gap exists but no marker bridges the
    /// boundary. Must report BrokenLink. An attacker can't
    /// fabricate a half-truth marker that authorises some
    /// deletions while hiding others.
    #[test]
    fn retention_marker_with_unrelated_hash_does_not_cover_gap() {
        let r1 = row(1, None);
        let r2 = row(2, Some(r1.row_hash.as_str()));
        let r3 = row(3, Some(r2.row_hash.as_str()));
        let r4 = row(4, Some(r3.row_hash.as_str()));
        // Walked slice: [r1, r4] (r2 + r3 deleted). Marker
        // attests an UNRELATED chain — doesn't link from
        // r1.row_hash. bridge_index.get(&Some(r1.row_hash))
        // returns None; gap unauthorised.
        let walked = vec![r1.clone(), r4.clone()];
        let markers = vec![marker_payload(&[(
            Some("unrelated_predecessor"),
            "unrelated_row_hash",
        )])];
        let report = verify_chain_rows("default", None, None, None, &walked, &markers);
        assert_eq!(report.status, ChainVerifyStatus::Mismatch);
        let m = report.first_mismatch.expect("mismatch reported");
        assert_eq!(m.kind, MismatchKind::BrokenLink);
        assert_eq!(m.chain_seq, 4);
        assert_eq!(m.actual, r3.row_hash);
    }

    /// Under-reporting marker.
    /// Sweep deleted r2 AND r3; marker only attests r3's
    /// deletion (omits r2). Walker tries to bridge
    /// r1.row_hash → r4.prev_hash but the marker starts at
    /// r2.row_hash, not r1.row_hash — bridge cursor never
    /// advances. BrokenLink.
    #[test]
    fn under_reporting_marker_fails_boundary_stitch() {
        let r1 = row(1, None);
        let r2 = row(2, Some(r1.row_hash.as_str()));
        let r3 = row(3, Some(r2.row_hash.as_str()));
        let r4 = row(4, Some(r3.row_hash.as_str()));
        // Under-reporting marker: only attests r3's deletion;
        // r2's deletion is silently dropped. The marker is
        // internally consistent (single entry passes
        // validate()) but the boundary stitch fails: walker
        // looks up by r1.row_hash, finds nothing, gap stays
        // unauthorised.
        let walked = vec![r1.clone(), r4.clone()];
        let markers = vec![marker_payload(&[(
            Some(r2.row_hash.as_str()),
            r3.row_hash.as_str(),
        )])];
        let report = verify_chain_rows("default", None, None, None, &walked, &markers);
        assert_eq!(
            report.status,
            ChainVerifyStatus::Mismatch,
            "under-reporting marker must NOT authorise the multi-row gap",
        );
        let m = report.first_mismatch.expect("mismatch reported");
        assert_eq!(m.kind, MismatchKind::BrokenLink);
    }

    /// Self-bootstrap.
    /// Sweep deletes r2 AND r3 (everything before the marker)
    /// then inserts marker M at chain_seq 4. M.prev_hash =
    /// r3.row_hash (chain head at insert time). Surviving:
    /// r1, M. Walker walks [r1, M]; M.prev_hash mismatches
    /// (expected r1.row_hash). Bridge lookup by r1.row_hash
    /// → M itself (its first deleted_rows entry's prev_hash
    /// is r1.row_hash); advance to M's last entry's
    /// row_hash = r3.row_hash; matches M.prev_hash. Bridged.
    #[test]
    fn marker_self_bootstraps_when_predecessor_deleted_by_itself() {
        let r1 = row(1, None);
        let r2 = row(2, Some(r1.row_hash.as_str()));
        let r3 = row(3, Some(r2.row_hash.as_str()));
        // Marker M at chain_seq 4, attesting deletion of
        // r2 and r3 (everything between r1 and M).
        let marker = marker_row(
            4,
            Some(r3.row_hash.as_str()),
            vec![
                DeletedRow {
                    prev_hash: Some(r1.row_hash.clone()),
                    row_hash: r2.row_hash.clone(),
                },
                DeletedRow {
                    prev_hash: Some(r2.row_hash.clone()),
                    row_hash: r3.row_hash.clone(),
                },
            ],
        );
        let marker_payload =
            RetentionMarker::from_reason(marker.reason.as_deref().expect("marker has reason"))
                .expect("marker payload parses");
        let walked = vec![r1.clone(), marker.clone()];
        let report = verify_chain_rows("default", None, None, None, &walked, &[marker_payload]);
        assert_eq!(
            report.status,
            ChainVerifyStatus::Ok,
            "marker must self-bootstrap: its own deleted_rows entry covers its own prev_hash",
        );
        assert_eq!(report.rows_walked, 2);
    }

    /// Multi-cycle stitching.
    /// Sweep 1 deletes r2 (marker M1). Sweep 2 (later)
    /// deletes r3 (marker M2). Walker sees [r1, r4]. Bridge
    /// stitches r1.row_hash → r2.row_hash via M1, then
    /// r2.row_hash → r3.row_hash via M2, matching
    /// r4.prev_hash.
    #[test]
    fn multi_cycle_stitching_bridges_gap() {
        let r1 = row(1, None);
        let r2 = row(2, Some(r1.row_hash.as_str()));
        let r3 = row(3, Some(r2.row_hash.as_str()));
        let r4 = row(4, Some(r3.row_hash.as_str()));
        let m1 = marker_payload(&[(Some(r1.row_hash.as_str()), r2.row_hash.as_str())]);
        let m2 = marker_payload(&[(Some(r2.row_hash.as_str()), r3.row_hash.as_str())]);
        let walked = vec![r1.clone(), r4.clone()];
        let report = verify_chain_rows("default", None, None, None, &walked, &[m1, m2]);
        assert_eq!(
            report.status,
            ChainVerifyStatus::Ok,
            "walker must stitch two markers across one gap",
        );
    }

    #[test]
    fn retention_history_beyond_hundred_markers_still_verifies() {
        const MARKER_DEPTH: usize = 101;
        let mut markers = Vec::with_capacity(MARKER_DEPTH);
        let mut previous_hash: Option<String> = None;

        for index in 0..MARKER_DEPTH {
            let row_hash = format!("deleted-{index}");
            markers.push(RetentionMarker {
                kind: RetentionMarker::KIND.to_owned(),
                deleted_rows: vec![DeletedRow {
                    prev_hash: previous_hash.clone(),
                    row_hash: row_hash.clone(),
                }],
                deleted_unchained_rows: Vec::new(),
                deleted_chain_seq_min: None,
                deleted_chain_seq_max: None,
                policy: Some("test".to_owned()),
            });
            previous_hash = Some(row_hash);
        }

        let survivor = row(10_000, previous_hash.as_deref());
        let report = verify_chain_rows("default", None, None, None, &[survivor], &markers);

        assert_eq!(
            report.status,
            ChainVerifyStatus::Ok,
            "valid retention history must not fail at an arbitrary marker depth",
        );
    }

    /// Marker integrity (the load-bearing property): even when
    /// a marker bridges a gap, the marker row IN the walked
    /// slice still has to chain-verify individually. Tamper
    /// the marker's reason after building it (without
    /// recomputing row_hash) — invariant 2 catches the
    /// staleness because canonical_audit_bytes includes
    /// `reason`. A malicious operator can't add hashes to an
    /// existing marker's reason field without also recomputing
    /// the chain from that marker forward.
    #[test]
    fn retention_marker_with_tampered_reason_fails_invariant_2() {
        let r1 = row(1, None);
        let r2 = row(2, Some(r1.row_hash.as_str()));
        let r3 = row(3, Some(r2.row_hash.as_str()));
        let r4 = row(4, Some(r3.row_hash.as_str()));
        // Clean marker at chain_seq 5, prev_hash links to
        // r4.row_hash so the marker itself is a valid
        // in-chain row.
        let mut marker = marker_row(
            5,
            Some(r4.row_hash.as_str()),
            vec![
                DeletedRow {
                    prev_hash: Some(r1.row_hash.clone()),
                    row_hash: r2.row_hash.clone(),
                },
                DeletedRow {
                    prev_hash: Some(r2.row_hash.clone()),
                    row_hash: r3.row_hash.clone(),
                },
            ],
        );
        // Tamper: rewrite reason to add a smuggled entry
        // WITHOUT recomputing row_hash. The stored row_hash
        // is now stale relative to the new canonical bytes.
        let tampered = RetentionMarker {
            kind: RetentionMarker::KIND.to_owned(),
            deleted_rows: vec![
                DeletedRow {
                    prev_hash: Some(r1.row_hash.clone()),
                    row_hash: r2.row_hash.clone(),
                },
                DeletedRow {
                    prev_hash: Some(r2.row_hash.clone()),
                    row_hash: r3.row_hash.clone(),
                },
                DeletedRow {
                    prev_hash: Some(r3.row_hash.clone()),
                    row_hash: "smuggled".to_owned(),
                },
            ],
            deleted_unchained_rows: Vec::new(),
            deleted_chain_seq_min: Some(2),
            deleted_chain_seq_max: Some(4),
            policy: None,
        };
        marker.reason = Some(tampered.to_reason());
        // Walker catches this on the marker row itself via
        // invariant 2 (BadRowHash), regardless of whether
        // any marker bridges any gap.
        let walked = vec![r1.clone(), r4.clone(), marker.clone()];
        let bridge = marker_payload(&[
            (Some(r1.row_hash.as_str()), r2.row_hash.as_str()),
            (Some(r2.row_hash.as_str()), r3.row_hash.as_str()),
        ]);
        let report = verify_chain_rows("default", None, None, None, &walked, &[bridge]);
        assert_eq!(report.status, ChainVerifyStatus::Mismatch);
        let m = report.first_mismatch.expect("mismatch reported");
        assert_eq!(m.kind, MismatchKind::BadRowHash);
        assert_eq!(m.chain_seq, 5, "marker itself must fail invariant 2");
    }

    /// Regression pin: a sweep at
    /// the LATEST chain head (high chain_seq) authorises a
    /// gap on the OLDEST page (low chain_seq) iff the marker
    /// set is supplied externally. The round-1 design
    /// collected markers walker-side and would have failed
    /// this case because the marker's chain_seq is past the
    /// page limit. The new design (set supplied by the
    /// storage adapter from a full-tenant marker fetch) is
    /// invariant in pagination.
    #[test]
    fn marker_at_chain_head_authorises_gap_on_older_page() {
        let r1 = row(1, None);
        let r2 = row(2, Some(r1.row_hash.as_str()));
        let r3 = row(3, Some(r2.row_hash.as_str()));
        let r4 = row(4, Some(r3.row_hash.as_str()));
        let markers = vec![marker_payload(&[
            (Some(r1.row_hash.as_str()), r2.row_hash.as_str()),
            (Some(r2.row_hash.as_str()), r3.row_hash.as_str()),
        ])];
        // Walked slice: page 1, just [r1, r4]. NO marker in
        // slice. Without the markers list the verifier would
        // BrokenLink on r4. With it, the gap is bridged.
        let walked = vec![r1.clone(), r4.clone()];
        let report = verify_chain_rows("default", None, None, None, &walked, &markers);
        assert_eq!(
            report.status,
            ChainVerifyStatus::Ok,
            "external marker set must authorise gaps regardless of pagination",
        );
    }

    /// Regression pin: per-marker
    /// chain-verification on the adapter side. A marker
    /// OUTSIDE the walked slice with a tampered reason
    /// (modified deleted_rows without recomputing row_hash)
    /// fails `recompute_row_hash` against its stored value
    /// and must NOT contribute to the bridge index.
    #[test]
    fn recompute_row_hash_catches_marker_reason_tamper() {
        let r1 = row(1, None);
        // Clean marker — single deletion claim chaining
        // from r1.row_hash.
        let mut marker = marker_row(
            5,
            Some(r1.row_hash.as_str()),
            vec![DeletedRow {
                prev_hash: Some(r1.row_hash.clone()),
                row_hash: "deleted_row_hash".to_owned(),
            }],
        );
        assert_eq!(
            recompute_row_hash(&marker),
            marker.row_hash,
            "clean marker must self-verify",
        );
        // Tamper: rewrite reason WITHOUT re-running
        // compute_row_hash.
        let tampered = RetentionMarker {
            kind: RetentionMarker::KIND.to_owned(),
            deleted_rows: vec![
                DeletedRow {
                    prev_hash: Some(r1.row_hash.clone()),
                    row_hash: "deleted_row_hash".to_owned(),
                },
                DeletedRow {
                    prev_hash: Some("deleted_row_hash".to_owned()),
                    row_hash: "smuggled".to_owned(),
                },
            ],
            deleted_unchained_rows: Vec::new(),
            deleted_chain_seq_min: None,
            deleted_chain_seq_max: None,
            policy: None,
        };
        marker.reason = Some(tampered.to_reason());
        assert_ne!(
            recompute_row_hash(&marker),
            marker.row_hash,
            "tampered marker must NOT self-verify — the adapter must filter it out",
        );
    }

    /// Cycle defence. Two markers
    /// each attest to each other's end: M1 starts at A and
    /// ends at B; M2 starts at B and ends at A. Bridge
    /// traversal loops A→B→A→B... — must terminate after exhausting the finite
    /// bridge graph and report BrokenLink rather than hanging. Cycle is
    /// constructed with fictitious hashes (the cycle structure is what
    /// matters, not real chain content).
    #[test]
    fn bridge_traversal_terminates_on_adversarial_cycle() {
        let r1 = row(1, None);
        // r2.prev_hash = "cycle_a", which is NOT r1.row_hash;
        // walker will try to bridge from r1.row_hash to
        // "cycle_a". The cycle markers offer A→B→A→... but
        // never reach the target.
        let mut r2 = row(2, Some("cycle_a"));
        // Don't fix row_hash recompute — for this test we
        // only care about the BrokenLink invariant 1 path;
        // the walker checks invariant 1 BEFORE invariant 2.
        // Make r2's row_hash internally consistent for its
        // (broken) prev_hash so invariant 2 doesn't fire
        // first.
        let bytes = canonical_audit_bytes(
            r2.id,
            r2.ts,
            &r2.category,
            &r2.tenant_id,
            &r2.action,
            &r2.outcome,
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
        );
        r2.row_hash = compute_row_hash(Some("cycle_a"), &bytes);
        let m1 = marker_payload(&[(Some(r1.row_hash.as_str()), "cycle_b")]);
        let m2 = marker_payload(&[(Some("cycle_b"), r1.row_hash.as_str())]);
        let walked = vec![r1.clone(), r2.clone()];
        let report = verify_chain_rows("default", None, None, None, &walked, &[m1, m2]);
        assert_eq!(
            report.status,
            ChainVerifyStatus::Mismatch,
            "adversarial cycle must terminate as BrokenLink, not hang",
        );
        assert_eq!(
            report.first_mismatch.expect("mismatch reported").kind,
            MismatchKind::BrokenLink,
        );
    }

    /// `validate()` rejects an
    /// empty marker. An empty marker contributes no bridge
    /// and would pollute the index — drop it.
    #[test]
    fn validate_rejects_empty_marker() {
        let m = RetentionMarker {
            kind: RetentionMarker::KIND.to_owned(),
            deleted_rows: vec![],
            deleted_unchained_rows: Vec::new(),
            deleted_chain_seq_min: None,
            deleted_chain_seq_max: None,
            policy: None,
        };
        assert!(!m.validate(), "empty marker must fail self-consistency");
    }

    #[test]
    fn validate_accepts_unique_unchained_rows_and_rejects_duplicate_ids() {
        let id = Uuid::from_u128(42);
        let mut marker = RetentionMarker {
            kind: RetentionMarker::KIND.to_owned(),
            deleted_rows: Vec::new(),
            deleted_unchained_rows: vec![DeletedUnchainedRow { id, chain_seq: 7 }],
            deleted_chain_seq_min: None,
            deleted_chain_seq_max: None,
            policy: None,
        };
        assert!(
            marker.validate(),
            "an unchained-only deletion still produces a valid visible marker",
        );
        marker
            .deleted_unchained_rows
            .push(DeletedUnchainedRow { id, chain_seq: 8 });
        assert!(
            !marker.validate(),
            "one marker must not claim the same unchained row twice",
        );
    }

    #[test]
    fn validate_accepts_a_contiguous_chain_with_unique_row_hashes() {
        let marker = marker_payload(&[(Some("anchor"), "first"), (Some("first"), "second")]);

        assert!(
            marker.validate(),
            "a contiguous deletion span with unique row hashes must be valid",
        );
    }

    /// `validate()` rejects a marker whose internal chain is
    /// broken (next.prev_hash != prior.row_hash).
    #[test]
    fn validate_rejects_broken_internal_chain() {
        let m = marker_payload(&[
            (Some("a"), "b"),
            (Some("not_b"), "c"), // not_b != b → broken
        ]);
        assert!(
            !m.validate(),
            "broken internal chain must fail self-consistency",
        );
    }

    /// `validate()` rejects a marker that lists the same
    /// row_hash twice. Same row can't be deleted twice in
    /// one sweep cycle; a duplicate is a malformed payload.
    #[test]
    fn validate_rejects_duplicate_row_hashes() {
        let m = marker_payload(&[
            (Some("a"), "b"),
            (Some("b"), "b"), // duplicate row_hash "b"
        ]);
        assert!(
            !m.validate(),
            "duplicate row_hash within marker must fail self-consistency",
        );
    }
}
