//! Signed evidence-bundle export.
//!
//! Builds a self-contained, recipient-verifiable bundle of
//! `audit_log` rows for a `(tenant, time_window)` slice plus
//! optional `principal_sub` / `tool` filters. Compliance
//! auditors get an NDJSON file they can verify offline with
//! the operator's published Ed25519 public key — no live
//! gateway access needed.
//!
//! ## File shape
//!
//! Newline-delimited JSON, three sections:
//!
//! ```text
//! {"$type":"header", "version":1, "tenant_id":"...", "from":"...", "to":"...",
//!  "principal_sub":null, "tool":null, "row_count":N,
//!  "signing_key_id":"...", "gateway_version":"...", "ts_emitted":"..."}
//! { ...audit row 1 as JSON... }
//! { ...audit row 2 as JSON... }
//! ...
//! { ...audit row N as JSON... }
//! {"$type":"footer", "algorithm":"ed25519", "signature":"<hex>"}
//! ```
//!
//! The signature covers the bytes of the header line and
//! every row line, joined by `\n` (no trailing `\n` before
//! signing). The footer line carries the signature but is
//! NOT itself signed.
//!
//! ## Recipient verification
//!
//! 1. Read header line → JSON.
//! 2. Read each row line until the line starts with
//!    `{"$type":"footer"`.
//! 3. Read footer line → JSON; extract `signature` (hex).
//! 4. Recompute `sha256(header_line || "\n" || row_1 || "\n"
//!    || ... || row_N)`.
//! 5. Verify Ed25519 signature against the operator's
//!    pre-published public key for `signing_key_id`.
//!
//! No CBOR, no protobuf, no schema registry — anything that
//! reads JSON and has a SHA256+Ed25519 library can verify.
//!
//! ## Signing key
//!
//! Ed25519, loaded from `GATEWAY_EVIDENCE_BUNDLE_SIGNING_KEY_PEM`
//! (PKCS8 PEM). The operator publishes the corresponding
//! public key out of band — typically in a compliance
//! attestation document or a key transparency log entry.
//!
//! `signing_key_id` defaults to the first 16 hex chars of
//! `sha256(verifying_key_bytes)`; operators can override via
//! `GATEWAY_EVIDENCE_BUNDLE_SIGNING_KEY_ID` to use a
//! human-readable label (`"bundle-2026-q2"`).
//!
//! ## Out of scope
//!
//! - **Chain-coverage attestation in the header.** Future
//!   work: include the tenant's `chain_head` (chain_seq +
//!   row_hash) and the chain-verifier verdict over the
//!   window, so a recipient sees not just the rows but the
//!   chain-integrity proof for them. Today the bundle is
//!   row export only; recipients wanting chain proof for the
//!   chain-bearing rows run a verify call against the live gateway
//!   separately.
//! - **Multi-tenant bundles.** A bundle is one tenant per
//!   call. Cross-tenant export would require either a
//!   "global compliance" role with cross-tenant read or
//!   per-tenant bundles concatenated — both deliberately
//!   deferred.

use std::io::Write;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

use crate::audit::AuditRow;

/// Bundle format version. Bumped if header/footer or
/// signing-bytes assembly changes in a way recipients need
/// to be aware of.
pub const BUNDLE_FORMAT_VERSION: u32 = 1;

/// Boot-time signing config the admin endpoint holds.
/// `waygate-server` constructs this once at startup from
/// the env (`GATEWAY_EVIDENCE_BUNDLE_SIGNING_KEY_PEM` for
/// the key, `..._KEY_ID` for the operator-visible label),
/// hands it to `AdminState` via the builder, and the
/// `audit_bundle` handler consumes both fields per export.
///
/// Held behind `Arc` in `AdminState` because the
/// `SigningKey` does not implement `Clone` cheaply (it
/// holds secret bytes); sharing immutably via Arc keeps
/// the secret in one place.
#[derive(Debug)]
pub struct BundleSigner {
    pub signing_key: SigningKey,
    pub signing_key_id: String,
}

impl BundleSigner {
    /// Construct from a PKCS8-PEM-encoded Ed25519 private
    /// key. `key_id` is the operator-supplied label; pass
    /// `None` to auto-derive via [`derive_signing_key_id`]
    /// over the corresponding public key.
    pub fn from_pem(pem: &str, key_id: Option<String>) -> Result<Self, BundleSignerError> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        let signing_key =
            SigningKey::from_pkcs8_pem(pem).map_err(|e| BundleSignerError::Pem(e.to_string()))?;
        let key_id = key_id.unwrap_or_else(|| derive_signing_key_id(&signing_key.verifying_key()));
        Ok(Self {
            signing_key,
            signing_key_id: key_id,
        })
    }
}

/// Signing-key load failures the waygate-server boot path
/// surfaces. Distinguished from `BundleError` because they
/// happen at startup, not at request time.
#[derive(Debug, Error)]
pub enum BundleSignerError {
    #[error("bundle signing key PEM parse: {0}")]
    Pem(String),
}

/// Header line shape. Serialised on the wire; recipients
/// deserialise with this same struct (cross-language clones
/// just need the field names + order-independent JSON).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BundleHeader {
    #[serde(rename = "$type")]
    pub type_tag: String,
    pub version: u32,
    pub tenant_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub from: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub to: OffsetDateTime,
    pub principal_sub: Option<String>,
    pub tool: Option<String>,
    pub row_count: usize,
    pub signing_key_id: String,
    pub gateway_version: String,
    #[serde(with = "time::serde::rfc3339")]
    pub ts_emitted: OffsetDateTime,
}

/// Footer line shape. Carries only the signature + the
/// algorithm identifier; recipients verify against the
/// signing key advertised in the header.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BundleFooter {
    #[serde(rename = "$type")]
    pub type_tag: String,
    pub algorithm: String,
    pub signature: String,
}

/// Bundle-construction failure modes. Distinguished from
/// `sqlx::Error` so the admin handler can map each to the
/// right HTTP status.
#[derive(Debug, Error)]
pub enum BundleError {
    #[error("postgres: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("bundle serialise: {0}")]
    Serialise(String),
}

/// Inputs for one bundle. Constructed by the admin handler
/// from the request body.
#[derive(Debug, Clone)]
pub struct BundleRequest {
    pub tenant_id: String,
    pub from: OffsetDateTime,
    pub to: OffsetDateTime,
    pub principal_sub: Option<String>,
    pub tool: Option<String>,
}

/// Assemble the bundle bytes (header line + rows + footer
/// line, `\n`-delimited). Pure function: no I/O, no DB. The
/// admin handler calls
/// `AuditReader::fetch_events_for_bundle` to get `rows`,
/// then passes them here.
///
/// `signing_key_id`: human label baked into the header so
/// recipients know which published key to verify against.
/// Pure-function callers (tests, golden-output tools) supply
/// the value directly; production callers usually default
/// it from the public-key hash (see
/// [`derive_signing_key_id`]).
pub fn build_bundle(
    req: &BundleRequest,
    rows: &[AuditRow],
    signing_key_id: &str,
    gateway_version: &str,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, BundleError> {
    let header = BundleHeader {
        type_tag: "header".to_owned(),
        version: BUNDLE_FORMAT_VERSION,
        tenant_id: req.tenant_id.clone(),
        from: req.from,
        to: req.to,
        principal_sub: req.principal_sub.clone(),
        tool: req.tool.clone(),
        row_count: rows.len(),
        signing_key_id: signing_key_id.to_owned(),
        gateway_version: gateway_version.to_owned(),
        ts_emitted: OffsetDateTime::now_utc(),
    };

    let header_bytes = serde_json::to_vec(&header)
        .map_err(|e| BundleError::Serialise(format!("header serialise: {e}")))?;
    let row_bytes: Vec<Vec<u8>> = rows
        .iter()
        .map(|r| {
            serde_json::to_vec(r).map_err(|e| BundleError::Serialise(format!("row serialise: {e}")))
        })
        .collect::<Result<_, _>>()?;

    // Signed payload: header_line || "\n" || row_1 || "\n"
    // || ... || row_N. NO trailing newline — the recipient
    // recomputes the same bytes by joining the lines they
    // read up to (but not including) the footer line.
    let mut signed = Vec::with_capacity(
        header_bytes.len() + row_bytes.iter().map(|r| r.len() + 1).sum::<usize>(),
    );
    signed.extend_from_slice(&header_bytes);
    for row in &row_bytes {
        signed.push(b'\n');
        signed.extend_from_slice(row);
    }

    let mut hasher = Sha256::new();
    hasher.update(&signed);
    let digest = hasher.finalize();
    let signature = signing_key.sign(&digest);
    let footer = BundleFooter {
        type_tag: "footer".to_owned(),
        algorithm: "ed25519".to_owned(),
        signature: hex::encode(signature.to_bytes()),
    };
    let footer_bytes = serde_json::to_vec(&footer)
        .map_err(|e| BundleError::Serialise(format!("footer serialise: {e}")))?;

    // Final wire format: signed payload + "\n" + footer.
    let mut out = Vec::with_capacity(signed.len() + 1 + footer_bytes.len() + 1);
    out.extend_from_slice(&signed);
    out.push(b'\n');
    out.extend_from_slice(&footer_bytes);
    out.push(b'\n');
    Ok(out)
}

/// Derive the default `signing_key_id` when the operator
/// hasn't set one explicitly. Uses the first 16 hex chars
/// of `sha256(verifying_key_bytes)` — distinct keys produce
/// distinct ids by construction; recipients verifying
/// against a published key list match by id.
pub fn derive_signing_key_id(verifying_key: &VerifyingKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifying_key.to_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

/// Recipient-side helper: verify a bundle's signature
/// against the supplied `VerifyingKey`. Exposed `pub` so
/// the integration tests AND a future
/// `gateway-server --verify-bundle` CLI can both use the
/// same code path. Returns `Ok(parsed_header)` on success,
/// `Err` describing the failure mode otherwise (so a CLI
/// can render "row N didn't deserialise" vs "signature
/// mismatch" vs "no footer found" distinctly).
pub fn verify_bundle(
    bytes: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<BundleHeader, VerifyError> {
    let text = std::str::from_utf8(bytes).map_err(|e| VerifyError::Utf8(e.to_string()))?;
    // `lines` is consumed iteratively: header first, then
    // rows via `while let Some(line) = lines.next()` so the
    // post-footer trailing-content check can still iterate
    // the leftovers.
    let mut lines = text.split('\n');
    let header_line = lines.next().ok_or(VerifyError::MissingHeader)?;
    let header: BundleHeader =
        serde_json::from_str(header_line).map_err(|e| VerifyError::HeaderParse(e.to_string()))?;
    if header.type_tag != "header" {
        return Err(VerifyError::HeaderParse(format!(
            "first line $type expected 'header', got '{}'",
            header.type_tag
        )));
    }
    if header.version != BUNDLE_FORMAT_VERSION {
        return Err(VerifyError::UnsupportedVersion(header.version));
    }
    // Collect everything between the header and the footer.
    // The footer is identified by `$type == "footer"` in the
    // line's JSON — we deserialise candidate lines to detect.
    let mut signed = Vec::with_capacity(header_line.len() + bytes.len() / 4);
    signed.extend_from_slice(header_line.as_bytes());
    let mut footer: Option<BundleFooter> = None;
    let mut row_count = 0usize;
    // `lines.by_ref()` so the iterator is NOT consumed by
    // this loop — after the footer is found, the
    // trailing-content scan below continues iterating the
    // remainder.
    for line in lines.by_ref() {
        if line.is_empty() {
            // Empty segment mid-stream BEFORE finding a
            // footer — malformed (a bundle with an empty
            // mid-line is not a shape `build_bundle`
            // emits). Continue and let the missing-footer
            // check below catch it.
            continue;
        }
        // Cheap test for the footer line: starts with the
        // `{"$type":"footer"` prefix.
        if let Some(rest) = line.strip_prefix(r#"{"$type":"footer""#) {
            // Re-parse as footer with the full line text.
            let parsed: BundleFooter =
                serde_json::from_str(&format!("{{\"$type\":\"footer\"{}", rest))
                    .map_err(|e| VerifyError::FooterParse(e.to_string()))?;
            footer = Some(parsed);
            break;
        }
        signed.push(b'\n');
        signed.extend_from_slice(line.as_bytes());
        row_count += 1;
    }
    let footer = footer.ok_or(VerifyError::MissingFooter)?;
    if footer.algorithm != "ed25519" {
        return Err(VerifyError::UnsupportedAlgorithm(footer.algorithm));
    }
    // Security: nothing may
    // follow the footer line. Appended unsigned records
    // would otherwise sit in the file looking
    // authoritative — a recipient running this verifier
    // gets back Ok and trusts the file, but the appended
    // tail was never signed. Reject any non-empty content
    // after the footer (a single trailing newline produces
    // one empty segment after split, which is fine; any
    // non-empty line is not).
    for trailing in lines {
        if !trailing.is_empty() {
            return Err(VerifyError::TrailingContent(format!(
                "non-empty line after footer: {}",
                trailing.chars().take(80).collect::<String>()
            )));
        }
    }
    if row_count != header.row_count {
        return Err(VerifyError::RowCountMismatch {
            header: header.row_count,
            observed: row_count,
        });
    }
    let sig_bytes =
        hex::decode(&footer.signature).map_err(|e| VerifyError::SignatureDecode(e.to_string()))?;
    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| VerifyError::SignatureDecode(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(&signed);
    let digest = hasher.finalize();
    verifying_key
        .verify_strict(&digest, &signature)
        .map_err(|e| VerifyError::SignatureInvalid(e.to_string()))?;
    Ok(header)
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("bundle is not valid UTF-8: {0}")]
    Utf8(String),
    #[error("bundle missing header line")]
    MissingHeader,
    #[error("header line parse: {0}")]
    HeaderParse(String),
    #[error(
        "unsupported bundle version {0} (this verifier reads version {BUNDLE_FORMAT_VERSION})"
    )]
    UnsupportedVersion(u32),
    #[error("bundle missing footer line")]
    MissingFooter,
    #[error("footer line parse: {0}")]
    FooterParse(String),
    #[error("unsupported signature algorithm '{0}' (only 'ed25519' is recognised)")]
    UnsupportedAlgorithm(String),
    #[error(
        "row count mismatch: header claims {header} rows but observed {observed} lines between \
         header and footer"
    )]
    RowCountMismatch { header: usize, observed: usize },
    #[error("signature hex decode: {0}")]
    SignatureDecode(String),
    #[error("signature did not verify: {0}")]
    SignatureInvalid(String),
    /// Security: non-empty
    /// content after the footer line. The footer's
    /// signature only covers the header + row lines that
    /// preceded it; anything appended is unsigned and
    /// must not be trusted as part of the bundle.
    #[error("trailing content after footer (unsigned): {0}")]
    TrailingContent(String),
}

/// Convenience helper for the admin handler: stream the
/// bundle bytes into any `Write` sink. The default impl
/// builds in memory (`Vec<u8>`); the streaming hook is
/// here so a future S3-archive-direct path can flush
/// straight to a bucket without an intermediate Vec.
pub fn write_bundle<W: Write>(
    sink: &mut W,
    req: &BundleRequest,
    rows: &[AuditRow],
    signing_key_id: &str,
    gateway_version: &str,
    signing_key: &SigningKey,
) -> Result<(), BundleError> {
    let bytes = build_bundle(req, rows, signing_key_id, gateway_version, signing_key)?;
    sink.write_all(&bytes)
        .map_err(|e| BundleError::Serialise(format!("write_all: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use waygate_evidence::audit::EvidenceCategory;

    fn signing_key() -> SigningKey {
        // Deterministic test key; never use this in
        // production. 32 zero bytes is a valid Ed25519
        // private key seed.
        SigningKey::from_bytes(&[0u8; 32])
    }

    fn sample_row(action: &str) -> AuditRow {
        AuditRow {
            operation: None,
            id: Uuid::from_u128(1),
            ts: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            category: Some(EvidenceCategory::Invocation.as_str().to_owned()),
            tenant_id: "default".to_owned(),
            action: action.to_owned(),
            outcome: "success".to_owned(),
            principal_sub: Some("user-1".to_owned()),
            principal_email: None,
            principal_groups: vec!["mcp-users".to_owned()],
            issuer: Some("https://idp.example.test".to_owned()),
            server: Some("example-messages".to_owned()),
            tool: Some("send_message".to_owned()),
            risk_level: Some("high".to_owned()),
            pii: Some(true),
            policy_ids: vec!["policy-1".to_owned()],
            reason: None,
            trace_id: Some("trace-xyz".to_owned()),
            latency_ms: Some(42),
            scim_active: None,
            scim_groups: Vec::new(),
            target: None,
            req_scopes: Vec::new(),
            auth_method: None,
            req_roles: Vec::new(),
            side_effects: None,
            invocation_hierarchy: None,
        }
    }

    fn req() -> BundleRequest {
        BundleRequest {
            tenant_id: "default".to_owned(),
            from: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            to: OffsetDateTime::from_unix_timestamp(1_700_086_400).unwrap(),
            principal_sub: None,
            tool: None,
        }
    }

    /// Round-trip: build, verify, header matches.
    #[test]
    fn round_trip_signs_and_verifies() {
        let sk = signing_key();
        let vk = sk.verifying_key();
        let rows = vec![sample_row("CallTool"), sample_row("SearchTools")];
        let bundle = build_bundle(&req(), &rows, "test-key", "1.0.0", &sk).unwrap();
        let header = verify_bundle(&bundle, &vk).expect("verifies");
        assert_eq!(header.row_count, 2);
        assert_eq!(header.tenant_id, "default");
        assert_eq!(header.signing_key_id, "test-key");
        assert_eq!(header.version, BUNDLE_FORMAT_VERSION);
    }

    /// Empty windows produce a header+footer with `row_count: 0`,
    /// and the signature still verifies.
    #[test]
    fn empty_window_still_verifies() {
        let sk = signing_key();
        let vk = sk.verifying_key();
        let bundle = build_bundle(&req(), &[], "test-key", "1.0.0", &sk).unwrap();
        let header = verify_bundle(&bundle, &vk).expect("verifies");
        assert_eq!(header.row_count, 0);
    }

    /// Tampering with a body row flips the signature.
    /// Recipients catch the modification.
    #[test]
    fn tampered_row_fails_verification() {
        let sk = signing_key();
        let vk = sk.verifying_key();
        let rows = vec![sample_row("CallTool")];
        let bundle = build_bundle(&req(), &rows, "test-key", "1.0.0", &sk).unwrap();
        // Tamper: replace "CallTool" with "Tampered " (same
        // byte count so the JSON shape stays parseable).
        let mut tampered = bundle.clone();
        if let Some(pos) = tampered.windows(8).position(|w| w == b"CallTool") {
            tampered[pos..pos + 8].copy_from_slice(b"Tampered");
        } else {
            panic!("test fixture: expected 'CallTool' substring in bundle bytes");
        }
        let err = verify_bundle(&tampered, &vk).expect_err("must reject");
        match err {
            VerifyError::SignatureInvalid(_) => {}
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    /// Tampering with the header flips the signature.
    #[test]
    fn tampered_header_fails_verification() {
        let sk = signing_key();
        let vk = sk.verifying_key();
        let rows = vec![sample_row("CallTool")];
        let bundle = build_bundle(&req(), &rows, "test-key", "1.0.0", &sk).unwrap();
        let mut tampered = bundle.clone();
        if let Some(pos) = tampered.windows(7).position(|w| w == b"default") {
            tampered[pos..pos + 7].copy_from_slice(b"tampery");
        }
        let err = verify_bundle(&tampered, &vk).expect_err("must reject");
        match err {
            VerifyError::SignatureInvalid(_) => {}
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    /// `derive_signing_key_id` is stable and produces 16 hex
    /// chars. Operators relying on the auto-derived id can
    /// pre-publish it before any bundle export runs.
    #[test]
    fn derive_signing_key_id_is_stable_16_hex() {
        let sk = signing_key();
        let id = derive_signing_key_id(&sk.verifying_key());
        assert_eq!(id.len(), 16, "{id}");
        // Stability: re-derive yields the same id.
        let id2 = derive_signing_key_id(&sk.verifying_key());
        assert_eq!(id, id2);
        // Different keys yield different ids.
        let sk2 = SigningKey::from_bytes(&[1u8; 32]);
        let id3 = derive_signing_key_id(&sk2.verifying_key());
        assert_ne!(id, id3);
    }

    /// Wrong key fails to verify — a malicious "operator"
    /// who fabricates rows + signs with their own key can't
    /// pass off the bundle as legitimate.
    #[test]
    fn wrong_key_fails_verification() {
        let real_sk = signing_key();
        let fake_sk = SigningKey::from_bytes(&[2u8; 32]);
        let rows = vec![sample_row("CallTool")];
        let bundle = build_bundle(&req(), &rows, "fake-key", "1.0.0", &fake_sk).unwrap();
        let err = verify_bundle(&bundle, &real_sk.verifying_key())
            .expect_err("real key must reject fake-signed bundle");
        match err {
            VerifyError::SignatureInvalid(_) => {}
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    /// Security: appended
    /// content after the footer line is rejected as
    /// unsigned. A recipient running `verify_bundle` on a
    /// file that's been tampered by an attacker appending
    /// audit-looking rows after the original footer would
    /// otherwise return Ok and let the auditor trust the
    /// appended tail.
    #[test]
    fn trailing_content_after_footer_fails_verification() {
        let sk = signing_key();
        let vk = sk.verifying_key();
        let rows = vec![sample_row("CallTool")];
        let mut bundle = build_bundle(&req(), &rows, "test-key", "1.0.0", &sk).unwrap();
        // Append an audit-row-shaped JSON line AFTER the
        // signed footer. The attacker hopes the recipient
        // treats it as a legitimate event.
        bundle.extend_from_slice(b"{\"id\":\"fake-row\",\"action\":\"InjectedTool\"}\n");
        let err = verify_bundle(&bundle, &vk).expect_err("must reject");
        match err {
            VerifyError::TrailingContent(_) => {}
            other => panic!("expected TrailingContent, got {other:?}"),
        }
    }

    /// Row-count mismatch (header claims N, body has M ≠ N)
    /// is caught — defends against a tampered header that
    /// drops rows from `row_count`.
    #[test]
    fn row_count_mismatch_fails_verification() {
        let sk = signing_key();
        let vk = sk.verifying_key();
        let rows = vec![sample_row("CallTool"), sample_row("Tool2")];
        let bundle = build_bundle(&req(), &rows, "test-key", "1.0.0", &sk).unwrap();
        // Replace the header's row_count from 2 to 99
        // without recomputing the signature.
        let mut tampered = bundle.clone();
        if let Some(pos) = tampered.windows(13).position(|w| w == b"\"row_count\":2") {
            tampered[pos..pos + 13].copy_from_slice(b"\"row_count\":9");
        } else {
            panic!("test fixture: expected row_count:2 substring");
        }
        let err = verify_bundle(&tampered, &vk).expect_err("must reject");
        // Mismatch is caught EITHER at the row-count check
        // OR at signature verify (the row_count is in the
        // signed bytes too) — both are correct rejection
        // paths.
        match err {
            VerifyError::RowCountMismatch { .. } | VerifyError::SignatureInvalid(_) => {}
            other => panic!("expected RowCountMismatch or SignatureInvalid, got {other:?}"),
        }
    }
}
