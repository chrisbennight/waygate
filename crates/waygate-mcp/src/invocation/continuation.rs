//! Sealed MRTR continuation state.
//!
//! `requestState` crosses an untrusted client, so the protocol requires a
//! server whose state influences authorization or business logic to
//! integrity-protect it and reject what fails verification, and to bind the
//! authenticated principal, an expiry, and the originating request inside
//! that protection. The gateway is a server at its own hop, so it seals its
//! own envelope around whatever the upstream minted: the caller echoes the
//! gateway's blob, and the upstream still receives exactly its own state
//! (or none) on the retry.
//!
//! The envelope is what makes an elicited file safe to deliver. Without it
//! the gateway cannot tell a genuine answer to a pause it relayed from a
//! continuation a caller assembled, so it could be steered into uploading
//! an owned file to a tool that never asked for one. With it, the retry
//! proves which principal, server, and tool the pause belonged to — and
//! nothing is persisted, so any replica can still serve any retry.
//!
//! What identifies the originating request is the selected server and tool,
//! the contract admitted behind those names, and a digest of the
//! caller-authored arguments, taken before any file rewriting so the
//! pausing leg and its retry hash the same call. An envelope minted for one
//! call therefore cannot be presented on a different call, even by the same
//! caller to the same tool, and a reload that swaps a different contract in
//! behind the same names invalidates outstanding pauses rather than letting
//! the replacement inherit them.
//!
//! The envelope also seals the response keys the pause issued, so a retry
//! may answer only what its own pause asked, and separately the subset of
//! those asked by an elicitation, which are the only keys a file may be
//! delivered under. Sampling and roots requests never ask a human for a
//! value, so they authorize no upload.
//!
//! Per-key file authorization is finer still — deliver only where the
//! upstream's `requestedSchema` marks a field file-valued — but the pinned
//! MCP library parses elicitation schemas into typed structures and drops
//! unknown keywords, so `x-mcp-file` does not survive the pause relay and
//! cannot be sealed. Until the library preserves it, an elicitation key is
//! the finest available grain; the residue is that a caller may answer one
//! of its own pause's non-file elicitation keys with a file, which the
//! eliciting upstream then rejects as an unexpected value.
//!
//! No replay counter is kept: binding, expiry, the argument digest, and the
//! sealed key sets bound cross-user, cross-call, and invented-key reuse.
//! What remains is re-answering the very same call inside the TTL, which
//! re-delivers a file to a field that pause did open; at-most-once would
//! require the server-side state the protocol says it needs, and this
//! feature does not.

use serde::{Deserialize, Serialize};
use waygate_oidc::session::{self, HasExp, SessionKey};
use waygate_oidc::Principal;

/// How long a relayed pause stays answerable. Long enough for a human to
/// answer an elicitation, short enough to bound replay.
const CONTINUATION_TTL_SECONDS: i64 = 30 * 60;

/// Seals and verifies the gateway's continuation envelope.
#[derive(Clone)]
pub struct ContinuationSealer {
    key: SessionKey,
}

/// What identifies the call a pause belongs to.
///
/// Names alone are not enough: a catalog or manifest reload can put a
/// different contract behind the same server and tool while a pause is
/// outstanding, and a file must never be delivered to a contract that did
/// not issue the elicitation.
pub struct CallIdentity<'a> {
    pub server: &'a str,
    pub tool: &'a str,
    /// Digest of the caller-authored arguments.
    pub digest: &'a str,
    /// The admitted contract identity, serialized. Compared as text, the
    /// same way Code Mode compares a persisted identity against a fresh one.
    pub contract: &'a str,
}

/// What one in-flight call knows about its own continuation.
#[derive(Default)]
pub struct CallState {
    /// Digest of the caller-authored arguments, taken before file rewriting
    /// so a pause and its retry identify the same originating request.
    pub digest: String,
    /// Response keys a verified continuation may deliver files under.
    /// `None` until a continuation verifies, which is not the same as a
    /// verified continuation that opened no key.
    pub deliverable_keys: Option<Vec<String>>,
}

/// The gateway's authenticated continuation claims.
///
/// `inner` carries the upstream's own opaque state verbatim so the retry can
/// resume it; the gateway never interprets that value.
#[derive(Debug, Serialize, Deserialize)]
struct SealedContinuation {
    /// Authenticated principal the pause was relayed to.
    sub: String,
    /// Principal's issuer, so subjects cannot collide across identity
    /// providers.
    iss: String,
    tenant: String,
    /// Originating request identity: the selected upstream and tool, and a
    /// digest of the caller-authored arguments the pause was raised for. The
    /// digest is what keeps an envelope from one call being presented on a
    /// different call to the same tool.
    server: String,
    tool: String,
    #[serde(default)]
    args: String,
    /// The contract admitted when the pause was raised, so a reload that
    /// swaps a different tool behind the same names invalidates the pause
    /// instead of inheriting it.
    #[serde(default)]
    contract: String,
    exp: i64,
    /// Response keys this pause issued. A retry may answer no others.
    #[serde(default)]
    keys: Vec<String>,
    /// Subset of `keys` whose request was an elicitation. Only an
    /// elicitation asks a human for a value, so only these may carry a
    /// file; a sampling or roots request never can.
    #[serde(default)]
    file_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inner: Option<String>,
}

/// What a verified continuation authorizes for this retry.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedContinuation {
    /// The upstream's own opaque state, forwarded verbatim.
    pub upstream_state: Option<String>,
    /// Elicitation keys this pause issued; files may be delivered only
    /// under these.
    pub deliverable_keys: Vec<String>,
}

impl HasExp for SealedContinuation {
    fn exp(&self) -> i64 {
        self.exp
    }
}

/// Why a caller-presented continuation was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum ContinuationError {
    /// The blob is not a valid gateway envelope: forged, tampered with,
    /// sealed by a different deployment or key, or expired.
    Unverifiable,
    /// The envelope verified but was minted for a different principal,
    /// server, or tool than this retry presents.
    NotForThisRequest,
}

impl ContinuationSealer {
    pub fn new(key: SessionKey) -> Self {
        Self { key }
    }

    /// Wrap an upstream pause's state, and what it asked for, for relay.
    pub fn seal(
        &self,
        principal: &Principal,
        call: &CallIdentity<'_>,
        input_requests: Option<&rmcp::model::InputRequests>,
        upstream_state: Option<String>,
    ) -> Result<String, String> {
        let (keys, file_keys) = issued_keys(input_requests);
        let claims = SealedContinuation {
            sub: principal.sub.clone(),
            iss: principal.issuer.clone(),
            tenant: principal.tenant.as_str().to_owned(),
            server: call.server.to_owned(),
            tool: call.tool.to_owned(),
            args: call.digest.to_owned(),
            contract: call.contract.to_owned(),
            exp: now_unix() + CONTINUATION_TTL_SECONDS,
            keys,
            file_keys,
            inner: upstream_state,
        };
        session::encrypt(&self.key, &claims).map_err(|error| error.to_string())
    }

    /// Verify a caller-presented envelope against this retry, returning the
    /// upstream state to forward and where files may be delivered.
    pub fn open(
        &self,
        principal: &Principal,
        call: &CallIdentity<'_>,
        sealed: &str,
        answered_keys: impl Iterator<Item = String>,
    ) -> Result<VerifiedContinuation, ContinuationError> {
        let claims: SealedContinuation =
            session::decrypt(&self.key, sealed).map_err(|_| ContinuationError::Unverifiable)?;
        let bound = claims.sub == principal.sub
            && claims.iss == principal.issuer
            && claims.tenant == principal.tenant.as_str()
            && claims.server == call.server
            && claims.tool == call.tool
            && claims.args == call.digest
            && claims.contract == call.contract;
        if !bound {
            return Err(ContinuationError::NotForThisRequest);
        }
        // A retry may answer only what this pause asked. Anything else is a
        // response the sealed pause never issued.
        for key in answered_keys {
            if !claims.keys.contains(&key) {
                return Err(ContinuationError::NotForThisRequest);
            }
        }
        Ok(VerifiedContinuation {
            upstream_state: claims.inner,
            deliverable_keys: claims.file_keys,
        })
    }
}

/// Read a relayed pause's shape: every response key it issued, and the
/// subset asked by an elicitation.
fn issued_keys(input_requests: Option<&rmcp::model::InputRequests>) -> (Vec<String>, Vec<String>) {
    let Some(requests) = input_requests else {
        return (Vec::new(), Vec::new());
    };
    let mut keys = Vec::with_capacity(requests.len());
    let mut file_keys = Vec::new();
    for (key, request) in requests {
        keys.push(key.clone());
        if matches!(request, rmcp::model::InputRequest::Elicitation(_)) {
            file_keys.push(key.clone());
        }
    }
    (keys, file_keys)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealer() -> ContinuationSealer {
        ContinuationSealer::new(SessionKey::from_bytes([7u8; 32]))
    }

    fn principal(sub: &str, tenant: &str) -> Principal {
        Principal {
            sub: sub.to_owned(),
            email: None,
            groups: vec![],
            issuer: "https://auth.test".to_owned(),
            scopes: vec![],
            tenant: waygate_core::TenantId::parse(tenant).expect("test tenant id"),
            auth_method: waygate_oidc::AuthMethod::Oauth,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    fn elicit(schema: serde_json::Value) -> rmcp::model::InputRequest {
        serde_json::from_value(serde_json::json!({
            "method": "elicitation/create",
            "params": { "mode": "form", "message": "answer", "requestedSchema": schema }
        }))
        .expect("elicitation request")
    }

    /// A pause asking for one file-valued field and one plain field, exactly
    /// as the upstream authored it.
    fn pause_requests() -> rmcp::model::InputRequests {
        rmcp::model::InputRequests::from([
            (
                "attachment".to_owned(),
                elicit(serde_json::json!({
                    "type": "object",
                    "properties": {
                        "file": {"type": "string", "x-mcp-file": {"transferModes": ["upload"]}}
                    }
                })),
            ),
            (
                "confirm".to_owned(),
                elicit(serde_json::json!({
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}}
                })),
            ),
        ])
    }

    /// Digest of the call a pause was raised for, and of a different call
    /// to the same tool.
    const CALL: &str = "args-v1-digest-of-the-original-call";
    const OTHER_CALL: &str = "args-v1-digest-of-a-different-call";
    /// The admitted contract behind the tool, and a replacement admitted
    /// under the same names.
    const CONTRACT: &str = r#"{"authority":{"catalog":{"tool_id":"t-1"}}}"#;
    const REPLACEMENT_CONTRACT: &str = r#"{"authority":{"catalog":{"tool_id":"t-2"}}}"#;

    fn call<'a>(server: &'a str, tool: &'a str, digest: &'a str) -> CallIdentity<'a> {
        CallIdentity {
            server,
            tool,
            digest,
            contract: CONTRACT,
        }
    }

    fn answered(keys: &[&str]) -> std::vec::IntoIter<String> {
        keys.iter()
            .map(|key| (*key).to_owned())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn upstream_state_round_trips_verbatim_with_the_pause_shape() {
        let sealer = sealer();
        let alice = principal("alice", "acme");
        let requests = pause_requests();
        let sealed = sealer
            .seal(
                &alice,
                &call("printable", "import", CALL),
                Some(&requests),
                Some("upstream-blob".into()),
            )
            .expect("seal");
        assert_ne!(
            sealed, "upstream-blob",
            "the upstream blob must not travel in the clear"
        );

        let verified = sealer
            .open(
                &alice,
                &call("printable", "import", CALL),
                &sealed,
                answered(&["attachment", "confirm"]),
            )
            .expect("verify");
        assert_eq!(verified.upstream_state, Some("upstream-blob".into()));
        // Both keys were asked by an elicitation, so both may carry a file.
        assert_eq!(
            verified.deliverable_keys,
            vec!["attachment".to_owned(), "confirm".to_owned()]
        );
    }

    #[test]
    fn a_pause_without_upstream_state_still_seals() {
        let sealer = sealer();
        let alice = principal("alice", "acme");
        let requests = pause_requests();
        let sealed = sealer
            .seal(
                &alice,
                &call("printable", "import", CALL),
                Some(&requests),
                None,
            )
            .expect("seal");
        let verified = sealer
            .open(
                &alice,
                &call("printable", "import", CALL),
                &sealed,
                answered(&["attachment"]),
            )
            .expect("verify");
        assert_eq!(verified.upstream_state, None);
    }

    #[test]
    fn a_fabricated_or_tampered_envelope_is_refused() {
        let sealer = sealer();
        let alice = principal("alice", "acme");
        let requests = pause_requests();

        assert_eq!(
            sealer.open(
                &alice,
                &call("printable", "import", CALL),
                "not-a-sealed-envelope",
                answered(&[])
            ),
            Err(ContinuationError::Unverifiable)
        );

        let sealed = sealer
            .seal(
                &alice,
                &call("printable", "import", CALL),
                Some(&requests),
                Some("upstream-blob".into()),
            )
            .expect("seal");
        let mut tampered = sealed.clone();
        tampered.pop();
        assert_eq!(
            sealer.open(
                &alice,
                &call("printable", "import", CALL),
                &tampered,
                answered(&[])
            ),
            Err(ContinuationError::Unverifiable)
        );

        let other = ContinuationSealer::new(SessionKey::from_bytes([9u8; 32]));
        assert_eq!(
            other.open(
                &alice,
                &call("printable", "import", CALL),
                &sealed,
                answered(&[])
            ),
            Err(ContinuationError::Unverifiable)
        );
    }

    #[test]
    fn an_envelope_cannot_be_transplanted_across_principal_or_tool() {
        let sealer = sealer();
        let alice = principal("alice", "acme");
        let requests = pause_requests();
        let sealed = sealer
            .seal(
                &alice,
                &call("printable", "import", CALL),
                Some(&requests),
                Some("upstream-blob".into()),
            )
            .expect("seal");

        for (who, server, tool) in [
            (principal("mallory", "acme"), "printable", "import"),
            (principal("alice", "other"), "printable", "import"),
            (principal("alice", "acme"), "printable", "delete_all"),
            (principal("alice", "acme"), "other-server", "import"),
        ] {
            assert_eq!(
                sealer.open(
                    &who,
                    &call(server, tool, CALL),
                    &sealed,
                    answered(&["attachment"])
                ),
                Err(ContinuationError::NotForThisRequest)
            );
        }
    }

    #[test]
    fn a_retry_may_answer_only_what_its_pause_asked() {
        // Replaying a valid envelope with caller-chosen responses is how a
        // file would otherwise be smuggled into a pause that never asked for
        // one; an unissued key is refused outright.
        let sealer = sealer();
        let alice = principal("alice", "acme");
        let requests = pause_requests();
        let sealed = sealer
            .seal(
                &alice,
                &call("printable", "import", CALL),
                Some(&requests),
                None,
            )
            .expect("seal");

        assert_eq!(
            sealer.open(
                &alice,
                &call("printable", "import", CALL),
                &sealed,
                answered(&["attachment", "invented_key"])
            ),
            Err(ContinuationError::NotForThisRequest)
        );
    }

    #[test]
    fn an_envelope_cannot_be_presented_on_a_different_call() {
        // Same principal, same tool, valid unexpired envelope — but a
        // different originating call. Without the argument digest this is
        // the reuse that a per-tool binding alone cannot see.
        let sealer = sealer();
        let alice = principal("alice", "acme");
        let requests = pause_requests();
        let sealed = sealer
            .seal(
                &alice,
                &call("printable", "import", CALL),
                Some(&requests),
                Some("upstream-blob".into()),
            )
            .expect("seal");

        assert_eq!(
            sealer.open(
                &alice,
                &call("printable", "import", OTHER_CALL),
                &sealed,
                answered(&["attachment"])
            ),
            Err(ContinuationError::NotForThisRequest)
        );
    }

    #[test]
    fn an_envelope_for_a_replaced_contract_is_refused() {
        // A catalog or manifest reload can put a different tool behind the
        // same server and tool names while a pause is outstanding. The
        // replacement never issued the elicitation, so it must not inherit
        // the pause and receive the file.
        let sealer = sealer();
        let alice = principal("alice", "acme");
        let requests = pause_requests();
        let sealed = sealer
            .seal(
                &alice,
                &call("printable", "import", CALL),
                Some(&requests),
                Some("upstream-blob".into()),
            )
            .expect("seal");

        let replaced = CallIdentity {
            server: "printable",
            tool: "import",
            digest: CALL,
            contract: REPLACEMENT_CONTRACT,
        };
        assert_eq!(
            sealer.open(&alice, &replaced, &sealed, answered(&["attachment"])),
            Err(ContinuationError::NotForThisRequest)
        );
    }

    #[test]
    fn only_an_elicitation_key_authorizes_a_file() {
        // A pause may ask for sampling or roots alongside an elicitation.
        // Those are answered by the client itself, never by a human choosing
        // a file, so they open no delivery key even though the retry may
        // legitimately answer them.
        let sealer = sealer();
        let alice = principal("alice", "acme");
        let mixed = rmcp::model::InputRequests::from([
            (
                "attachment".to_owned(),
                elicit(serde_json::json!({
                    "type": "object",
                    "properties": {"file": {"type": "string"}}
                })),
            ),
            (
                "summary".to_owned(),
                serde_json::from_value(serde_json::json!({
                    "method": "sampling/createMessage",
                    "params": {
                        "messages": [
                            {"role": "user", "content": {"type": "text", "text": "summarize"}}
                        ],
                        "maxTokens": 16
                    }
                }))
                .expect("sampling request"),
            ),
        ]);
        let sealed = sealer
            .seal(
                &alice,
                &call("printable", "import", CALL),
                Some(&mixed),
                None,
            )
            .expect("seal");

        let verified = sealer
            .open(
                &alice,
                &call("printable", "import", CALL),
                &sealed,
                answered(&["attachment", "summary"]),
            )
            .expect("verify");
        assert_eq!(
            verified.deliverable_keys,
            vec!["attachment".to_owned()],
            "a sampling request authorizes no upload"
        );
    }

    #[test]
    fn a_state_only_pause_authorizes_no_delivery_key() {
        // A pause that issued no input requests opens no key at all, so a
        // retry against it can deliver nothing.
        let sealer = sealer();
        let alice = principal("alice", "acme");
        let sealed = sealer
            .seal(
                &alice,
                &call("printable", "import", CALL),
                None,
                Some("state".into()),
            )
            .expect("seal");

        let verified = sealer
            .open(
                &alice,
                &call("printable", "import", CALL),
                &sealed,
                answered(&[]),
            )
            .expect("verify");
        assert!(
            verified.deliverable_keys.is_empty(),
            "a pause that opened no key can deliver nothing"
        );
    }

    #[test]
    fn an_expired_envelope_is_refused() {
        let sealer = sealer();
        let alice = principal("alice", "acme");
        let expired = SealedContinuation {
            sub: alice.sub.clone(),
            iss: alice.issuer.clone(),
            tenant: alice.tenant.as_str().to_owned(),
            server: "printable".into(),
            tool: "import".into(),
            args: CALL.to_owned(),
            contract: CONTRACT.to_owned(),
            exp: now_unix() - 1,
            keys: vec!["attachment".into()],
            file_keys: vec!["attachment".into()],
            inner: Some("upstream-blob".into()),
        };
        let sealed = session::encrypt(&sealer.key, &expired).expect("seal expired");
        assert_eq!(
            sealer.open(
                &alice,
                &call("printable", "import", CALL),
                &sealed,
                answered(&["attachment"])
            ),
            Err(ContinuationError::Unverifiable)
        );
    }
}
