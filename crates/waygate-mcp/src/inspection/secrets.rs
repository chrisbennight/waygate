//! `SecretsInspector` — built-in secret-token response
//! inspector. Composes with the `PiiInspector` via the
//! same `Inspector` trait; both opt-in independently
//! (`GATEWAY_SECRET_REDACT=on` is parallel to `GATEWAY_PII_REDACT`).
//!
//! ## Default ruleset
//!
//! High-confidence string patterns operators almost never want
//! to ship in a tool response:
//!
//! - **AWS_ACCESS_KEY_ID** — `AKIA…` prefix + 16 uppercase
//!   alphanumeric chars. Reserved per AWS docs; near-zero false
//!   positives.
//! - **GITHUB_TOKEN** — `ghp_` / `gho_` / `ghu_` / `ghs_` /
//!   `ghr_` prefix + 36 alphanumeric chars. GitHub's documented
//!   personal-access-token / OAuth-app / user / server / refresh
//!   token formats.
//! - **JWT** — three base64-url segments joined by `.`, header
//!   prefix `eyJ` (the only header `{"alg":…}` can serialize to
//!   in base64). Conservative length floor on each segment so
//!   one-off `foo.bar.baz` strings don't trigger.
//! - **PRIVATE_KEY_PEM** — `-----BEGIN … PRIVATE KEY-----`
//!   header (RSA / EC / DSA / OpenSSH / unqualified).
//! - **STRIPE_KEY** — `sk_live_` / `sk_test_` / `rk_live_` /
//!   `rk_test_` prefix + 24+ alphanumerics (secret and
//!   restricted API keys).
//! - **SLACK_TOKEN** — `xoxb-` / `xoxa-` / `xoxp-` / `xoxr-` /
//!   `xoxs-` prefix (bot / app / user / refresh / session).
//! - **SENDGRID_KEY** — `SG.` + 22-char key id + `.` + 43-char
//!   secret (SendGrid's documented API-key shape).
//! - **TWILIO_API_KEY** — `SK` + 32 lowercase hex.
//! - **GCP_API_KEY** — `AIza` + 35 base64url chars (Google's
//!   documented API-key format).
//! - **AZURE_ACCOUNT_KEY** — `AccountKey=` + 40+ base64 chars
//!   (storage connection strings).
//!
//! Deliberately NOT in the default ruleset:
//!
//! - **AWS secret access keys** (the 40-char base64 paired with
//!   AKIA…). High entropy alone is a noisy signal; doing it
//!   right needs a "near `aws_secret_access_key=` keyword"
//!   heuristic.
//! - **Generic high-entropy detector**. Same noise-floor
//!   concern; a usable version wants per-tenant rule overrides
//!   so operators can tune the entropy threshold.
//!
//! ## Sanitization
//!
//! Same discipline as the PII inspector: the [`Decision::Block`] reason
//! carries ONLY the rule label (e.g. `"matched secret rule
//! \`AWS_ACCESS_KEY_ID\`"`), NEVER the matched token. Logs +
//! audit events + the wire envelope all consume the same
//! sanitized reason.
//!
//! ## Regex safety
//!
//! `regex` crate is RE2-derivative — worst-case O(n), no
//! backtracking. `OnceLock` compiles each pattern once per
//! process.

use std::sync::OnceLock;

use async_trait::async_trait;
use regex::Regex;
use rmcp::model::CallToolResult;
use serde_json::Value;

use super::{Decision, InspectionContext, Inspector};

const NAME: &str = "secrets";

/// Built-in inspector enforcing the default secret-detection
/// ruleset.
#[derive(Default, Debug)]
pub struct SecretsInspector;

impl SecretsInspector {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Inspector for SecretsInspector {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn inspect(&self, _ctx: &InspectionContext<'_>, result: &CallToolResult) -> Decision {
        if let Some(rule) = scan_call_tool_result(result) {
            return Decision::Block {
                reason: format!("matched secret rule `{rule}`"),
            };
        }
        Decision::Pass
    }
}

/// Pure helper extracted for testability. First match short-
/// circuits the walk (anti-flood — one Block per inspection,
/// never N).
pub fn scan_call_tool_result(result: &CallToolResult) -> Option<&'static str> {
    if let Some(sc) = result.structured_content.as_ref() {
        if let Some(rule) = scan_value(sc) {
            return Some(rule);
        }
    }
    for content in &result.content {
        if let Some(text) = content.as_text() {
            if let Some(rule) = scan_text(&text.text) {
                return Some(rule);
            }
        }
    }
    None
}

/// Clone an arbitrary JSON document and replace any string containing a
/// high-confidence secret with a label. Decision previews use this instead of
/// retaining the matched token.
pub fn redact_json_value(value: &Value) -> (Value, u32) {
    let mut redacted = value.clone();
    let findings = redact_value(&mut redacted);
    (redacted, findings)
}

fn redact_value(value: &mut Value) -> u32 {
    match value {
        Value::String(text) => match scan_text(text) {
            Some(rule) => {
                *text = format!("[REDACTED:{rule}]");
                1
            }
            None => 0,
        },
        Value::Array(values) => values.iter_mut().map(redact_value).sum(),
        Value::Object(values) => values.values_mut().map(redact_value).sum(),
        _ => 0,
    }
}

fn scan_value(v: &Value) -> Option<&'static str> {
    match v {
        Value::String(s) => scan_text(s),
        Value::Array(arr) => arr.iter().find_map(scan_value),
        Value::Object(obj) => obj.values().find_map(scan_value),
        _ => None,
    }
}

/// Run every secret rule against `text`. Order: highest-
/// confidence + cheapest first.
fn scan_text(text: &str) -> Option<&'static str> {
    if has_aws_access_key(text) {
        return Some("AWS_ACCESS_KEY_ID");
    }
    if has_github_token(text) {
        return Some("GITHUB_TOKEN");
    }
    if has_jwt(text) {
        return Some("JWT");
    }
    if has_private_key_pem(text) {
        return Some("PRIVATE_KEY_PEM");
    }
    if has_stripe_key(text) {
        return Some("STRIPE_KEY");
    }
    if has_slack_token(text) {
        return Some("SLACK_TOKEN");
    }
    if has_sendgrid_key(text) {
        return Some("SENDGRID_KEY");
    }
    if has_twilio_api_key(text) {
        return Some("TWILIO_API_KEY");
    }
    if has_gcp_api_key(text) {
        return Some("GCP_API_KEY");
    }
    if has_azure_account_key(text) {
        return Some("AZURE_ACCOUNT_KEY");
    }
    None
}

// --- Rule implementations ---------------------------------------

fn aws_access_key_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // `AKIA` is the canonical access-key prefix; `ASIA` is
        // temporary STS session creds (also worth catching).
        Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").expect("aws access key regex compiles")
    })
}

fn has_aws_access_key(text: &str) -> bool {
    aws_access_key_regex().is_match(text)
}

fn github_token_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // GitHub's documented PAT / OAuth / user / server /
        // refresh prefixes. Each is followed by exactly 36
        // alphanumeric chars (per the format spec).
        Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{36}\b").expect("github token regex compiles")
    })
}

fn has_github_token(text: &str) -> bool {
    github_token_regex().is_match(text)
}

fn jwt_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // JWT header is base64-encoded `{"alg":...}` which
        // always starts with `eyJ`. Three segments joined by
        // `.`, base64url alphabet, minimum 10 chars per
        // segment to dodge `eyJ.eyJ.x` false positives. The
        // payload also starts with `eyJ` (it's `{"…":…}`
        // base64-encoded), but that's not part of the pattern
        // (some tokens have stripped payloads in tests).
        Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
            .expect("jwt regex compiles")
    })
}

fn has_jwt(text: &str) -> bool {
    jwt_regex().is_match(text)
}

fn private_key_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // Match the PEM armor line — that's the unambiguous
        // marker. Body content is base64 and varies per key
        // type; the header alone is the high-signal hit.
        Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |)PRIVATE KEY-----")
            .expect("private key regex compiles")
    })
}

fn has_private_key_pem(text: &str) -> bool {
    private_key_regex().is_match(text)
}

fn stripe_key_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // Secret (`sk_`) and restricted (`rk_`) API keys in both
        // modes. Publishable `pk_` keys are not secrets and are
        // deliberately excluded.
        Regex::new(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{24,}\b").expect("stripe key regex compiles")
    })
}

fn has_stripe_key(text: &str) -> bool {
    stripe_key_regex().is_match(text)
}

fn slack_token_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // Bot / app / user / refresh / session token prefixes.
        // Slack token bodies are dash-separated alphanumeric runs;
        // a conservative length floor avoids prose collisions.
        Regex::new(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b").expect("slack token regex compiles")
    })
}

fn has_slack_token(text: &str) -> bool {
    slack_token_regex().is_match(text)
}

fn sendgrid_key_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // SendGrid's documented shape: `SG.` + 22-char key id +
        // `.` + 43-char secret, both base64url.
        Regex::new(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")
            .expect("sendgrid key regex compiles")
    })
}

fn has_sendgrid_key(text: &str) -> bool {
    sendgrid_key_regex().is_match(text)
}

fn twilio_api_key_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // API key SIDs are `SK` + 32 lowercase hex. The lowercase
        // hex body keeps ordinary uppercase prose from matching.
        Regex::new(r"\bSK[0-9a-f]{32}\b").expect("twilio api key regex compiles")
    })
}

fn has_twilio_api_key(text: &str) -> bool {
    twilio_api_key_regex().is_match(text)
}

fn gcp_api_key_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // Google API keys are `AIza` + exactly 35 base64url chars.
        Regex::new(r"\bAIza[0-9A-Za-z_-]{35}\b").expect("gcp api key regex compiles")
    })
}

fn has_gcp_api_key(text: &str) -> bool {
    gcp_api_key_regex().is_match(text)
}

fn azure_account_key_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // Storage connection strings carry `AccountKey=` followed by
        // a long base64 blob. The keyword anchor is what makes this
        // high-confidence; bare base64 alone is the noisy signal the
        // module doc rejects.
        Regex::new(r"AccountKey=[A-Za-z0-9+/=]{40,}").expect("azure account key regex compiles")
    })
}

fn has_azure_account_key(text: &str) -> bool {
    azure_account_key_regex().is_match(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result_with_structured(v: Value) -> CallToolResult {
        let mut r = CallToolResult::success(vec![]);
        r.structured_content = Some(v);
        r
    }

    fn result_with_text(s: &str) -> CallToolResult {
        CallToolResult::success(vec![rmcp::model::ContentBlock::text(s)])
    }

    // --- AWS access keys -------------------------------------

    #[test]
    fn aws_access_key_matches_canonical_akia() {
        assert!(has_aws_access_key("creds: AKIAIOSFODNN7EXAMPLE in env"));
    }

    #[test]
    fn aws_access_key_matches_temporary_asia() {
        // STS session creds use ASIA prefix; just as sensitive.
        assert!(has_aws_access_key("sts session ASIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn aws_access_key_skips_non_aws_lookalike() {
        // Right length but not the AKIA/ASIA prefix.
        assert!(!has_aws_access_key("AKIB".to_owned().repeat(5).as_str()));
        // Lowercase doesn't match (AWS keys are upper).
        assert!(!has_aws_access_key("akiaiosfodnn7example"));
        // Random 20-char uppercase NOT starting with AKIA/ASIA.
        assert!(!has_aws_access_key("ABCDEFGHIJKLMNOPQRST"));
    }

    // --- GitHub tokens ---------------------------------------

    #[test]
    fn github_token_matches_pat_prefix() {
        assert!(has_github_token(
            "use ghp_abcdefghijklmnopqrstuvwxyz0123456789 for auth"
        ));
    }

    #[test]
    fn github_token_matches_other_prefixes() {
        // OAuth app, user-server, server, refresh — all in
        // GitHub's documented format.
        assert!(has_github_token("gho_abcdefghijklmnopqrstuvwxyz0123456789"));
        assert!(has_github_token("ghu_abcdefghijklmnopqrstuvwxyz0123456789"));
        assert!(has_github_token("ghs_abcdefghijklmnopqrstuvwxyz0123456789"));
        assert!(has_github_token("ghr_abcdefghijklmnopqrstuvwxyz0123456789"));
    }

    #[test]
    fn github_token_skips_wrong_length() {
        // Too short — not a valid PAT.
        assert!(!has_github_token("ghp_short"));
        // Too long — also not valid.
        assert!(!has_github_token(
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789TOOLONGNOW"
        ));
    }

    #[test]
    fn github_token_skips_non_token_prefix() {
        assert!(!has_github_token(
            "ghx_abcdefghijklmnopqrstuvwxyz0123456789"
        ));
    }

    // --- JWTs -------------------------------------------------

    #[test]
    fn jwt_matches_canonical_three_segment() {
        // Real-shape JWT (header.payload.signature, all
        // base64url, header starts with eyJ).
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                     eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.\
                     SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert!(has_jwt(&format!("auth: Bearer {token}")));
    }

    #[test]
    fn jwt_skips_short_three_segment_lookalike() {
        // `eyJ.eyJ.x` — matches three-segment shape but each
        // segment is too short to be a real JWT.
        assert!(!has_jwt("eyJ.eyJ.x"));
        // First segment too short:
        assert!(!has_jwt("eyJabc.eyJabcdefghij.signaturebody"));
    }

    #[test]
    fn jwt_skips_non_jwt_three_segment() {
        // Same shape but no `eyJ` prefixes — not a JWT (or at
        // least not one we can distinguish from arbitrary
        // base64-period-separated data).
        assert!(!has_jwt("abc1234567.def1234567.xyz1234567"));
    }

    // --- Private keys ----------------------------------------

    #[test]
    fn private_key_matches_typical_pem_headers() {
        assert!(has_private_key_pem("-----BEGIN RSA PRIVATE KEY-----")); // gitleaks:allow
        assert!(has_private_key_pem("-----BEGIN EC PRIVATE KEY-----")); // gitleaks:allow
        assert!(has_private_key_pem("-----BEGIN PRIVATE KEY-----")); // gitleaks:allow
        assert!(has_private_key_pem("-----BEGIN OPENSSH PRIVATE KEY-----")); // gitleaks:allow
        assert!(has_private_key_pem("-----BEGIN ENCRYPTED PRIVATE KEY-----")); // gitleaks:allow
    }

    #[test]
    fn private_key_skips_public_key_header() {
        // Public keys are not secrets.
        assert!(!has_private_key_pem("-----BEGIN PUBLIC KEY-----"));
        assert!(!has_private_key_pem("-----BEGIN CERTIFICATE-----"));
    }

    // --- Vendor-prefixed API keys ----------------------------

    #[test]
    fn stripe_secret_and_restricted_keys_match_but_publishable_does_not() {
        let secret_key = format!("sk_{}_{}", "live", "a".repeat(24));
        assert!(has_stripe_key(&secret_key));
        assert!(has_stripe_key(
            "rk_test_abcdefghijklmnopqrstuvwx0123" // gitleaks:allow
        ));
        // Publishable keys are shipped to browsers; not a secret.
        assert!(!has_stripe_key("pk_live_abcdefghijklmnopqrstuvwx"));
        assert!(!has_stripe_key("sk_live_short"));
    }

    #[test]
    fn slack_token_prefixes_match_but_prose_does_not() {
        assert!(has_slack_token("xoxb-1234567890-abcdefghijkl"));
        assert!(has_slack_token("xoxp-9876543210-mnopqrstuvwx"));
        assert!(!has_slack_token("xoxz-1234567890-abcdefghijkl"));
        assert!(!has_slack_token("xoxb-short"));
    }

    #[test]
    fn sendgrid_key_matches_documented_shape_only() {
        assert!(has_sendgrid_key(&format!(
            "SG.{}.{}",
            "a".repeat(22),
            "b".repeat(43)
        )));
        assert!(!has_sendgrid_key("SG.tooshort.alsotooshort"));
    }

    #[test]
    fn twilio_api_key_matches_lowercase_hex_body_only() {
        assert!(has_twilio_api_key(&format!("SK{}", "0af1".repeat(8))));
        // Uppercase body — ordinary identifier, not the documented shape.
        assert!(!has_twilio_api_key(&format!("SK{}", "0AF1".repeat(8))));
        assert!(!has_twilio_api_key("SK0123abcd"));
    }

    #[test]
    fn gcp_api_key_matches_aiza_prefix_with_exact_length() {
        assert!(has_gcp_api_key(&format!("AIza{}", "x".repeat(35))));
        assert!(!has_gcp_api_key(&format!("AIza{}", "x".repeat(20))));
    }

    #[test]
    fn azure_account_key_requires_keyword_anchor() {
        let blob = "A".repeat(60);
        assert!(has_azure_account_key(&format!(
            "DefaultEndpointsProtocol=https;AccountKey={blob};EndpointSuffix=core.windows.net"
        )));
        // The same base64 blob without the keyword anchor stays clean —
        // bare high-entropy detection is deliberately out of scope.
        assert!(!has_azure_account_key(&blob));
    }

    // --- Full CallToolResult coverage ------------------------

    #[test]
    fn clean_response_passes_inspection_with_no_finding() {
        let r = result_with_structured(serde_json::json!({"ok": true, "items": [1, 2, 3]}));
        assert_eq!(scan_call_tool_result(&r), None);
    }

    #[test]
    fn aws_key_in_structured_content_triggers_match() {
        let r = result_with_structured(
            serde_json::json!({"profile": {"access_key": "AKIAIOSFODNN7EXAMPLE"}}),
        );
        assert_eq!(scan_call_tool_result(&r), Some("AWS_ACCESS_KEY_ID"),);
    }

    #[test]
    fn github_token_in_text_content_triggers_match() {
        let r = result_with_text(
            "create a webhook with token ghp_abcdefghijklmnopqrstuvwxyz0123456789 please",
        );
        assert_eq!(scan_call_tool_result(&r), Some("GITHUB_TOKEN"));
    }

    #[test]
    fn private_key_in_text_content_triggers_match() {
        let r = result_with_text(
            "host key: \n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA…\n-----END OPENSSH PRIVATE KEY-----\n",
        );
        assert_eq!(scan_call_tool_result(&r), Some("PRIVATE_KEY_PEM"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn inspector_returns_block_with_rule_name_in_reason() {
        let inspector = SecretsInspector::new();
        let r = result_with_text("here's my token ghp_abcdefghijklmnopqrstuvwxyz0123456789 ok?");
        let ctx = InspectionContext {
            tenant: "default",
            principal_sub: Some("alice"),
            server: "github",
            tool: "summarize_repo",
            risk: waygate_core::RiskTier::Low,
            pii_classified: false,
        };
        let d = inspector.inspect(&ctx, &r).await;
        match d {
            Decision::Block { reason } => {
                assert!(
                    reason.contains("GITHUB_TOKEN"),
                    "reason should name the rule: {reason}"
                );
                // Sanitization contract: the matched token MUST
                // NOT appear in the reason. The token here is
                // the canonical-shape one used in the test text.
                assert!(
                    !reason.contains("ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
                    "reason must not leak the matched token: {reason}",
                );
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn inspector_passes_clean_response() {
        let inspector = SecretsInspector::new();
        let r = result_with_structured(serde_json::json!({"weather": "sunny", "temp_c": 22}));
        let ctx = InspectionContext {
            tenant: "default",
            principal_sub: None,
            server: "weather",
            tool: "get",
            risk: waygate_core::RiskTier::Low,
            pii_classified: false,
        };
        assert!(matches!(inspector.inspect(&ctx, &r).await, Decision::Pass));
    }

    #[test]
    fn scan_text_handles_multibyte_utf8_without_panic() {
        // Regex match offsets are
        // bytes; multi-byte UTF-8 around a match must not
        // panic the scanner. Secrets inspector uses
        // `is_match`-only (no byte slicing), so this is a
        // belt-and-suspenders pin against future refactors.
        let _ = scan_text("éab AKIAIOSFODNN7EXAMPLE éab");
        let _ = scan_text("日本語 ghp_abcdefghijklmnopqrstuvwxyz0123456789");
        let _ = scan_text("→← -----BEGIN PRIVATE KEY----- →←");
    }
}
