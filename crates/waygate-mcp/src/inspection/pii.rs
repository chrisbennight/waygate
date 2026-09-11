//! `PiiInspector` — built-in PII response inspector.
//!
//! Scans the upstream response for known PII patterns. On a
//! match, returns [`Decision::Block`] with a reason that names
//! the rule that fired (e.g. `"US_SSN"`) but NEVER the matched
//! payload. The block path is opt-in at boot via
//! `GATEWAY_PII_REDACT=on` so existing deployments see no
//! behavior change until an operator explicitly enables it.
//!
//! ## What "PII" means here
//!
//! A small, opinionated default ruleset: US SSN, US phone, email,
//! credit-card number with Luhn check. The ruleset is hard-coded;
//! per-tenant custom rules (admin REST + `inspection_rules`
//! table) are a planned extension.
//!
//! ## Where it scans
//!
//! - `structured_content` (`Option<Value>`) — walks the JSON
//!   tree, scans every `Value::String` leaf.
//! - `content: Vec<Content>` — for each item that's a `Text`
//!   variant, scans the string. Image / Audio / Resource /
//!   ResourceLink are skipped (binary or pointer; the secret
//!   detector may scan resource URIs).
//!
//! ## Anti-flood
//!
//! Even if a single response contains 100 SSNs, this inspector
//! returns ONE `Decision::Block` (the first match short-circuits
//! the walk). The audit-event flood concern applies more to
//! redaction than to block.
//!
//! ## Regex safety
//!
//! `regex` crate is RE2-derivative: no backtracking, worst-case
//! O(n) match time regardless of input. The `OnceLock`
//! compilation only happens once per process.

use std::sync::OnceLock;

use async_trait::async_trait;
use regex::Regex;
use rmcp::model::CallToolResult;
use serde_json::Value;

use super::{Decision, InspectionContext, Inspector};

const NAME: &str = "pii";

/// Built-in inspector enforcing the default PII ruleset.
///
/// Two modes, both opt-in at the composition root:
///
/// - **Block** (default, `GATEWAY_PII_MODE=block` or unset): on
///   any match, refuse to forward the response with
///   `Decision::Block`. This is the original behavior — preserved
///   so existing deployments under `GATEWAY_PII_REDACT=on`
///   keep blocking.
/// - **Redact** (`GATEWAY_PII_MODE=redact`): forward
///   the response with every match replaced by
///   `[REDACTED:<RULE>]`. `findings_count` reports the total
///   number of replacements so the orchestrator can emit ONE
///   summary audit row per inspection.
#[derive(Debug)]
pub struct PiiInspector {
    redact: bool,
}

impl Default for PiiInspector {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiInspector {
    /// Construct in block mode (the default).
    pub fn new() -> Self {
        Self { redact: false }
    }

    /// Switch the inspector into redaction mode. On match, the
    /// response is forwarded with redactions in place rather
    /// than refused. Operators opt in via
    /// `GATEWAY_PII_MODE=redact`.
    #[must_use]
    pub fn with_redaction(mut self, redact: bool) -> Self {
        self.redact = redact;
        self
    }
}

#[async_trait]
impl Inspector for PiiInspector {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn inspect(&self, _ctx: &InspectionContext<'_>, result: &CallToolResult) -> Decision {
        if self.redact {
            // Cheap scan FIRST so
            // the clean path never pays a clone. Only on a
            // confirmed finding do we pay the
            // `redact_call_tool_result` clone + redact cost.
            // The two-pass cost (scan + redact) only hits the
            // already-rare "matched" path; the common
            // "nothing to redact" path is zero clones, same
            // cost as block mode's fast path.
            if scan_call_tool_result(result).is_none() {
                return Decision::Pass;
            }
            let (redacted, findings_count) = redact_call_tool_result(result);
            if findings_count > 0 {
                return Decision::Redact {
                    redacted,
                    findings_count,
                };
            }
            // Defensive: scan said match, redact said none.
            // Possible if a future rule has different scan vs.
            // redact semantics (e.g. partial-match safe in
            // scan but no redaction applies). Fall through to
            // Pass so we never return Redact{findings_count=0}.
            return Decision::Pass;
        }
        // Block mode (the default behavior):
        // first match → Decision::Block.
        if let Some(rule) = scan_call_tool_result(result) {
            return Decision::Block {
                reason: format!("matched PII rule `{rule}`"),
            };
        }
        Decision::Pass
    }
}

/// Pure helper extracted for testability — returns the first
/// matching rule label, or `None` when the response is clean.
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

fn scan_value(v: &Value) -> Option<&'static str> {
    match v {
        Value::String(s) => scan_text(s),
        Value::Array(arr) => arr.iter().find_map(scan_value),
        Value::Object(obj) => obj.values().find_map(scan_value),
        _ => None,
    }
}

/// Clone-and-redact pass over a `CallToolResult`.
/// Returns the redacted clone + the number of replacements
/// made. Zero replacements ⇒ the orchestrator turns this into
/// `Decision::Pass` (no need to send a clone over the wire
/// when nothing changed).
pub fn redact_call_tool_result(result: &CallToolResult) -> (CallToolResult, u32) {
    let mut findings_count: u32 = 0;
    let mut redacted = result.clone();
    if let Some(sc) = redacted.structured_content.as_mut() {
        findings_count = findings_count.saturating_add(redact_value(sc));
    }
    for content in redacted.content.iter_mut() {
        // Mutate the text in place when the block is a Text variant.
        // Other variants (Image / Audio / Resource / ResourceLink) are
        // skipped — same scope as the scanner.
        if let rmcp::model::ContentBlock::Text(text) = content {
            let (new_text, count) = redact_text(&text.text);
            if count > 0 {
                text.text = new_text;
                findings_count = findings_count.saturating_add(count);
            }
        }
    }
    (redacted, findings_count)
}

/// Walk a serde JSON value and redact every `Value::String`
/// leaf in place. Returns the total number of matches replaced.
fn redact_value(v: &mut Value) -> u32 {
    match v {
        Value::String(s) => {
            let (new_s, count) = redact_text(s);
            if count > 0 {
                *s = new_s;
            }
            count
        }
        Value::Array(arr) => arr.iter_mut().map(redact_value).sum(),
        Value::Object(obj) => obj.values_mut().map(redact_value).sum(),
        _ => 0,
    }
}

/// Apply every PII rule to `text` in turn, replacing each
/// match with `[REDACTED:<RULE>]`. Returns the rebuilt string
/// + the total number of matches replaced across all rules.
///
/// Rule order mirrors [`scan_text`]'s confidence ordering
/// (SSN before CC before email before phone). Each replacement
/// pass operates on the output of the previous, so a string
/// containing both a SSN and an email gets both redacted.
fn redact_text(text: &str) -> (String, u32) {
    let mut working = text.to_owned();
    let mut total: u32 = 0;
    // SSN — honor SSA invalidity filter via captures.
    let (new_s, count) = redact_ssn(&working);
    working = new_s;
    total = total.saturating_add(count);
    // Credit card — honor Luhn check via per-match validation.
    let (new_s, count) = redact_credit_card(&working);
    working = new_s;
    total = total.saturating_add(count);
    // Email — plain regex replace_all.
    let (new_s, count) = redact_with_regex(&working, email_regex(), "EMAIL");
    working = new_s;
    total = total.saturating_add(count);
    // Phone — honor URL/port false-positive filter via
    // captures + window check.
    let (new_s, count) = redact_phone(&working);
    working = new_s;
    total = total.saturating_add(count);
    (working, total)
}

fn redact_with_regex(text: &str, re: &Regex, label: &str) -> (String, u32) {
    let replacement = format!("[REDACTED:{label}]");
    let mut count: u32 = 0;
    let out = re.replace_all(text, |_m: &regex::Captures| {
        count = count.saturating_add(1);
        replacement.clone()
    });
    (out.into_owned(), count)
}

fn redact_ssn(text: &str) -> (String, u32) {
    let replacement = "[REDACTED:US_SSN]".to_owned();
    let mut count: u32 = 0;
    let out = ssn_regex().replace_all(text, |cap: &regex::Captures| {
        // Same invalid-prefix filter as `has_us_ssn` — kills
        // 000-12-3456, 666-12-3456, 9xx-…, …-00-…, …-…0000.
        let a = &cap["a"];
        let b = &cap["b"];
        let c = &cap["c"];
        if a == "000" || a == "666" || a.starts_with('9') || b == "00" || c == "0000" {
            return cap[0].to_owned();
        }
        count = count.saturating_add(1);
        replacement.clone()
    });
    (out.into_owned(), count)
}

fn redact_credit_card(text: &str) -> (String, u32) {
    let replacement = "[REDACTED:CREDIT_CARD]".to_owned();
    let mut count: u32 = 0;
    let out = cc_regex().replace_all(text, |cap: &regex::Captures| {
        let matched = &cap[0];
        let digits: String = matched.chars().filter(|c| c.is_ascii_digit()).collect();
        if (13..=19).contains(&digits.len()) && luhn_check(&digits) {
            count = count.saturating_add(1);
            return replacement.clone();
        }
        matched.to_owned()
    });
    (out.into_owned(), count)
}

fn redact_phone(text: &str) -> (String, u32) {
    let replacement = "[REDACTED:US_PHONE]".to_owned();
    let mut count: u32 = 0;
    // For each match decide whether to replace via the same
    // URL/port window check the scanner uses. Reuses the
    // UTF-8-safe boundary helpers.
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for m in phone_regex().find_iter(text) {
        let start = m.start();
        let end = m.end();
        let window_before = &text[char_boundary_at_or_before(text, start.saturating_sub(4))..start];
        let window_after = &text[end..char_boundary_at_or_after(text, (end + 4).min(text.len()))];
        out.push_str(&text[cursor..start]);
        if window_before.contains(':')
            || window_before.contains('/')
            || window_after.contains(':')
            || window_after.contains('/')
        {
            // URL/port lookalike — leave the match alone.
            out.push_str(&text[start..end]);
        } else {
            out.push_str(&replacement);
            count = count.saturating_add(1);
        }
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    (out, count)
}

/// Run every PII rule against `text`. First match wins; the
/// caller short-circuits.
fn scan_text(text: &str) -> Option<&'static str> {
    if has_us_ssn(text) {
        return Some("US_SSN");
    }
    if has_credit_card(text) {
        return Some("CREDIT_CARD");
    }
    if has_email(text) {
        return Some("EMAIL");
    }
    if has_us_phone(text) {
        return Some("US_PHONE");
    }
    None
}

// --- Rule implementations ---------------------------------------

fn ssn_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"\b(?P<a>\d{3})-(?P<b>\d{2})-(?P<c>\d{4})\b").expect("ssn regex compiles")
    })
}

fn has_us_ssn(text: &str) -> bool {
    for cap in ssn_regex().captures_iter(text) {
        let a = &cap["a"];
        let b = &cap["b"];
        let c = &cap["c"];
        // SSA invalidity table: drops "000-12-3456",
        // "666-12-3456", "9xx-...", "...-00-...", "...-...0000".
        // Kills the most common false positives (test data,
        // sample SSNs in docs that match the regex shape).
        if a == "000" || a == "666" || a.starts_with('9') || b == "00" || c == "0000" {
            continue;
        }
        return true;
    }
    false
}

fn email_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // Single-character TLDs not in current ICANN root; cap
        // at 24 chars to avoid matching `something@host.really-long-string`
        // false positives.
        Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b")
            .expect("email regex compiles")
    })
}

fn has_email(text: &str) -> bool {
    email_regex().is_match(text)
}

fn phone_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // NANP: area code 2-9, exchange 2-9, line 0000-9999.
        // Optional country code (+1 or 1 prefix). Optional
        // parens around area; common separators.
        Regex::new(r"\b(?:\+?1[-.\s]?)?\(?([2-9]\d{2})\)?[-.\s]?([2-9]\d{2})[-.\s]?(\d{4})\b")
            .expect("phone regex compiles")
    })
}

fn has_us_phone(text: &str) -> bool {
    for m in phone_regex().find_iter(text) {
        // False-positive filter: phone-like digit groupings that
        // appear inside URLs or `host:port` strings should not
        // trigger (`http://1.2.3.4:8080`, `host:80`).
        //
        // The 4-byte window must be
        // expanded to the nearest UTF-8 char boundary on both
        // sides. Otherwise a multi-byte prefix character
        // (`éab 212-555-1234`) lands the lower bound INSIDE the
        // `é`, and Rust's `&str` slicing panics. The expansion
        // can only WIDEN the window (operator-friendly: more
        // context, never less); it can never narrow it past the
        // intended ±4-byte minimum.
        let start = m.start();
        let end = m.end();
        let window_before = &text[char_boundary_at_or_before(text, start.saturating_sub(4))..start];
        let window_after = &text[end..char_boundary_at_or_after(text, (end + 4).min(text.len()))];
        if window_before.contains(':')
            || window_before.contains('/')
            || window_after.contains(':')
            || window_after.contains('/')
        {
            continue;
        }
        return true;
    }
    false
}

/// Walk backward from `idx` until we hit a `&str` char boundary
/// (or 0). UTF-8-safe replacement for raw `text[idx..]` slicing
/// when `idx` came from arithmetic that ignored char widths.
fn char_boundary_at_or_before(text: &str, idx: usize) -> usize {
    let mut lo = idx.min(text.len());
    while lo > 0 && !text.is_char_boundary(lo) {
        lo -= 1;
    }
    lo
}

/// Walk forward from `idx` until we hit a `&str` char boundary
/// (or `text.len()`).
fn char_boundary_at_or_after(text: &str, idx: usize) -> usize {
    let mut hi = idx.min(text.len());
    while hi < text.len() && !text.is_char_boundary(hi) {
        hi += 1;
    }
    hi
}

fn cc_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // 13-19 digits with optional spaces or dashes between.
        // Luhn check disambiguates random IDs from real CC
        // numbers.
        Regex::new(r"\b(?:\d[ -]?){13,19}\b").expect("cc regex compiles")
    })
}

fn has_credit_card(text: &str) -> bool {
    for m in cc_regex().find_iter(text) {
        let digits: String = m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
        if (13..=19).contains(&digits.len()) && luhn_check(&digits) {
            return true;
        }
    }
    false
}

/// Mod-10 (Luhn) check used to filter random 16-digit strings
/// (UUID-without-dashes, order numbers, etc.) from real credit
/// card numbers.
fn luhn_check(digits: &str) -> bool {
    if digits.is_empty() {
        return false;
    }
    let mut sum = 0u32;
    let mut alternate = false;
    for ch in digits.chars().rev() {
        let mut d = match ch.to_digit(10) {
            Some(d) => d,
            None => return false,
        };
        if alternate {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        alternate = !alternate;
    }
    sum.is_multiple_of(10)
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

    // --- SSN ---

    #[test]
    fn ssn_matches_canonical_form_in_text() {
        assert_eq!(scan_text("ssn: 123-45-6789 ok"), Some("US_SSN"));
    }

    #[test]
    fn ssn_matches_in_structured_content() {
        let v = serde_json::json!({"profile": {"ssn": "234-56-7890"}});
        assert_eq!(scan_value(&v), Some("US_SSN"));
    }

    #[test]
    fn ssn_skips_invalid_prefixes() {
        // 000, 666, 900-999 prefixes are SSA-invalid → not real
        // SSNs; the inspector skips them.
        assert!(!has_us_ssn("000-12-3456"));
        assert!(!has_us_ssn("666-12-3456"));
        assert!(!has_us_ssn("912-12-3456"));
        // 00 group + 0000 serial are also SSA-invalid.
        assert!(!has_us_ssn("123-00-4567"));
        assert!(!has_us_ssn("123-45-0000"));
        // Sanity: valid form still matches.
        assert!(has_us_ssn("123-45-6789"));
    }

    #[test]
    fn ssn_no_match_in_clean_text() {
        assert!(!has_us_ssn("the order number is 123-45-67890"));
    }

    // --- Credit card / Luhn ---

    #[test]
    fn credit_card_matches_valid_visa() {
        // Visa test number — Luhn-valid by design.
        assert!(has_credit_card("paid with 4111 1111 1111 1111 today"));
    }

    #[test]
    fn credit_card_skips_luhn_failing_digits() {
        // 16 random digits — Luhn fails, not a CC.
        assert!(!has_credit_card("order id 1234567890123456 logged"));
    }

    #[test]
    fn credit_card_matches_no_separators() {
        assert!(has_credit_card("4111111111111111"));
    }

    #[test]
    fn luhn_check_known_vectors() {
        assert!(luhn_check("4111111111111111"));
        assert!(luhn_check("5555555555554444"));
        assert!(luhn_check("378282246310005"));
        assert!(!luhn_check("4111111111111112"));
        assert!(!luhn_check("1234567890123456"));
        assert!(!luhn_check(""));
    }

    // --- Email ---

    #[test]
    fn email_matches_typical_address() {
        assert_eq!(scan_text("contact alice@example.com please"), Some("EMAIL"));
    }

    #[test]
    fn email_no_match_in_clean_text() {
        assert!(!has_email("symbols @ are # important"));
    }

    // --- US phone ---

    #[test]
    fn phone_matches_canonical_forms() {
        assert!(has_us_phone("call 415-555-1234 anytime"));
        assert!(has_us_phone("call (415) 555 1234 anytime"));
        assert!(has_us_phone("call +1 415 555 1234 anytime"));
    }

    #[test]
    fn phone_skips_url_and_port_lookalikes() {
        // IP:port — the digits match the phone regex shape but
        // the surrounding `:` triggers the false-positive
        // filter.
        assert!(!has_us_phone("connect to http://192.168.1.4:8080"));
        assert!(!has_us_phone("server at 555.555.5555:443"));
        // Bare numeric ports in URLs.
        assert!(!has_us_phone("see /api/v1/2125551234"));
    }

    #[test]
    fn phone_skips_invalid_area_codes() {
        // Area code starting with 0 or 1 is invalid NANP.
        assert!(!has_us_phone("dial 015-555-1234"));
        assert!(!has_us_phone("dial 155-555-1234"));
    }

    #[test]
    fn phone_handles_multibyte_utf8_prefix_without_panic() {
        // Regression pin: UTF-8 boundary panic in the scan window.
        //
        // Pre-fix, the 4-byte window before the regex match
        // landed inside the `é` (2-byte UTF-8 sequence) and
        // `&text[lo..start]` panicked with "byte index N is
        // not a char boundary". The post-fix path widens the
        // window to the nearest char boundary, so any
        // upstream string containing non-ASCII characters
        // around a phone-shaped match scans safely.
        //
        // Each case here would have panicked the inspector
        // pre-fix; post-fix they each return a deterministic
        // bool (panic-free is the contract — the bool value
        // is incidental).
        let _ = has_us_phone("éab 212-555-1234");
        let _ = has_us_phone("→← 415-555-1234 →←");
        let _ = has_us_phone("日本語 415-555-1234 日本語");
        // Multi-byte at the boundary of the after-window
        // (end byte close to text.len()).
        let _ = has_us_phone("415-555-1234é");
        // Pure ASCII sanity — fix can't regress the easy path.
        assert!(has_us_phone("call 415-555-1234"));
    }

    #[test]
    fn scan_text_handles_multibyte_utf8_in_full_inspector() {
        // Same UTF-8 stress applied at the top level (the
        // surface the inspector actually exercises). Asserts
        // a deterministic return — pre-fix this panicked
        // through `scan_text` → `has_us_phone` on real
        // upstream responses.
        let _ = scan_text("éab 212-555-1234 normal text");
        let _ = scan_text("日本語 alice@example.com");
        let _ = scan_text("日本語 234-56-7890");
        let _ = scan_text("éab 4111 1111 1111 1111");
    }

    // --- Full CallToolResult coverage ---

    #[test]
    fn clean_response_passes_inspection_with_no_finding() {
        let r = result_with_structured(serde_json::json!({"ok": true, "count": 42}));
        assert_eq!(scan_call_tool_result(&r), None);
    }

    #[test]
    fn structured_content_ssn_triggers_match() {
        let r = result_with_structured(
            serde_json::json!({"profile": {"name": "alice", "ssn": "234-56-7890"}}),
        );
        assert_eq!(scan_call_tool_result(&r), Some("US_SSN"));
    }

    #[test]
    fn text_content_email_triggers_match() {
        let r = result_with_text("response: please contact alice@example.com");
        assert_eq!(scan_call_tool_result(&r), Some("EMAIL"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn inspector_returns_block_with_rule_name_in_reason() {
        let inspector = PiiInspector::new();
        let r = result_with_text("234-56-7890");
        let ctx = InspectionContext {
            tenant: "default",
            principal_sub: Some("alice"),
            server: "example-messages",
            tool: "send",
            risk: waygate_core::RiskTier::Low,
            pii_classified: false,
        };
        let d = inspector.inspect(&ctx, &r).await;
        match d {
            Decision::Block { reason } => {
                assert!(
                    reason.contains("US_SSN"),
                    "reason must name the rule: {reason}"
                );
                // The matched payload MUST NOT appear in the
                // reason — only the rule label.
                assert!(
                    !reason.contains("234-56-7890"),
                    "reason must not leak the matched payload: {reason}",
                );
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn inspector_passes_clean_response() {
        let inspector = PiiInspector::new();
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

    // --- Redaction-mode tests -----------------------------

    fn ctx_default<'a>() -> InspectionContext<'a> {
        InspectionContext {
            tenant: "default",
            principal_sub: Some("alice"),
            server: "tool-server",
            tool: "tool",
            risk: waygate_core::RiskTier::Low,
            pii_classified: false,
        }
    }

    #[test]
    fn redact_ssn_replaces_match_with_label() {
        let (out, count) = redact_text("ssn: 234-56-7890 ok");
        assert_eq!(count, 1, "exactly one redaction");
        assert!(out.contains("[REDACTED:US_SSN]"), "out: {out}");
        // Sanitization: the original SSN MUST NOT survive
        // in the redacted output.
        assert!(!out.contains("234-56-7890"));
    }

    #[test]
    fn redact_ssn_honors_invalid_prefix_filter() {
        // 000 prefix is SSA-invalid — must NOT be redacted.
        let (out, count) = redact_text("test data: 000-12-3456 here");
        assert_eq!(count, 0);
        assert!(out.contains("000-12-3456"), "invalid SSN preserved: {out}");
    }

    #[test]
    fn redact_credit_card_honors_luhn() {
        // Luhn-failing: 16 random digits → NOT redacted.
        let (out, count) = redact_text("order 1234567890123456 placed");
        assert_eq!(count, 0);
        assert!(out.contains("1234567890123456"));
        // Luhn-valid Visa test number → REDACTED.
        let (out, count) = redact_text("paid with 4111 1111 1111 1111 today");
        assert_eq!(count, 1);
        assert!(out.contains("[REDACTED:CREDIT_CARD]"));
        assert!(!out.contains("4111"));
    }

    #[test]
    fn redact_email_replaces_match() {
        let (out, count) = redact_text("contact alice@example.com please");
        assert_eq!(count, 1);
        assert!(out.contains("[REDACTED:EMAIL]"));
        assert!(!out.contains("alice@example.com"));
    }

    #[test]
    fn redact_phone_honors_url_filter() {
        // URL-context phone shape → NOT redacted.
        let (out, count) = redact_text("server at http://1.2.3.4:8080");
        assert_eq!(count, 0);
        assert!(out.contains("1.2.3.4:8080"));
        // Real phone → REDACTED.
        let (out, count) = redact_text("call 415-555-1234 anytime");
        assert_eq!(count, 1);
        assert!(out.contains("[REDACTED:US_PHONE]"));
        assert!(!out.contains("415-555-1234"));
    }

    #[test]
    fn redact_multiple_matches_in_one_string_counts_all() {
        // Email + SSN in the same string.
        let (out, count) = redact_text("user alice@example.com (ssn 234-56-7890) signed up");
        assert_eq!(count, 2, "both findings counted, got {count}: {out}");
        assert!(out.contains("[REDACTED:US_SSN]"));
        assert!(out.contains("[REDACTED:EMAIL]"));
        assert!(!out.contains("alice@example.com"));
        assert!(!out.contains("234-56-7890"));
    }

    #[test]
    fn redact_call_tool_result_walks_structured_and_text() {
        let mut r = result_with_text("see profile alice@example.com for details");
        r.structured_content = Some(serde_json::json!({
            "profile": {"ssn": "234-56-7890"},
            "items": ["phone 415-555-1234"],
        }));
        let (redacted, count) = redact_call_tool_result(&r);
        assert!(count >= 3, "expected ≥3 findings, got {count}");
        // Text content redacted in place.
        let text_redacted = redacted.content[0]
            .as_text()
            .expect("text content")
            .text
            .clone();
        assert!(text_redacted.contains("[REDACTED:EMAIL]"));
        assert!(!text_redacted.contains("alice@example.com"));
        // Structured content recursively walked.
        let sc = redacted.structured_content.as_ref().expect("structured");
        let sc_string = sc.to_string();
        assert!(sc_string.contains("[REDACTED:US_SSN]"));
        assert!(sc_string.contains("[REDACTED:US_PHONE]"));
        assert!(!sc_string.contains("234-56-7890"));
        assert!(!sc_string.contains("415-555-1234"));
    }

    #[test]
    fn redact_clean_response_zero_findings() {
        let r = result_with_structured(serde_json::json!({"weather": "sunny", "temp_c": 22}));
        let (_redacted, count) = redact_call_tool_result(&r);
        assert_eq!(count, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn inspector_with_redaction_returns_redact_on_match() {
        let inspector = PiiInspector::new().with_redaction(true);
        let r = result_with_text("contact alice@example.com please");
        let d = inspector.inspect(&ctx_default(), &r).await;
        match d {
            Decision::Redact {
                redacted,
                findings_count,
            } => {
                assert_eq!(findings_count, 1);
                let text = redacted.content[0].as_text().expect("text").text.clone();
                assert!(text.contains("[REDACTED:EMAIL]"), "got: {text}");
                assert!(!text.contains("alice@example.com"));
            }
            other => panic!("expected Redact, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn inspector_with_redaction_returns_pass_on_clean() {
        // Zero findings in redact mode → Pass, NOT Redact(0).
        // (The orchestrator would otherwise burn a clone for
        // no reason on every clean call.)
        let inspector = PiiInspector::new().with_redaction(true);
        let r = result_with_structured(serde_json::json!({"weather": "sunny"}));
        let d = inspector.inspect(&ctx_default(), &r).await;
        assert!(matches!(d, Decision::Pass));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn inspector_block_mode_unchanged_in_default_path() {
        // Default behavior preserved: `new()` returns
        // Block on match, not Redact. Existing deployments
        // under GATEWAY_PII_REDACT=on (without GATEWAY_PII_MODE=redact)
        // keep blocking.
        let inspector = PiiInspector::new();
        let r = result_with_text("ssn: 234-56-7890");
        let d = inspector.inspect(&ctx_default(), &r).await;
        assert!(matches!(d, Decision::Block { .. }));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn redact_mode_clean_response_passes_without_redact_decision() {
        // Regression pin: a clean
        // response in redact mode must return `Decision::Pass`
        // (the orchestrator skips the per-inspector clone +
        // audit row). Before the scan-before-clone fix, the
        // clean path silently allocated a CallToolResult clone
        // for every successful upstream call when
        // GATEWAY_PII_MODE=redact was set.
        let inspector = PiiInspector::new().with_redaction(true);
        let r = result_with_structured(
            serde_json::json!({"weather": "sunny", "temp_c": 22, "items": [1, 2, 3]}),
        );
        let d = inspector.inspect(&ctx_default(), &r).await;
        assert!(
            matches!(d, Decision::Pass),
            "clean response in redact mode must return Pass, got {d:?}",
        );
    }
}
