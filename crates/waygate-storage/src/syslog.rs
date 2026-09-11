//! RFC 5424 syslog mapping for
//! [`waygate_evidence::audit::AuditEvent`].
//!
//! ## Scope
//!
//! Translates each persisted [`AuditEvent`] into an RFC 5424
//! syslog line. Companion to [`crate::ocsf`] and
//! [`crate::ecs`] — same drain + exporter shape,
//! different wire format. Targets operators with on-prem
//! SIEM stacks fed by syslog (rsyslog, syslog-ng,
//! Sentinel/Splunk syslog forwarders, network-appliance
//! receivers).
//!
//! ## Line shape
//!
//! ```text
//! <priority>1 <ts> <hostname> mcp-gateway <pid> <msgid> [sd-block ...] <msg>
//! ```
//!
//! Where:
//! - `<priority>` = `facility * 8 + severity`. Facility
//!   defaults to `local0` (16) but is configurable via
//!   `GATEWAY_EVIDENCE_SYSLOG_FACILITY`. Severity is derived
//!   from the event's outcome + risk tier (see
//!   [`severity_for`]).
//! - `1` is the RFC 5424 version literal.
//! - `<ts>` is RFC 3339 with microsecond precision.
//! - `<hostname>` is the sender — `mcp-gateway` by default;
//!   the [`audit_event_to_rfc5424`] function takes it as a
//!   parameter so an operator can pass their actual host id.
//! - `<msgid>` carries the gateway category
//!   (`invocation`, `admin_mutation`, ...). RFC 5424 spec
//!   says msgid is a message-type identifier; the category
//!   is the closest gateway analogue and lets SIEM rules
//!   pivot on it without parsing structured-data.
//! - The structured-data section carries
//!   gateway-specific fields under a private-enterprise
//!   namespace. Default PEN is `32473` (the IANA-reserved
//!   "example" PEN per RFC 5612); operators with their own
//!   assigned PEN can override via
//!   `GATEWAY_EVIDENCE_SYSLOG_PEN`.
//! - `<msg>` is a short free-form summary
//!   (`tenant=<t> <action> <outcome>`).
//!
//! ## Out of scope
//!
//! - **TLS.** Plain TCP only. Operators wanting
//!   `syslog+tls://` use stunnel / haproxy / a sidecar in
//!   front of the receiver until a follow-up adds native
//!   rustls handling.
//! - **UDP.** TCP only for retry + ordering. Operators on
//!   UDP-only SIEM stacks have a follow-up here too.

use serde_json::Value;
use time::format_description::well_known::Iso8601;
use uuid::Uuid;

use waygate_core::RiskTier;
use waygate_evidence::audit::{AuditEvent, AuditOutcome, EvidenceCategory};

/// Default facility. `local0` (16) is the conventional
/// "application logs" facility most syslog routing rules
/// already key on. Operators override via env.
pub const DEFAULT_FACILITY: u8 = 16;

/// Default private-enterprise number for structured-data
/// blocks. RFC 5612 reserves `32473` for documentation /
/// testing — using it in production is technically wrong
/// (operators should request their own PEN from IANA) but
/// is widely tolerated by syslog parsers and doesn't break
/// anything. Operators with an assigned PEN override via
/// `GATEWAY_EVIDENCE_SYSLOG_PEN`.
pub const DEFAULT_PEN: u32 = 32_473;

/// Render an `AuditEvent` as a single RFC 5424 line. The
/// returned `String` is one complete syslog message,
/// WITHOUT a trailing newline (the exporter adds framing
/// per RFC 6587 non-transparent-framing convention).
///
/// `event_id` is threaded so the structured-data block
/// carries the gateway's row id for cross-reference back
/// to `audit_log`.
pub fn audit_event_to_rfc5424(
    event_id: Uuid,
    event: &AuditEvent,
    hostname: &str,
    facility: u8,
    pen: u32,
) -> String {
    let severity = severity_for(event.outcome, event.risk_level);
    let priority = (facility as u16) * 8 + (severity as u16);
    let ts = event
        .ts
        .format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| String::from("-"));
    let msgid = event.category.as_str();
    let sd = structured_data(event_id, event, pen);
    let msg = message_summary(event);
    // `<procid>` = `-` (we don't expose a meaningful pid;
    // RFC 5424 lets `-` stand in for "absent").
    format!(
        "<{}>1 {} {} mcp-gateway - {} {} {}",
        priority,
        ts,
        sanitize_field(hostname),
        msgid,
        sd,
        msg,
    )
}

/// Map AuditOutcome + RiskTier → syslog severity (0–7).
///
/// - High-risk denial → 3 (err)
/// - High-risk success → 4 (warning)
/// - Medium-risk denial → 4 (warning)
/// - Medium-risk success → 5 (notice)
/// - Low-risk anything → 6 (info)
/// - No risk + success → 6 (info)
/// - No risk + non-success → 5 (notice)
fn severity_for(outcome: AuditOutcome, risk: Option<RiskTier>) -> u8 {
    let is_failure = !matches!(outcome, AuditOutcome::Success);
    match (risk, is_failure) {
        (Some(RiskTier::High), true) => 3,    // err
        (Some(RiskTier::High), false) => 4,   // warning
        (Some(RiskTier::Medium), true) => 4,  // warning
        (Some(RiskTier::Medium), false) => 5, // notice
        (Some(RiskTier::Low), _) => 6,        // info
        (None, true) => 5,                    // notice
        (None, false) => 6,                   // info
    }
}

/// Build the RFC 5424 structured-data section. RFC 5424
/// SD-ELEMENT is `[SD-ID PARAM-NAME="PARAM-VALUE" ...]`;
/// multiple elements concatenate. Empty SD-block is `-`.
fn structured_data(event_id: Uuid, event: &AuditEvent, pen: u32) -> String {
    let mut blocks: Vec<String> = Vec::new();

    // Always-present gateway-id block.
    let mut gw = format!(
        "[mcp@{} event_id=\"{}\" tenant=\"{}\" outcome=\"{}\"",
        pen,
        event_id,
        escape_param(event.tenant.as_str()),
        event.outcome.as_str(),
    );
    if let Some(risk) = event.risk_level {
        gw.push_str(&format!(
            " risk=\"{}\"",
            match risk {
                RiskTier::High => "high",
                RiskTier::Medium => "medium",
                RiskTier::Low => "low",
            }
        ));
    }
    if let Some(pii) = event.pii {
        gw.push_str(&format!(" pii=\"{}\"", pii));
    }
    if let Some(latency) = event.latency_ms {
        gw.push_str(&format!(" latency_ms=\"{}\"", latency));
    }
    if let Some(trace) = event.trace_id.as_deref() {
        gw.push_str(&format!(" trace_id=\"{}\"", escape_param(trace)));
    }
    gw.push(']');
    blocks.push(gw);

    // Principal block — only when present.
    if let Some(p) = event.principal.as_ref() {
        let mut pr = format!("[principal@{} sub=\"{}\"", pen, escape_param(&p.sub));
        if let Some(email) = p.email.as_deref() {
            pr.push_str(&format!(" email=\"{}\"", escape_param(email)));
        }
        if !p.groups.is_empty() {
            pr.push_str(&format!(
                " groups=\"{}\"",
                escape_param(&p.groups.join(","))
            ));
        }
        pr.push_str(&format!(" issuer=\"{}\"", escape_param(&p.issuer)));
        // SCIM-resolved
        // attributes on the same `principal@` structured-data
        // block. Only emit when set so syslog lines for non-
        // SCIM principals stay byte-identical with their
        // pre-SCIM shape.
        if let Some(active) = p.scim_active {
            pr.push_str(&format!(" scim_active=\"{active}\""));
        }
        if !p.scim_groups.is_empty() {
            pr.push_str(&format!(
                " scim_groups=\"{}\"",
                escape_param(&p.scim_groups.join(","))
            ));
        }
        pr.push(']');
        blocks.push(pr);
    }

    // Tool block — only for tool-call events.
    if let (Some(server), Some(tool)) = (event.server.as_deref(), event.tool.as_deref()) {
        // The operation joins the block it qualifies, and is omitted rather
        // than emitted empty so a tool classified by name alone produces the
        // same block it always has.
        let operation = event.operation.as_deref().map_or_else(String::new, |o| {
            format!(" operation=\"{}\"", escape_param(o))
        });
        blocks.push(format!(
            "[tool@{} server=\"{}\" tool=\"{}\"{}]",
            pen,
            escape_param(server),
            escape_param(tool),
            operation,
        ));
    }

    // Subject block for a decision that names no tool: a native resource read
    // is identified by its URI, and without this such an event exports with no
    // subject at all.
    if event.tool.is_none() {
        if let Some(target) = event.target.as_deref() {
            blocks.push(format!("[target@{} uri=\"{}\"]", pen, escape_param(target),));
        }
    }

    // Policy block — only when policy_ids non-empty.
    if !event.policy_ids.is_empty() {
        blocks.push(format!(
            "[policy@{} ids=\"{}\"]",
            pen,
            escape_param(&event.policy_ids.join(","))
        ));
    }
    if let Some(hierarchy) = event.invocation_hierarchy {
        blocks.push(format!(
            "[execution@{} parent_id=\"{}\" step=\"{}\" call_id=\"{}\" attempt=\"{}\"]",
            pen,
            hierarchy.parent_execution_id,
            hierarchy.step,
            hierarchy.call_id,
            hierarchy.attempt,
        ));
    }

    if blocks.is_empty() {
        "-".to_owned()
    } else {
        blocks.concat()
    }
}

/// RFC 5424 PARAM-VALUE escape: `\`, `"`, `]` must be
/// backslash-escaped within the quoted string.
fn escape_param(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '\\' => vec!['\\', '\\'],
            '"' => vec!['\\', '"'],
            ']' => vec!['\\', ']'],
            // Newlines and tabs would break the
            // single-line message; replace with spaces so
            // a syslog parser doesn't mid-line-split.
            '\n' | '\r' | '\t' => vec![' '],
            other => vec![other],
        })
        .collect()
}

/// RFC 5424 HOSTNAME / APP-NAME / MSGID forbid spaces and
/// most special chars (printable US-ASCII, no whitespace).
/// Replace anything outside that range with `_` so a weird
/// hostname doesn't break parsing.
fn sanitize_field(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_graphic() && c != '[' && c != ']' && c != '"' && c != ' ' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Short free-form message body. Operators dashboarding by
/// message text get something readable; structured rule
/// writing keys on the structured-data block.
///
/// Security: every component
/// that originates outside the gateway (`principal.sub`,
/// `server`, `tool`, `action`) goes through
/// [`sanitize_msg_component`] before interpolation.
/// Without that, a `principal.sub` containing `\n` —
/// JWT-controlled, so attacker-influenceable — would split
/// the RFC 6587 non-transparent frame and inject a forged
/// follow-on syslog line on the receiver.
fn message_summary(event: &AuditEvent) -> String {
    match (event.server.as_deref(), event.tool.as_deref()) {
        (Some(server), Some(tool)) => format!(
            "{} called {}.{} -> {}",
            sanitize_msg_component(
                event
                    .principal
                    .as_ref()
                    .map(|p| p.sub.as_str())
                    .unwrap_or("anonymous")
            ),
            sanitize_msg_component(server),
            sanitize_msg_component(tool),
            event.outcome.as_str(),
        ),
        _ => format!(
            "{} -> {}",
            sanitize_msg_component(&event.action),
            event.outcome.as_str()
        ),
    }
}

/// Security: strip any
/// character that could break the single-line MSG frame
/// or smuggle a control sequence into the SIEM's log
/// parser. ASCII control codes (including `\n`, `\r`,
/// `\t`) collapse to a single space; everything else
/// passes through.
fn sanitize_msg_component(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_control() { ' ' } else { c })
        .collect()
}

/// Suppress unused-import lint when category isn't directly
/// referenced (it's used via `event.category.as_str()` only).
#[allow(dead_code)]
fn _ensure_imports() -> EvidenceCategory {
    EvidenceCategory::Invocation
}

/// Suppress unused-import lint for serde_json::Value
/// (referenced in tests / future structured payloads).
#[allow(dead_code)]
fn _ensure_value_import(_v: Value) {}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;
    use waygate_evidence::audit::AuditPrincipal;

    fn base_event() -> AuditEvent {
        AuditEvent {
            operation: None,
            id: Uuid::from_u128(1),
            ts: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            category: EvidenceCategory::Invocation,
            tenant: waygate_core::TenantId::default(),
            principal: Some(AuditPrincipal {
                sub: "user-123".to_owned(),
                email: Some("user@example.test".to_owned()),
                groups: vec!["mcp-users".to_owned(), "mcp-admins".to_owned()],
                issuer: "https://idp.example.test".to_owned(),
                scim_active: None,
                scim_groups: Vec::new(),
            }),
            action: "CallTool".to_owned(),
            server: Some("example-messages".to_owned()),
            tool: Some("send_message".to_owned()),
            outcome: AuditOutcome::Success,
            risk_level: Some(RiskTier::High),
            pii: Some(true),
            policy_ids: vec!["policy-allow-mcp-users".to_owned()],
            reason: None,
            trace_id: Some("trace-xyz".to_owned()),
            latency_ms: Some(42),
            target: None,
            req_scopes: Vec::new(),
            auth_method: None,
            req_roles: Vec::new(),
            side_effects: None,
            acting_agent: None,
            invocation_hierarchy: None,
        }
    }

    /// Line starts with the priority + version-literal `1`
    /// per RFC 5424; the timestamp follows. All fields
    /// space-separated.
    #[test]
    fn line_starts_with_priority_and_version() {
        let line = audit_event_to_rfc5424(
            Uuid::from_u128(7),
            &base_event(),
            "mcp-gateway",
            DEFAULT_FACILITY,
            DEFAULT_PEN,
        );
        // High-risk success → severity 4. Priority =
        // 16*8 + 4 = 132.
        assert!(line.starts_with("<132>1 "), "{line}");
    }

    /// Severity maps AuditOutcome + RiskTier per the
    /// documented table.
    #[test]
    fn severity_table_matches_docs() {
        // High + denial = err (3)
        assert_eq!(severity_for(AuditOutcome::Denied, Some(RiskTier::High)), 3);
        // High + success = warning (4)
        assert_eq!(severity_for(AuditOutcome::Success, Some(RiskTier::High)), 4);
        // Medium + denial = warning (4)
        assert_eq!(
            severity_for(AuditOutcome::Denied, Some(RiskTier::Medium)),
            4
        );
        // Medium + success = notice (5)
        assert_eq!(
            severity_for(AuditOutcome::Success, Some(RiskTier::Medium)),
            5
        );
        // Low any = info (6)
        assert_eq!(severity_for(AuditOutcome::Success, Some(RiskTier::Low)), 6);
        assert_eq!(severity_for(AuditOutcome::Denied, Some(RiskTier::Low)), 6);
        // None + success = info, None + non-success = notice
        assert_eq!(severity_for(AuditOutcome::Success, None), 6);
        assert_eq!(severity_for(AuditOutcome::Denied, None), 5);
        assert_eq!(severity_for(AuditOutcome::ExecutionError, None), 5);
        assert_eq!(severity_for(AuditOutcome::StepUpRequired, None), 5);
    }

    /// Structured data carries event_id + tenant + outcome
    /// in the always-present `mcp@<pen>` block.
    #[test]
    fn structured_data_always_includes_event_id_and_tenant() {
        let line = audit_event_to_rfc5424(
            Uuid::from_u128(0xDEADBEEF),
            &base_event(),
            "mcp-gateway",
            DEFAULT_FACILITY,
            DEFAULT_PEN,
        );
        assert!(
            line.contains(&format!("event_id=\"{}\"", Uuid::from_u128(0xDEADBEEF))),
            "{line}"
        );
        assert!(line.contains("tenant=\"default\""), "{line}");
        assert!(line.contains("outcome=\"success\""), "{line}");
    }

    #[test]
    fn nested_invocation_hierarchy_has_an_execution_block() {
        use std::num::NonZeroU32;

        let mut event = base_event();
        let hierarchy = waygate_core::InvocationHierarchy::new(
            Uuid::from_u128(10),
            NonZeroU32::new(2).unwrap(),
            Uuid::from_u128(20),
            NonZeroU32::new(3).unwrap(),
        );
        event.invocation_hierarchy = Some(hierarchy);
        let line = audit_event_to_rfc5424(
            event.id,
            &event,
            "mcp-gateway",
            DEFAULT_FACILITY,
            DEFAULT_PEN,
        );

        assert!(line.contains(&format!(
            "[execution@{} parent_id=\"{}\" step=\"2\" call_id=\"{}\" attempt=\"3\"]",
            DEFAULT_PEN, hierarchy.parent_execution_id, hierarchy.call_id
        )));
    }

    /// Principal block only emitted when present; emitted
    /// fields don't include `email` / `groups` when empty.
    #[test]
    fn principal_block_skipped_when_absent() {
        let mut e = base_event();
        e.principal = None;
        let line = audit_event_to_rfc5424(
            Uuid::from_u128(1),
            &e,
            "mcp-gateway",
            DEFAULT_FACILITY,
            DEFAULT_PEN,
        );
        assert!(!line.contains("[principal@"), "{line}");
    }

    /// Tool block only emitted for tool-call events
    /// (server + tool both present).
    #[test]
    fn tool_block_skipped_when_no_tool() {
        let mut e = base_event();
        e.server = None;
        e.tool = None;
        let line = audit_event_to_rfc5424(
            Uuid::from_u128(1),
            &e,
            "mcp-gateway",
            DEFAULT_FACILITY,
            DEFAULT_PEN,
        );
        assert!(!line.contains("[tool@"), "{line}");
    }

    /// Param escape: backslash, quote, close-bracket get
    /// backslash-escaped. Newlines collapse to spaces (a
    /// multi-line value would otherwise break the
    /// single-line message frame).
    #[test]
    fn escape_param_handles_specials() {
        assert_eq!(escape_param(r#"a"b"#), r#"a\"b"#);
        assert_eq!(escape_param(r"a\b"), r"a\\b");
        assert_eq!(escape_param("a]b"), "a\\]b");
        assert_eq!(escape_param("a\nb"), "a b");
    }

    /// Hostname sanitize: spaces / brackets become `_`.
    #[test]
    fn sanitize_hostname_replaces_unsafe_chars() {
        assert_eq!(sanitize_field("ok-host.example.com"), "ok-host.example.com");
        assert_eq!(sanitize_field("bad host"), "bad_host");
        assert_eq!(sanitize_field("bad[host]"), "bad_host_");
    }

    /// Facility override produces a different priority.
    #[test]
    fn facility_override_changes_priority() {
        // local1 = 17. Priority for high-risk success = 17*8 + 4 = 140.
        let line = audit_event_to_rfc5424(
            Uuid::from_u128(1),
            &base_event(),
            "mcp-gateway",
            17,
            DEFAULT_PEN,
        );
        assert!(line.starts_with("<140>1 "), "{line}");
    }

    /// Security: components
    /// interpolated into the MSG body must NOT carry
    /// newlines / CR / tabs / other control codes. An
    /// attacker-controlled `principal.sub` containing
    /// `\n` would split the RFC 6587 non-transparent
    /// frame and inject a forged follow-on syslog line
    /// on the receiver.
    #[test]
    fn msg_body_strips_newlines_to_defeat_frame_injection() {
        let mut e = base_event();
        // Attacker-shaped sub with embedded newline +
        // would-be injected frame on the next "line."
        e.principal = Some(AuditPrincipal {
            sub: "alice\n<37>1 - - mcp-gateway - injection - INJECTED".to_owned(),
            email: None,
            groups: vec![],
            issuer: "https://idp.example.test".to_owned(),
            scim_active: None,
            scim_groups: Vec::new(),
        });
        let line = audit_event_to_rfc5424(
            Uuid::from_u128(1),
            &e,
            "mcp-gateway",
            DEFAULT_FACILITY,
            DEFAULT_PEN,
        );
        // The produced syslog frame MUST be one line
        // (no embedded `\n`) — any newline in `sub` is
        // collapsed to space.
        assert!(
            !line.contains('\n'),
            "MSG must be a single line; got newline in: {line}",
        );
        // Sanity: the sanitised text still appears (with
        // the newline replaced by a space).
        assert!(line.contains("alice <37>1"), "{line}");
    }

    /// Same defence for `server` / `tool` — both flow into
    /// MSG too and both are externally-influenceable.
    #[test]
    fn msg_body_strips_newlines_in_server_and_tool() {
        let mut e = base_event();
        e.server = Some("legit\nINJECTED".to_owned());
        e.tool = Some("send\rmessage".to_owned());
        let line = audit_event_to_rfc5424(
            Uuid::from_u128(1),
            &e,
            "mcp-gateway",
            DEFAULT_FACILITY,
            DEFAULT_PEN,
        );
        assert!(!line.contains('\n'), "{line}");
        assert!(!line.contains('\r'), "{line}");
    }

    /// PEN override changes the SD-element namespace.
    #[test]
    fn pen_override_changes_sd_namespace() {
        let line = audit_event_to_rfc5424(
            Uuid::from_u128(1),
            &base_event(),
            "mcp-gateway",
            DEFAULT_FACILITY,
            99_999,
        );
        assert!(line.contains("[mcp@99999"), "{line}");
        assert!(line.contains("[principal@99999"), "{line}");
        assert!(line.contains("[tool@99999"), "{line}");
    }

    #[test]
    fn the_operation_joins_the_tool_block() {
        let mut event = base_event();
        event.operation = Some("secrets.reveal".to_owned());
        let rendered = audit_event_to_rfc5424(
            Uuid::from_u128(7),
            &event,
            "mcp-gateway",
            DEFAULT_FACILITY,
            DEFAULT_PEN,
        );

        assert!(
            rendered.contains(r#"operation="secrets.reveal""#),
            "the operation belongs in the block that names the tool: {rendered}"
        );
    }

    #[test]
    fn a_row_with_no_operation_emits_the_block_unchanged() {
        let rendered = audit_event_to_rfc5424(
            Uuid::from_u128(7),
            &base_event(),
            "mcp-gateway",
            DEFAULT_FACILITY,
            DEFAULT_PEN,
        );

        assert!(
            !rendered.contains("operation="),
            "an absent operation must not render as an empty parameter: {rendered}"
        );
    }
}
