//! OCSF (Open Cybersecurity Schema Framework)
//! 1.7 mapping for [`waygate_evidence::audit::AuditEvent`].
//!
//! ## Scope
//!
//! Translates each persisted [`AuditEvent`] into the OCSF
//! Application Activity class (`class_uid = 6003`), the
//! well-established catch-all class every OCSF-consuming SIEM
//! (Splunk, Datadog, Sumo, Elastic with OCSF parser) ingests.
//! Activity discriminates within the class via `activity_id`
//! (today: always `6` = Other, with the gateway action carried
//! in `activity_name`); `status_id` + `severity_id` give SIEMs
//! the basic triage fields they expect.
//!
//! AI-agent specifics (tool name, risk tier, PII flag, policy
//! ids) ride in `enrichments` so they survive a strict
//! OCSF-1.7 schema check while remaining queryable in
//! SIEM-side rule writing. OCSF AI-agent extension classes are
//! evolving as a community spec (proposed classes 1002 Agent
//! Event / 1003 Tool Invocation in flight); when those
//! stabilise and SIEMs support them, the mapper can opt
//! Invocation-category events into a more specific class
//! without breaking the existing 6003 path.
//!
//! ## Design choices
//!
//! - **`class_uid = 6003` for every category.** The catch-all
//!   parses everywhere; specific classes (3002 Authentication
//!   for AuthAttempt, 3001 Account Change for ApiKeyLifecycle)
//!   would route nicer in some SIEMs but require operators to
//!   set up parsers per class. The single-class default is
//!   the broadest-compatible starting point.
//! - **Pure-function mapping.** The mapper takes a `&AuditEvent`
//!   and returns `serde_json::Value`. No I/O, no HTTP — those
//!   live in [`crate::exporter::OcsfExporter`]. Pure mapping
//!   keeps the OCSF schema testable without a live endpoint.
//! - **No drops, no normalisation.** Every AuditEvent field
//!   is represented somewhere in the OCSF envelope (standard
//!   slot when one fits; `enrichments` when not). Losing a
//!   field at the exporter would hide it from downstream
//!   SIEM rules forever.

use serde_json::{json, Value};
use uuid::Uuid;

use waygate_core::RiskTier;
use waygate_evidence::audit::{AuditEvent, AuditOutcome, EvidenceCategory};

/// OCSF schema version we claim in `metadata.version`. Updating
/// implies refactoring the mapper if any field semantics changed
/// — keep the constant + the mapper changes together.
pub const OCSF_VERSION: &str = "1.7.0";

/// OCSF `category_uid` 6 = Application Activity.
const OCSF_CATEGORY_UID_APPLICATION_ACTIVITY: u32 = 6;
/// OCSF `class_uid` 6003 = Application Activity.
const OCSF_CLASS_UID_APPLICATION_ACTIVITY: u32 = 6003;
/// `activity_id` 6 = Other (gateway's action string carries
/// the actual verb via `activity_name`).
const OCSF_ACTIVITY_ID_OTHER: u32 = 6;
/// `type_uid` = `class_uid * 100 + activity_id`. Per the OCSF
/// spec, this composite is what most SIEM rule languages
/// pattern-match against.
const OCSF_TYPE_UID_APPLICATION_OTHER: u32 = 600306;

/// Render one `AuditEvent` as an OCSF 1.7 record. `event_id`
/// is threaded through so the OCSF `metadata.uid` matches the
/// gateway's own row id; the SIEM operator can cross-reference
/// back to `audit_log` by UUID without parsing the
/// `enrichments` block.
/// Supports opt-in OWASP Agentic Apps Security (AOS)
/// trace enrichment. When `aos_trace=true`, the OCSF record's
/// `enrichments` array gains an extra block named `aos_trace`
/// (`type: "owasp"`) carrying the agent-action context an
/// AOS-aware SIEM would want to query on: actor chain,
/// fully-qualified tool, risk tier, PII flag, decision +
/// policy ids, latency. Default `false` so existing OCSF
/// consumers see no change.
///
/// The enrichment is *additive* — every previously-emitted
/// field stays in the record at the same path. A SIEM that
/// doesn't understand AOS just sees one more enrichment object
/// and can ignore it; one that does can pick the block out by
/// `enrichments[?(@.name=='aos_trace')]`.
pub fn audit_event_to_ocsf(event_id: Uuid, event: &AuditEvent) -> Value {
    audit_event_to_ocsf_with_options(event_id, event, false)
}

/// Same shape as [`audit_event_to_ocsf`] plus an `aos_trace`
/// toggle. The default exporter constructor enables this when
/// `GATEWAY_OCSF_AOS_TRACE=true`. Pulled into its own function
/// (rather than mutating the existing signature) so the bulk
/// of the mapper stays unchanged + the AOS block is testable
/// in isolation.
pub fn audit_event_to_ocsf_with_options(
    event_id: Uuid,
    event: &AuditEvent,
    aos_trace: bool,
) -> Value {
    let actor = build_actor(event);
    let mut record = json!({
        "metadata": {
            "version": OCSF_VERSION,
            "uid": event_id.to_string(),
            "log_name": "audit_log",
            "product": {
                "name": "mcp-gateway",
                "vendor_name": "Anthropic",
            },
        },
        // OCSF time is ms-since-epoch (per spec). audit_log's
        // `ts` is OffsetDateTime which serialises to RFC3339
        // text by default; OCSF wants the integer. Use
        // `unix_timestamp` + ms remainder so a SIEM time
        // filter on the field works without parsing dates.
        "time": ms_since_epoch(event),
        "category_uid": OCSF_CATEGORY_UID_APPLICATION_ACTIVITY,
        "category_name": "Application Activity",
        "class_uid": OCSF_CLASS_UID_APPLICATION_ACTIVITY,
        "class_name": "Application Activity",
        "activity_id": OCSF_ACTIVITY_ID_OTHER,
        "activity_name": event.action.clone(),
        "type_uid": OCSF_TYPE_UID_APPLICATION_OTHER,
        "type_name": "Application Activity: Other",
        "severity_id": severity_id(event.risk_level),
        "severity": severity_name(event.risk_level),
        "status_id": status_id(event.outcome),
        "status": status_name(event.outcome),
        "actor": actor,
        "app_name": "mcp-gateway",
        "enrichments": build_enrichments(event, aos_trace),
        // OCSF's "unmapped" object is where we stash native
        // gateway fields that don't fit a standard OCSF slot
        // and aren't classified as enrichments. SIEMs that
        // care about the gateway-native shape can lift these;
        // SIEMs that only need OCSF can ignore them.
        "unmapped": {
            "gateway_event_id": event_id.to_string(),
            "gateway_category": event.category.as_str(),
            "tenant_id": event.tenant.as_str(),
        },
    });

    // Server / tool only meaningful for Invocation / Discovery
    // categories. When present, expose as `app_uid` so SIEM
    // dashboards keyed on "which tool" don't need to crack the
    // enrichments array.
    if let (Some(server), Some(tool)) = (event.server.as_deref(), event.tool.as_deref()) {
        record["app_uid"] = json!(format!("{}.{}", server, tool));
    }
    // A decision that names no tool still acted on something — a native
    // resource read is identified by its URI. Without this a `ReadResource`
    // row exports with no subject at all, so a SIEM sees that a resource was
    // decided but not which one.
    if let Some(target) = event.target.as_deref() {
        record["resource_uid"] = json!(target);
    }

    // Duration field aligns with OCSF's `duration` (ms).
    if let Some(latency) = event.latency_ms {
        record["duration"] = json!(latency);
    }

    // Trace id maps to OCSF's `trace_uid` slot.
    if let Some(trace) = event.trace_id.as_deref() {
        record["trace_uid"] = json!(trace);
    }

    // `status_detail` is the OCSF slot for "human-readable why
    // this outcome". The gateway's `reason` field (denial
    // explanation, error message, sweep summary) fits exactly.
    if let Some(reason) = event.reason.as_deref() {
        record["status_detail"] = json!(reason);
    }

    record
}

fn ms_since_epoch(event: &AuditEvent) -> i64 {
    // `unix_timestamp` is seconds; multiply by 1000 and add ms
    // remainder so a SIEM time filter on the OCSF time field
    // is millisecond-accurate (matching what OCSF spec calls
    // for).
    let secs = event.ts.unix_timestamp();
    let nanos = event.ts.nanosecond();
    secs.saturating_mul(1_000) + (nanos as i64) / 1_000_000
}

/// OCSF severity_id scale (per spec):
/// 0=Unknown, 1=Informational, 2=Low, 3=Medium, 4=High,
/// 5=Critical, 6=Fatal, 99=Other.
///
/// Mapping from RiskTier matches how operators routinely think
/// of MCP-tool risk: a `Critical` risk classification is OCSF
/// Critical; informational events (no risk tier) map to
/// Informational, not Unknown — Unknown reads as "tooling
/// couldn't classify" rather than "intentionally low-noise."
fn severity_id(risk: Option<RiskTier>) -> u32 {
    match risk {
        Some(RiskTier::High) => 4,
        Some(RiskTier::Medium) => 3,
        Some(RiskTier::Low) => 2,
        None => 1,
    }
}

fn severity_name(risk: Option<RiskTier>) -> &'static str {
    match risk {
        Some(RiskTier::High) => "High",
        Some(RiskTier::Medium) => "Medium",
        Some(RiskTier::Low) => "Low",
        None => "Informational",
    }
}

/// OCSF status_id: 0=Unknown, 1=Success, 2=Failure, 99=Other.
fn status_id(outcome: AuditOutcome) -> u32 {
    match outcome {
        AuditOutcome::Success => 1,
        AuditOutcome::Denied | AuditOutcome::ExecutionError | AuditOutcome::StepUpRequired => 2,
    }
}

fn status_name(outcome: AuditOutcome) -> &'static str {
    match outcome {
        AuditOutcome::Success => "Success",
        AuditOutcome::Denied | AuditOutcome::ExecutionError | AuditOutcome::StepUpRequired => {
            "Failure"
        }
    }
}

fn build_actor(event: &AuditEvent) -> Value {
    match event.principal.as_ref() {
        Some(p) => {
            let mut user = serde_json::Map::new();
            user.insert("uid".into(), json!(p.sub));
            user.insert("email_addr".into(), json!(p.email));
            user.insert(
                "groups".into(),
                json!(p
                    .groups
                    .iter()
                    .map(|g| json!({ "name": g }))
                    .collect::<Vec<_>>()),
            );
            user.insert("domain".into(), json!(p.issuer));
            // SCIM-resolved
            // attributes belong on the actor's user object so
            // SOC2/AccessReview pipelines can ingest active +
            // group state per-event without joining against the
            // live SCIM store (which may have flipped since).
            // `scim` is a nested sub-record so OCSF schema
            // validators that don't know about it ignore it
            // rather than reject the event.
            if p.scim_active.is_some() || !p.scim_groups.is_empty() {
                let mut scim = serde_json::Map::new();
                if let Some(active) = p.scim_active {
                    scim.insert("active".into(), json!(active));
                }
                if !p.scim_groups.is_empty() {
                    scim.insert(
                        "groups".into(),
                        json!(p
                            .scim_groups
                            .iter()
                            .map(|g| json!({ "name": g }))
                            .collect::<Vec<_>>()),
                    );
                }
                user.insert("scim".into(), Value::Object(scim));
            }
            json!({ "user": Value::Object(user) })
        }
        // OCSF requires `actor` to be an object; an empty
        // `user` block keeps schema validators happy for
        // principal-less events (boot-time policy reloads,
        // background sweeps that ran without a request).
        None => json!({ "user": {} }),
    }
}

fn build_enrichments(event: &AuditEvent, aos_trace: bool) -> Value {
    let mut e: Vec<Value> = Vec::new();
    e.push(json!({
        "name": "audit_category",
        "type": "gateway",
        "data": event.category.as_str(),
    }));
    // The tool name alone does not identify what ran when the tool carries many
    // operations, and the risk beside it describes the operation's
    // classification rather than the tool's.
    if let Some(operation) = event.operation.as_deref() {
        e.push(json!({
            "name": "operation",
            "type": "gateway",
            "data": operation,
        }));
    }
    if let Some(risk) = event.risk_level {
        e.push(json!({
            "name": "risk_level",
            "type": "gateway",
            "data": risk_label(risk),
        }));
    }
    if let Some(pii) = event.pii {
        e.push(json!({
            "name": "pii",
            "type": "gateway",
            "data": pii,
        }));
    }
    if !event.policy_ids.is_empty() {
        e.push(json!({
            "name": "policy_ids",
            "type": "gateway",
            "data": event.policy_ids.clone(),
        }));
    }
    if let Some(hierarchy) = event.invocation_hierarchy {
        e.push(json!({
            "name": "invocation_hierarchy",
            "type": "gateway",
            "data": hierarchy,
        }));
    }
    if aos_trace {
        e.push(build_aos_trace(event));
    }
    json!(e)
}

fn risk_label(risk: RiskTier) -> &'static str {
    match risk {
        RiskTier::High => "high",
        RiskTier::Medium => "medium",
        RiskTier::Low => "low",
    }
}

/// OWASP Agentic Apps Security trace
/// enrichment.
///
/// `name=aos_trace` + `type=owasp` lets a SIEM pluck this block
/// out by JSONPath without parsing every enrichment. The
/// `data` payload is a stable JSON shape; new fields may be
/// added (e.g. `argument_hash`, `approval_grant_id`) but the
/// existing keys stay byte-stable so SIEM rules survive across
/// versions.
///
/// `schema_ref` is the OWASP Agentic AI Top 10 anchor —
/// auditors can cite it directly. The link points to the
/// project landing page, not a specific RC version, so the
/// reference doesn't rot on every OWASP revision.
fn build_aos_trace(event: &AuditEvent) -> Value {
    let principal_sub = event
        .principal
        .as_ref()
        .map(|p| p.sub.as_str())
        .unwrap_or("");
    let principal_issuer = event
        .principal
        .as_ref()
        .map(|p| p.issuer.as_str())
        .unwrap_or("");
    let tool_fq = match (event.server.as_deref(), event.tool.as_deref()) {
        (Some(s), Some(t)) => format!("{s}.{t}"),
        _ => String::new(),
    };
    // The "actor chain" names every identity the call passed
    // through: the human/service principal, then the gateway
    // itself (RFC 8693 `act` semantics). Future hops (a
    // federated peer) would append here. Empty principal_sub
    // means the action ran without a Principal — typically
    // boot-time policy reload or background sweep; we still
    // emit the gateway link so AOS rules that key on "every
    // tool action passes through a gateway" stay true.
    let mut actor_chain: Vec<String> = Vec::new();
    if !principal_sub.is_empty() {
        actor_chain.push(format!("user:{principal_sub}"));
    }
    actor_chain.push("gateway:mcp-gateway".to_owned());
    json!({
        "name": "aos_trace",
        "type": "owasp",
        "data": {
            "principal_sub": principal_sub,
            "principal_issuer": principal_issuer,
            "actor_chain": actor_chain,
            "tool": tool_fq,
            "risk_tier": event.risk_level.map(risk_label).unwrap_or(""),
            "pii_handling": event.pii.unwrap_or(false),
            "decision": match event.outcome {
                AuditOutcome::Success => "success",
                AuditOutcome::Denied => "denied",
                AuditOutcome::StepUpRequired => "step_up_required",
                AuditOutcome::ExecutionError => "execution_error",
            },
            "policy_ids": event.policy_ids.clone(),
            "reason": event.reason.as_deref().unwrap_or(""),
            "latency_ms": event.latency_ms.unwrap_or(0),
            "trace_id": event.trace_id.as_deref().unwrap_or(""),
            "schema_ref": "https://owasp.org/www-project-agentic-ai-top-10/",
        },
    })
}

#[allow(unused_imports)]
fn _ensure_imports_used() {
    let _: EvidenceCategory = EvidenceCategory::Invocation;
}

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

    /// Spec-mandated fields all present + well-typed. SIEM
    /// parsers will reject the record if any of these are
    /// missing or the wrong shape; pin them as a contract.
    #[test]
    fn required_ocsf_fields_present() {
        let event_id = Uuid::from_u128(0xDEAD_BEEF);
        let r = audit_event_to_ocsf(event_id, &base_event());
        assert_eq!(r["metadata"]["version"], json!("1.7.0"));
        assert_eq!(r["metadata"]["uid"], json!(event_id.to_string()));
        assert_eq!(r["category_uid"], json!(6));
        assert_eq!(r["class_uid"], json!(6003));
        assert_eq!(r["type_uid"], json!(600306));
        assert!(r["time"].is_i64());
        assert!(r["actor"]["user"].is_object());
        assert_eq!(r["activity_id"], json!(6));
        assert_eq!(r["activity_name"], json!("CallTool"));
    }

    #[test]
    fn nested_invocation_hierarchy_is_exported_as_enrichment() {
        use std::num::NonZeroU32;

        let mut event = base_event();
        let hierarchy = waygate_core::InvocationHierarchy::new(
            Uuid::from_u128(10),
            NonZeroU32::new(2).unwrap(),
            Uuid::from_u128(20),
            NonZeroU32::new(3).unwrap(),
        );
        event.invocation_hierarchy = Some(hierarchy);
        let record = audit_event_to_ocsf(event.id, &event);
        let enrichment = record["enrichments"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "invocation_hierarchy")
            .expect("hierarchy enrichment");

        assert_eq!(enrichment["data"], json!(hierarchy));
    }

    /// status_id pins the success/failure contract operators
    /// will write SIEM rules against.
    #[test]
    fn status_maps_each_outcome() {
        for (outcome, expected_id) in [
            (AuditOutcome::Success, 1u32),
            (AuditOutcome::Denied, 2),
            (AuditOutcome::ExecutionError, 2),
            (AuditOutcome::StepUpRequired, 2),
        ] {
            assert_eq!(status_id(outcome), expected_id, "{outcome:?}");
        }
    }

    /// severity_id pins the risk tier → OCSF severity mapping.
    /// Operators dashboarding by severity rely on this.
    #[test]
    fn severity_maps_each_risk_tier() {
        for (risk, expected_id) in [
            (Some(RiskTier::High), 4u32),
            (Some(RiskTier::Medium), 3),
            (Some(RiskTier::Low), 2),
            (None, 1),
        ] {
            assert_eq!(severity_id(risk), expected_id, "{risk:?}");
        }
    }

    /// Tool calls expose `app_uid = "<server>.<tool>"` so SIEM
    /// dashboards keyed on "which tool was called" don't need
    /// to crack the enrichments array.
    #[test]
    fn invocation_carries_app_uid() {
        let r = audit_event_to_ocsf(Uuid::from_u128(1), &base_event());
        assert_eq!(r["app_uid"], json!("example-messages.send_message"));
    }

    /// Non-tool-call events (no server/tool) MUST NOT emit
    /// `app_uid` — sending an empty or null app_uid would
    /// pollute SIEM aggregations.
    #[test]
    fn non_tool_event_omits_app_uid() {
        let mut e = base_event();
        e.category = EvidenceCategory::PolicyReload;
        e.server = None;
        e.tool = None;
        let r = audit_event_to_ocsf(Uuid::from_u128(1), &e);
        assert!(r.get("app_uid").is_none(), "{r}");
    }

    /// Principal-less events still emit a well-formed `actor`
    /// (empty user object) — OCSF spec requires the field.
    #[test]
    fn principal_less_event_emits_empty_user() {
        let mut e = base_event();
        e.principal = None;
        let r = audit_event_to_ocsf(Uuid::from_u128(1), &e);
        assert_eq!(r["actor"]["user"], json!({}));
    }

    /// `status_detail` carries the gateway's `reason` field
    /// (denial explanation, error string, sweep summary). SIEM
    /// rules that key on denial reasons would otherwise have
    /// to parse the enrichments array.
    #[test]
    fn reason_lands_in_status_detail() {
        let mut e = base_event();
        e.outcome = AuditOutcome::Denied;
        e.reason = Some("forbid policies: pii-block".to_owned());
        let r = audit_event_to_ocsf(Uuid::from_u128(1), &e);
        assert_eq!(r["status_id"], json!(2));
        assert_eq!(r["status"], json!("Failure"));
        assert_eq!(r["status_detail"], json!("forbid policies: pii-block"));
    }

    /// Enrichments include category + risk + pii + policy_ids
    /// when present. Empty fields are SKIPPED — a present-but-
    /// null `pii` enrichment would mis-route SIEM rules.
    #[test]
    fn enrichments_carry_gateway_specific_fields() {
        let r = audit_event_to_ocsf(Uuid::from_u128(1), &base_event());
        let names: Vec<&str> = r["enrichments"]
            .as_array()
            .expect("enrichments is array")
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"audit_category"), "{names:?}");
        assert!(names.contains(&"risk_level"), "{names:?}");
        assert!(names.contains(&"pii"), "{names:?}");
        assert!(names.contains(&"policy_ids"), "{names:?}");
    }

    /// Optional fields absent on the event MUST NOT emit
    /// empty/null enrichment entries. Otherwise a SIEM rule
    /// querying `enrichments[?(@.name == "pii")].data == false`
    /// would match events where pii was never recorded vs
    /// events explicitly recorded as false.
    #[test]
    fn enrichments_skip_absent_optional_fields() {
        let mut e = base_event();
        e.risk_level = None;
        e.pii = None;
        e.policy_ids = vec![];
        let r = audit_event_to_ocsf(Uuid::from_u128(1), &e);
        let names: Vec<&str> = r["enrichments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["audit_category"], "only category should remain");
    }

    /// `time` is ms-since-epoch (OCSF spec requirement). A
    /// SIEM operator filtering on `time >= now - 1h` expects
    /// the integer-ms shape, not RFC3339 text.
    #[test]
    fn time_is_ms_since_epoch() {
        let r = audit_event_to_ocsf(Uuid::from_u128(1), &base_event());
        // 1_700_000_000 seconds * 1000 = 1_700_000_000_000 ms.
        assert_eq!(r["time"], json!(1_700_000_000_000i64));
    }

    // AOS trace enrichment is opt-in.

    fn aos_block(r: &Value) -> Option<&Value> {
        r["enrichments"]
            .as_array()?
            .iter()
            .find(|x| x["name"] == "aos_trace")
    }

    #[test]
    fn aos_trace_is_absent_by_default() {
        // Default path (no aos_trace arg) must never include
        // the enrichment — existing SIEMs would otherwise
        // see schema noise on first upgrade after this PR.
        let r = audit_event_to_ocsf(Uuid::from_u128(1), &base_event());
        assert!(
            aos_block(&r).is_none(),
            "aos_trace must be opt-in; default path emitted it"
        );
    }

    #[test]
    fn aos_trace_when_enabled_carries_actor_chain_tool_decision() {
        let r = audit_event_to_ocsf_with_options(Uuid::from_u128(1), &base_event(), true);
        let aos = aos_block(&r).expect("aos_trace block must be present when enabled");
        assert_eq!(aos["type"], json!("owasp"));
        let data = &aos["data"];
        assert_eq!(data["principal_sub"], json!("user-123"));
        assert_eq!(data["principal_issuer"], json!("https://idp.example.test"));
        assert_eq!(
            data["actor_chain"],
            json!(["user:user-123", "gateway:mcp-gateway"]),
            "actor_chain must name human first, gateway as RFC 8693 act, in that order"
        );
        assert_eq!(data["tool"], json!("example-messages.send_message"));
        assert_eq!(data["risk_tier"], json!("high"));
        assert_eq!(data["pii_handling"], json!(true));
        assert_eq!(data["decision"], json!("success"));
        assert_eq!(
            data["policy_ids"],
            json!(["policy-allow-mcp-users".to_owned()])
        );
        assert_eq!(data["latency_ms"], json!(42));
        assert_eq!(data["trace_id"], json!("trace-xyz"));
        assert_eq!(
            data["schema_ref"],
            json!("https://owasp.org/www-project-agentic-ai-top-10/")
        );
    }

    #[test]
    fn aos_trace_denied_decision_serialises_lowercase() {
        let mut e = base_event();
        e.outcome = AuditOutcome::Denied;
        let r = audit_event_to_ocsf_with_options(Uuid::from_u128(1), &e, true);
        assert_eq!(aos_block(&r).unwrap()["data"]["decision"], json!("denied"));
    }

    #[test]
    fn aos_trace_principal_less_event_still_has_gateway_link() {
        // Background sweeps / boot-time policy reloads have
        // no Principal. The AOS chain must still be emitted
        // (with just `gateway:mcp-gateway`) so AOS rules
        // keyed on "every action passes through a gateway"
        // stay true.
        let mut e = base_event();
        e.principal = None;
        e.server = None;
        e.tool = None;
        let r = audit_event_to_ocsf_with_options(Uuid::from_u128(1), &e, true);
        let aos = aos_block(&r).unwrap();
        assert_eq!(aos["data"]["principal_sub"], json!(""));
        assert_eq!(aos["data"]["actor_chain"], json!(["gateway:mcp-gateway"]));
        assert_eq!(aos["data"]["tool"], json!(""));
    }

    #[test]
    fn aos_trace_does_not_displace_existing_enrichments() {
        // Append-only contract: enabling AOS must NOT remove
        // or reorder the existing enrichment blocks. SIEM
        // rules that already key on `audit_category` /
        // `risk_level` / `pii` / `policy_ids` keep working.
        let r = audit_event_to_ocsf_with_options(Uuid::from_u128(1), &base_event(), true);
        let names: Vec<&str> = r["enrichments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec![
                "audit_category",
                "risk_level",
                "pii",
                "policy_ids",
                "aos_trace",
            ],
            "AOS must be appended last; existing order must be preserved"
        );
    }

    #[test]
    fn the_operation_is_enriched() {
        let mut event = base_event();
        event.operation = Some("secrets.reveal".to_owned());
        let rendered = audit_event_to_ocsf(Uuid::from_u128(7), &event);

        let found = rendered["enrichments"]
            .as_array()
            .expect("enrichments is an array")
            .iter()
            .any(|e| e["name"] == "operation" && e["data"] == "secrets.reveal");
        assert!(found, "the operation must be enriched: {rendered}");
    }

    #[test]
    fn a_row_with_no_operation_enriches_none() {
        let rendered = audit_event_to_ocsf(Uuid::from_u128(7), &base_event());

        let found = rendered["enrichments"]
            .as_array()
            .expect("enrichments is an array")
            .iter()
            .any(|e| e["name"] == "operation");
        assert!(!found, "an absent operation must add no enrichment");
    }
}
