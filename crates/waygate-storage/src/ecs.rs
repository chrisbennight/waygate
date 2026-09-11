//! Elastic Common Schema (ECS) 8.x mapping
//! for [`waygate_evidence::audit::AuditEvent`].
//!
//! ## Scope
//!
//! Translates each persisted [`AuditEvent`] into the ECS
//! field shape Elasticsearch + Kibana + ELK-stack tools
//! consume natively. Companion to [`crate::ocsf`] —
//! same drain + exporter shape, different schema — for
//! operators whose SIEM is Elastic-native rather than
//! OCSF-aware.
//!
//! ## ECS vs OCSF
//!
//! ECS uses dotted field names (`event.action`,
//! `user.email`, `labels.tool`) whereas OCSF uses nested
//! objects. ECS's `event.category` is a controlled-vocabulary
//! array (`["authentication"]`, `["configuration", "iam"]`),
//! whereas OCSF uses a single `class_uid`. ECS encourages
//! the `labels` object for custom fields; gateway-specific
//! data (tool name, risk tier, PII flag, policy ids,
//! tenant id) lives there.
//!
//! Both exporters can run in parallel — the operator names
//! both `ocsf` and `ecs` in `GATEWAY_EVIDENCE_OUTBOX_TARGETS`,
//! sets the two URLs, and the drain ships each event to both
//! formats. Same atomic-outbox semantics.
//!
//! ## Design choices
//!
//! - **Pure-function mapping.** Same shape as the OCSF
//!   module — `&AuditEvent` in, `serde_json::Value` out. No
//!   I/O. Unit-testable.
//! - **No drops.** Every AuditEvent field is represented
//!   (standard ECS slot when one fits, `labels` when not).
//! - **`@timestamp` is ECS-canonical RFC3339 string**, not
//!   ms-since-epoch like OCSF. ECS parsers everywhere
//!   expect the RFC3339 form.
//! - **`event.category` controlled-vocab array** per ECS spec
//!   so Kibana's pre-built security dashboards key on the
//!   expected values without operator-side mapping.

use serde_json::{json, Value};
use uuid::Uuid;

use waygate_core::RiskTier;
use waygate_evidence::audit::{AuditEvent, AuditOutcome, EvidenceCategory};

/// ECS version we claim in `ecs.version`. Updating implies
/// re-auditing the mapper against ECS field-rename / schema
/// migrations.
pub const ECS_VERSION: &str = "8.11.0";

/// Render one `AuditEvent` as an ECS-shaped record. `event_id`
/// becomes ECS's `event.id`; operators cross-reference back
/// to `audit_log` by UUID without parsing `labels`.
pub fn audit_event_to_ecs(event_id: Uuid, event: &AuditEvent) -> Value {
    let mut record = json!({
        "@timestamp": waygate_core::fmt::format_ts_rfc3339(event.ts),
        "ecs": { "version": ECS_VERSION },
        "event": {
            "id": event_id.to_string(),
            "action": event.action.clone(),
            "category": event_categories_for(event.category),
            "kind": event_kind(event),
            "outcome": ecs_outcome(event.outcome),
            "dataset": "mcp-gateway.audit",
            "module": "mcp-gateway",
            "severity": severity_for(event.risk_level),
        },
        "service": {
            "name": "mcp-gateway",
            "type": "mcp_gateway",
        },
        "labels": build_labels(event),
    });

    if let Some(p) = event.principal.as_ref() {
        // ECS user.* fields. `user.roles` carries groups
        // because Kibana's security UI keys role-based
        // detections on it; ECS uses "roles" as the
        // keyword-array slot regardless of whether the
        // source IdP calls them groups or roles.
        let mut user = serde_json::Map::new();
        user.insert("id".to_owned(), json!(p.sub));
        if let Some(email) = p.email.as_deref() {
            user.insert("email".to_owned(), json!(email));
        }
        if !p.groups.is_empty() {
            user.insert("roles".to_owned(), json!(p.groups));
        }
        user.insert("domain".to_owned(), json!(p.issuer));
        // SCIM-resolved
        // attributes ride on the `user.*` object so Kibana
        // detection rules can gate on `user.scim.active ==
        // false` or `user.scim.groups: "admins"`. ECS doesn't
        // formally define a `scim` sub-record; nested
        // sub-fields work fine in practice (Elastic ignores
        // unknown sub-fields rather than rejecting the
        // document).
        if p.scim_active.is_some() || !p.scim_groups.is_empty() {
            let mut scim = serde_json::Map::new();
            if let Some(active) = p.scim_active {
                scim.insert("active".to_owned(), json!(active));
            }
            if !p.scim_groups.is_empty() {
                scim.insert("groups".to_owned(), json!(p.scim_groups));
            }
            user.insert("scim".to_owned(), Value::Object(scim));
        }
        record["user"] = Value::Object(user);
        // ECS `related.user` is the cross-document
        // correlation slot — Kibana joins documents on
        // `related.user == "<sub>"` for "all events from
        // this user" pivot.
        record["related"] = json!({ "user": [p.sub.clone()] });
    }

    // `event.duration` in ECS is NANOSECONDS (per spec).
    // The gateway records ms, so multiply.
    if let Some(latency_ms) = event.latency_ms {
        record["event"]["duration"] = json!(latency_ms.saturating_mul(1_000_000));
    }

    if let Some(trace_id) = event.trace_id.as_deref() {
        record["trace"] = json!({ "id": trace_id });
    }

    // `event.reason` per ECS spec is the human-readable why
    // for the outcome. Maps directly from the gateway's
    // `reason` field.
    if let Some(reason) = event.reason.as_deref() {
        record["event"]["reason"] = json!(reason);
    }

    record
}

/// ECS `event.category` is a controlled-vocabulary array.
/// Map each gateway category to the closest ECS bucket(s).
/// Multi-value when a single audit event spans two ECS
/// categories (e.g., ApiKeyLifecycle is both `iam` and
/// `authentication`).
fn event_categories_for(category: EvidenceCategory) -> Vec<&'static str> {
    match category {
        EvidenceCategory::Invocation => vec!["process", "session"],
        // An LLM completion is a process/session event like a tool invocation.
        EvidenceCategory::LlmCompletion => vec!["process", "session"],
        EvidenceCategory::Discovery => vec!["session"],
        EvidenceCategory::AdminMutation => vec!["configuration", "iam"],
        EvidenceCategory::AuthAttempt => vec!["authentication"],
        EvidenceCategory::PolicyReload => vec!["configuration"],
        EvidenceCategory::ManifestReload => vec!["configuration"],
        EvidenceCategory::ApiKeyLifecycle => vec!["iam", "authentication"],
        EvidenceCategory::OAuthEvent => vec!["authentication"],
        EvidenceCategory::UpstreamHealth => vec!["process"],
        EvidenceCategory::ApprovalLifecycle => vec!["iam"],
        EvidenceCategory::CatalogDrift => vec!["configuration"],
        EvidenceCategory::DataInspection => vec!["intrusion_detection"],
        EvidenceCategory::FileTransfer => vec!["file"],
        EvidenceCategory::RetentionSweep => vec!["configuration"],
    }
}

/// ECS `event.kind` semantics:
/// - "event" — normal observation.
/// - "alert" — security-significant signal a SIEM should
///   surface to a human (escalations + high-risk denials).
///
/// Map high-risk denials and the security-sensitive
/// categories to "alert"; everything else is "event."
fn event_kind(event: &AuditEvent) -> &'static str {
    let high_severity_denial = matches!(
        (event.outcome, event.risk_level),
        (AuditOutcome::Denied, Some(RiskTier::High))
    );
    let security_category = matches!(
        event.category,
        EvidenceCategory::DataInspection
            | EvidenceCategory::CatalogDrift
            | EvidenceCategory::FileTransfer
    );
    if high_severity_denial || security_category {
        "alert"
    } else {
        "event"
    }
}

/// ECS `event.outcome` is `"success" | "failure" | "unknown"`.
/// AuditOutcome's Denied/ExecutionError/StepUpRequired all
/// map to failure — they're failed dispositions of the call
/// attempt regardless of the specific reason.
fn ecs_outcome(outcome: AuditOutcome) -> &'static str {
    match outcome {
        AuditOutcome::Success => "success",
        AuditOutcome::Denied | AuditOutcome::ExecutionError | AuditOutcome::StepUpRequired => {
            "failure"
        }
    }
}

/// ECS `event.severity` is a long, conventionally 1 (lowest)
/// to 7 (highest). Mapped from RiskTier:
/// High=5, Medium=4, Low=3, None=1.
fn severity_for(risk: Option<RiskTier>) -> u32 {
    match risk {
        Some(RiskTier::High) => 5,
        Some(RiskTier::Medium) => 4,
        Some(RiskTier::Low) => 3,
        None => 1,
    }
}

/// `labels` is ECS's canonical custom-data slot. AI-agent
/// specifics live here so they survive a strict ECS
/// schema validator while remaining queryable in
/// Kibana / Lens.
fn build_labels(event: &AuditEvent) -> Value {
    let mut labels = serde_json::Map::new();
    labels.insert("tenant_id".to_owned(), json!(event.tenant.as_str()));
    labels.insert(
        "gateway_category".to_owned(),
        json!(event.category.as_str()),
    );
    if let (Some(server), Some(tool)) = (event.server.as_deref(), event.tool.as_deref()) {
        labels.insert("tool".to_owned(), json!(format!("{}.{}", server, tool)));
    }
    // The subject of a decision that names no tool, so a native resource read
    // exports identifying the URI it acted on rather than nothing.
    if let Some(target) = event.target.as_deref() {
        labels.insert("target".to_owned(), json!(target));
    }
    // Beside the tool it qualifies: for an executor the tool label is the same
    // for every operation it carries, so a consumer filtering on `tool` alone
    // cannot tell two calls apart.
    if let Some(operation) = event.operation.as_deref() {
        labels.insert("operation".to_owned(), json!(operation));
    }
    if let Some(risk) = event.risk_level {
        labels.insert(
            "risk_level".to_owned(),
            json!(match risk {
                RiskTier::High => "high",
                RiskTier::Medium => "medium",
                RiskTier::Low => "low",
            }),
        );
    }
    if let Some(pii) = event.pii {
        labels.insert("pii".to_owned(), json!(pii));
    }
    if !event.policy_ids.is_empty() {
        labels.insert("policy_ids".to_owned(), json!(event.policy_ids));
    }
    if let Some(hierarchy) = event.invocation_hierarchy {
        labels.insert(
            "parent_execution_id".to_owned(),
            json!(hierarchy.parent_execution_id),
        );
        labels.insert("execution_step".to_owned(), json!(hierarchy.step.get()));
        labels.insert("execution_call_id".to_owned(), json!(hierarchy.call_id));
        labels.insert(
            "execution_attempt".to_owned(),
            json!(hierarchy.attempt.get()),
        );
    }
    Value::Object(labels)
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

    /// ECS required-by-Kibana fields all present and well-typed.
    #[test]
    fn required_ecs_fields_present() {
        let event_id = Uuid::from_u128(0xDEAD_BEEF);
        let r = audit_event_to_ecs(event_id, &base_event());
        // @timestamp is RFC3339 string (ECS-canonical), not
        // ms epoch.
        let ts = r["@timestamp"].as_str().expect("@timestamp is string");
        assert!(ts.starts_with("2023-11-14"), "got {ts}");
        assert_eq!(r["ecs"]["version"], json!("8.11.0"));
        assert_eq!(r["event"]["id"], json!(event_id.to_string()));
        assert_eq!(r["event"]["action"], json!("CallTool"));
        assert_eq!(r["event"]["outcome"], json!("success"));
        assert_eq!(r["event"]["dataset"], json!("mcp-gateway.audit"));
        assert_eq!(r["service"]["name"], json!("mcp-gateway"));
    }

    #[test]
    fn nested_invocation_hierarchy_is_exported_as_labels() {
        use std::num::NonZeroU32;

        let mut event = base_event();
        let hierarchy = waygate_core::InvocationHierarchy::new(
            Uuid::from_u128(10),
            NonZeroU32::new(2).unwrap(),
            Uuid::from_u128(20),
            NonZeroU32::new(3).unwrap(),
        );
        event.invocation_hierarchy = Some(hierarchy);
        let record = audit_event_to_ecs(event.id, &event);

        assert_eq!(
            record["labels"]["parent_execution_id"],
            json!(hierarchy.parent_execution_id)
        );
        assert_eq!(record["labels"]["execution_step"], json!(2));
        assert_eq!(
            record["labels"]["execution_call_id"],
            json!(hierarchy.call_id)
        );
        assert_eq!(record["labels"]["execution_attempt"], json!(3));
    }

    /// `event.category` is a controlled-vocabulary array per
    /// ECS spec. Pin each gateway category's mapping so
    /// pre-built Kibana security dashboards key on the
    /// expected values.
    #[test]
    fn category_maps_to_controlled_vocab_array() {
        let pairs: &[(EvidenceCategory, &[&str])] = &[
            (EvidenceCategory::Invocation, &["process", "session"]),
            (EvidenceCategory::AuthAttempt, &["authentication"]),
            (EvidenceCategory::AdminMutation, &["configuration", "iam"]),
            (
                EvidenceCategory::ApiKeyLifecycle,
                &["iam", "authentication"],
            ),
            (EvidenceCategory::RetentionSweep, &["configuration"]),
            (EvidenceCategory::DataInspection, &["intrusion_detection"]),
        ];
        for (cat, expected) in pairs {
            let v = event_categories_for(*cat);
            assert_eq!(&v, expected, "{cat:?} → {expected:?}");
        }
    }

    /// `event.outcome` is "success" | "failure" | "unknown" per
    /// ECS spec. Every AuditOutcome maps to success or failure;
    /// "unknown" is reserved for "didn't observe" which the
    /// gateway never emits.
    #[test]
    fn outcome_maps_to_ecs_vocabulary() {
        assert_eq!(ecs_outcome(AuditOutcome::Success), "success");
        assert_eq!(ecs_outcome(AuditOutcome::Denied), "failure");
        assert_eq!(ecs_outcome(AuditOutcome::ExecutionError), "failure");
        assert_eq!(ecs_outcome(AuditOutcome::StepUpRequired), "failure");
    }

    /// `event.kind` should be "alert" for security-significant
    /// signals (high-risk denials, security-category events)
    /// so Kibana SIEM rules pick them up; everything else is
    /// "event."
    #[test]
    fn kind_alerts_on_security_significant_signals() {
        // High-risk denial → alert.
        let mut e = base_event();
        e.outcome = AuditOutcome::Denied;
        e.risk_level = Some(RiskTier::High);
        assert_eq!(event_kind(&e), "alert");
        // Same denial at low risk → event.
        e.risk_level = Some(RiskTier::Low);
        assert_eq!(event_kind(&e), "event");
        // DataInspection always alerts (security category).
        let mut di = base_event();
        di.category = EvidenceCategory::DataInspection;
        assert_eq!(event_kind(&di), "alert");
        // Normal invocation success → event.
        assert_eq!(event_kind(&base_event()), "event");
    }

    /// `event.duration` in ECS is NANOSECONDS (per spec).
    /// The gateway records ms; the mapper must multiply.
    #[test]
    fn duration_is_nanoseconds() {
        let r = audit_event_to_ecs(Uuid::from_u128(1), &base_event());
        assert_eq!(r["event"]["duration"], json!(42_000_000i64));
    }

    /// `user.*` populated when principal is present; absent
    /// otherwise. `related.user` carries the sub for SIEM
    /// cross-document correlation pivot.
    #[test]
    fn principal_lands_in_user_and_related_user() {
        let r = audit_event_to_ecs(Uuid::from_u128(1), &base_event());
        assert_eq!(r["user"]["id"], json!("user-123"));
        assert_eq!(r["user"]["email"], json!("user@example.test"));
        assert_eq!(r["user"]["roles"], json!(["mcp-users", "mcp-admins"]));
        assert_eq!(r["user"]["domain"], json!("https://idp.example.test"));
        assert_eq!(r["related"]["user"], json!(["user-123"]));
    }

    /// Principal-less events MUST NOT emit `user` or
    /// `related` — empty objects would break Kibana's
    /// user-pivot filters.
    #[test]
    fn principal_less_event_omits_user_and_related() {
        let mut e = base_event();
        e.principal = None;
        let r = audit_event_to_ecs(Uuid::from_u128(1), &e);
        assert!(r.get("user").is_none(), "{r}");
        assert!(r.get("related").is_none(), "{r}");
    }

    /// AI-agent specifics ride in `labels`. Pinning the
    /// labelset operators will write Kibana queries against.
    #[test]
    fn labels_carry_gateway_specific_fields() {
        let r = audit_event_to_ecs(Uuid::from_u128(1), &base_event());
        assert_eq!(r["labels"]["tenant_id"], json!("default"));
        assert_eq!(r["labels"]["gateway_category"], json!("invocation"));
        assert_eq!(r["labels"]["tool"], json!("example-messages.send_message"));
        assert_eq!(r["labels"]["risk_level"], json!("high"));
        assert_eq!(r["labels"]["pii"], json!(true));
        assert_eq!(r["labels"]["policy_ids"], json!(["policy-allow-mcp-users"]));
    }

    /// Absent optional fields MUST NOT emit empty/null label
    /// entries. Same rationale as the OCSF enrichments
    /// rule — Kibana queries that key on `labels.pii == false`
    /// must distinguish never-recorded from explicitly-false.
    #[test]
    fn labels_skip_absent_optional_fields() {
        let mut e = base_event();
        e.server = None;
        e.tool = None;
        e.risk_level = None;
        e.pii = None;
        e.policy_ids = vec![];
        let r = audit_event_to_ecs(Uuid::from_u128(1), &e);
        let labels = r["labels"].as_object().expect("labels is object");
        assert!(!labels.contains_key("tool"), "{labels:?}");
        assert!(!labels.contains_key("risk_level"), "{labels:?}");
        assert!(!labels.contains_key("pii"), "{labels:?}");
        assert!(!labels.contains_key("policy_ids"), "{labels:?}");
        // tenant_id + gateway_category always present.
        assert!(labels.contains_key("tenant_id"));
        assert!(labels.contains_key("gateway_category"));
    }

    /// `event.reason` (ECS slot) carries the gateway's
    /// `reason` field — denial explanations land in the
    /// operator's primary triage view.
    #[test]
    fn reason_lands_in_event_reason() {
        let mut e = base_event();
        e.outcome = AuditOutcome::Denied;
        e.reason = Some("forbid policies: pii-block".to_owned());
        let r = audit_event_to_ecs(Uuid::from_u128(1), &e);
        assert_eq!(r["event"]["outcome"], json!("failure"));
        assert_eq!(r["event"]["reason"], json!("forbid policies: pii-block"));
    }

    #[test]
    fn the_operation_is_labelled_beside_the_tool() {
        // A consumer filtering on `tool` sees the same value for every
        // operation an executor carries, so the label is what lets it tell two
        // calls apart.
        let mut event = base_event();
        event.operation = Some("secrets.reveal".to_owned());
        let rendered = audit_event_to_ecs(Uuid::from_u128(7), &event);

        assert_eq!(rendered["labels"]["operation"], "secrets.reveal");
        assert_eq!(rendered["labels"]["tool"], "example-messages.send_message");
    }

    #[test]
    fn a_row_with_no_operation_labels_none() {
        // Every row written before the column, and every tool classified by
        // name alone, must render exactly as it did.
        let rendered = audit_event_to_ecs(Uuid::from_u128(7), &base_event());

        assert!(rendered["labels"].get("operation").is_none());
    }
}
