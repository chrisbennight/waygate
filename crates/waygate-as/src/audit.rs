//! `OAuthEvent`-category audit emission for `/oauth/token` and
//! `/oauth/callback`.
//!
//! The two endpoints are the gateway's bearer-credential mint, so every
//! outcome — success and rejection — produces a durable `audit_log` row
//! plus the existing `tracing` line (`/oauth/token rejected`, etc.).
//! The tracing pipeline is the operational signal; the audit row is
//! compliance-grade evidence the admin Activity feed and the
//! OCSF/syslog/S3 exporters key off.
//!
//! Chained best effort reflects the intended posture: successful rows extend
//! the tenant evidence chain, while an audit outage must not make a successful
//! token mint fail.

use waygate_evidence::audit::SharedEvidence;
use waygate_evidence::{AuditEvent, AuditOutcome, EvidenceCategory};

/// Compact "what subject did what client do" payload, formatted into
/// `AuditEvent.reason`. Keeping these on the row lets an investigator
/// pivot from a `/admin/activity` entry to "every OAuth event for
/// `client_id=codex sub=alice@…` in the last hour" without joining
/// other tables.
pub(crate) struct OauthFacts<'a> {
    pub action: &'static str,
    pub outcome: AuditOutcome,
    pub client_id: Option<&'a str>,
    pub sub: Option<&'a str>,
    pub grant_type: Option<&'a str>,
    pub detail: Option<&'a str>,
}

pub(crate) async fn record(evidence: &SharedEvidence, facts: OauthFacts<'_>) {
    evidence
        .record_chained_best_effort(
            AuditEvent::new(facts.action, facts.outcome)
                .with_category(EvidenceCategory::OAuthEvent)
                .with_reason(format_reason(&facts)),
        )
        .await;
}

fn format_reason(f: &OauthFacts<'_>) -> String {
    // Stable key=value shape so the admin Activity drawer and downstream
    // OCSF/syslog exporters can parse it without a JSON wrapper. Missing
    // fields are rendered as `?` rather than omitted so the column
    // positions stay stable across grant types.
    let client = f.client_id.unwrap_or("?");
    let sub = f.sub.unwrap_or("?");
    let grant = f.grant_type.unwrap_or("?");
    match f.detail {
        Some(d) => format!("client_id={client} sub={sub} grant={grant} detail={d}"),
        None => format!("client_id={client} sub={sub} grant={grant}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use waygate_evidence::audit::{EvidencePosture, InMemorySink};

    #[tokio::test]
    async fn oauth_events_use_chained_best_effort() {
        let sink = Arc::new(InMemorySink::new());
        let evidence: SharedEvidence = sink.clone();
        record(
            &evidence,
            OauthFacts {
                action: "OAuthTokenIssued",
                outcome: AuditOutcome::Success,
                client_id: Some("client"),
                sub: Some("subject"),
                grant_type: Some("authorization_code"),
                detail: None,
            },
        )
        .await;

        let rows = sink.snapshot_with_posture().await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].posture, EvidencePosture::ChainedBestEffort);
        assert_eq!(rows[0].event.category, EvidenceCategory::OAuthEvent);
    }
}
