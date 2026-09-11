//! Webhook implementation of the out-of-band change-request notifier
//! for the HITL control plane.
//!
//! POSTs an operator-safe JSON summary to a configured webhook
//! (`GATEWAY_HITL_WEBHOOK_URL`) when an agent proposes a change. The webhook
//! is the integration seam for "away from the desk" delivery — point it at a
//! Signal/SMTP/Slack relay, an alerting pipeline, or a custom handler. The
//! body carries only the summary + a deep link (see
//! [`waygate_admin::change_notify`]); it is a *link, never an approve button*,
//! and never includes the proposed params or justification.
//!
//! Lives in `waygate-server` (the composition root) rather than
//! `waygate-admin`: it needs `reqwest`, and the REST/dashboard crate
//! deliberately stays HTTP-client-free — the same reason the rmcp-typed MCP
//! adapter lives here. The trait it implements is defined in `waygate-admin`
//! alongside `propose_core`, which fires it.

use std::time::Duration;

use serde_json::json;

use waygate_admin::change_notify::{ChangeProposedNotification, ChangeRequestNotifier};
use waygate_core::fmt::format_ts_rfc3339;
use waygate_core::http_client::{self, Profile};

/// Per-request webhook timeout. A slow endpoint must not pile up spawned
/// tasks; 10s matches the evidence `WebhookExporter`.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Fire-and-forget webhook notifier. `notify_change_proposed` spawns the POST
/// and returns immediately; the propose path never blocks on or fails for
/// delivery.
pub struct WebhookChangeNotifier {
    client: reqwest::Client,
    url: String,
}

impl WebhookChangeNotifier {
    /// Validate the URL (parse + http/https scheme) at construction, matching
    /// the evidence `WebhookExporter` — a malformed or unsupported scheme is
    /// rejected up front rather than burning best-effort POST attempts on
    /// every propose. The error string deliberately echoes only the parse
    /// failure / scheme, never the raw URL (which may carry credentials).
    /// Returns `Err` so the composition root can disable the notifier with a
    /// warning instead of crashing boot.
    pub fn new(url: String) -> Result<Self, String> {
        let parsed = reqwest::Url::parse(&url).map_err(|e| format!("webhook URL parse: {e}"))?;
        match parsed.scheme() {
            "http" | "https" => {}
            other => return Err(format!("webhook URL must be http or https, got `{other}`")),
        }
        let client = http_client::builder(Profile::Custom(TIMEOUT))
            .build()
            .map_err(|e| format!("webhook client build: {e}"))?;
        Ok(Self { client, url })
    }

    /// Build the JSON body. Pure (no I/O) so it is unit-testable. Carries ONLY
    /// the operator-safe summary + deep link from the payload — there is no
    /// path by which the proposed params or justification could appear,
    /// because [`ChangeProposedNotification`] does not carry them.
    fn body(payload: &ChangeProposedNotification) -> serde_json::Value {
        json!({
            "event": "change_request.proposed",
            "tenant_id": payload.tenant_id,
            "change_request_id": payload.change_request_id,
            "action_type": payload.action_type,
            "requested_by": payload.requested_by,
            "binding_code": payload.binding_code,
            "expires_at": format_ts_rfc3339(payload.expires_at),
            "approval_url": payload.approval_url,
        })
    }
}

impl ChangeRequestNotifier for WebhookChangeNotifier {
    fn notify_change_proposed(&self, payload: ChangeProposedNotification) {
        let client = self.client.clone();
        let url = self.url.clone();
        let id = payload.change_request_id;
        let body = Self::body(&payload).to_string();
        // Fire-and-forget: a delivery failure is logged at warn and dropped —
        // the change still sits in the dashboard review queue regardless.
        tokio::spawn(async move {
            let sent = client
                .post(&url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body)
                .send()
                .await;
            match sent {
                Ok(resp) if resp.status().is_success() => {
                    tracing::debug!(change_request_id = %id, "HITL change-notify webhook delivered");
                }
                Ok(resp) => {
                    tracing::warn!(
                        change_request_id = %id,
                        status = %resp.status(),
                        "HITL change-notify webhook returned non-2xx",
                    );
                }
                Err(e) => {
                    // `reqwest::Error`'s Display includes the request URL,
                    // which would leak a credential-bearing
                    // GATEWAY_HITL_WEBHOOK_URL into the log on every transient
                    // failure. `without_url()` strips it, leaving a useful
                    // diagnostic ("connection timed out", "DNS failure")
                    // without the credential tail — matching the evidence
                    // WebhookExporter.
                    tracing::warn!(
                        change_request_id = %id,
                        error = %e.without_url(),
                        "HITL change-notify webhook delivery failed",
                    );
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn payload() -> ChangeProposedNotification {
        let change_request_id = Uuid::from_u128(0x1234_5678);
        ChangeProposedNotification {
            tenant_id: "acme".into(),
            change_request_id,
            action_type: "rate_limit.update".into(),
            requested_by: "agent-1".into(),
            binding_code: "AMBER-OTTER".into(),
            expires_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            approval_url: format!(
                "https://gw.example/admin/changes?pending_id={change_request_id}#change-{change_request_id}"
            ),
        }
    }

    #[test]
    fn body_carries_only_the_operator_safe_summary() {
        let body = WebhookChangeNotifier::body(&payload());
        assert_eq!(body["event"], "change_request.proposed");
        assert_eq!(body["tenant_id"], "acme");
        assert_eq!(body["action_type"], "rate_limit.update");
        assert_eq!(body["requested_by"], "agent-1");
        assert_eq!(body["binding_code"], "AMBER-OTTER");
        let change_request_id = payload().change_request_id;
        assert_eq!(
            body["approval_url"],
            format!(
                "https://gw.example/admin/changes?pending_id={change_request_id}#change-{change_request_id}"
            )
        );
        assert_eq!(body["expires_at"], "2023-11-14T22:13:20Z");
    }

    #[test]
    fn new_validates_scheme_and_rejects_non_http() {
        // http/https accepted; everything else (file:, data:, a bare string)
        // rejected at construction, matching the evidence WebhookExporter.
        assert!(WebhookChangeNotifier::new("https://hooks.example/x".into()).is_ok());
        assert!(WebhookChangeNotifier::new("http://localhost:9000/h".into()).is_ok());
        assert!(WebhookChangeNotifier::new("file:///etc/passwd".into()).is_err());
        assert!(WebhookChangeNotifier::new("not a url".into()).is_err());
        // The error string must not echo a credential-bearing URL — only the
        // scheme / parse failure. (Matched, not `.expect_err()`, because the
        // Ok type deliberately doesn't derive Debug — it holds the URL.)
        let err = match WebhookChangeNotifier::new("ftp://user:secret@host/x".into()) {
            Err(e) => e,
            Ok(_) => panic!("ftp must be rejected"),
        };
        assert!(
            !err.contains("secret"),
            "error must not echo the URL: {err}"
        );
    }

    #[test]
    fn body_never_carries_params_or_justification() {
        // The notification is a heads-up + deep link, NOT a carrier for the
        // sensitive proposal detail. Defense-in-depth assertion of the
        // payload contract (the struct has no such fields, so this can only
        // regress if someone widens `body`).
        let body = WebhookChangeNotifier::body(&payload());
        let keys: Vec<&str> = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert!(
            !keys.contains(&"params"),
            "proposed params must never be in the notification: {keys:?}"
        );
        assert!(
            !keys.contains(&"justification"),
            "justification must never be in the notification: {keys:?}"
        );
    }
}
