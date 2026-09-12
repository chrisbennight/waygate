//! Per-target evidence exporter trait + registry.
//!
//! The drain worker (`crate::drain`) walks
//! [`crate::outbox::dequeue_ready`] batches and dispatches each
//! row to the [`Exporter`] registered for its `target_sink`
//! identifier. Supported implementations are [`WebhookExporter`],
//! [`OcsfExporter`], [`EcsExporter`], and [`SyslogExporter`]. The composition
//! root registers configured sinks; exporters return typed retryable or
//! permanent errors to the drain worker.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;
use waygate_core::http_client::{self, Profile};

/// One shipping attempt's outcome. `Transient` flows back into
/// the outbox as `failed` with a fresh `next_attempt` (the
/// drain retries); `Permanent` flows straight to `dead_letter`
/// (the exporter declared the row unrecoverable — e.g., the
/// remote returned 400 with "malformed payload"; no amount of
/// retry will fix that).
#[derive(Debug, Error)]
pub enum ExportError {
    /// Retry after backoff. Network blip, 5xx, rate limit, etc.
    #[error("transient export failure: {0}")]
    Transient(String),
    /// Don't retry — the row is unshippable. 4xx on a
    /// well-formed payload, schema rejection by the remote, etc.
    #[error("permanent export failure: {0}")]
    Permanent(String),
}

/// Delivery contract for a configured evidence sink. `target_sink` identifies
/// the destination selected by the outbox row.
#[async_trait]
pub trait Exporter: Send + Sync + 'static {
    async fn export(
        &self,
        target_sink: &str,
        event_id: Uuid,
        payload: &Value,
    ) -> Result<(), ExportError>;
}

/// Type-erased registry: `target_sink` identifier → exporter.
/// Built at boot, immutable thereafter — adding/removing
/// exporters requires a restart (matches every other "wire at
/// boot, lock in for the run" pattern in this gateway).
#[derive(Clone, Default)]
pub struct ExporterRegistry {
    by_target: HashMap<String, Arc<dyn Exporter>>,
}

impl ExporterRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `exporter` under `target_sink`. Operators name
    /// targets in `GATEWAY_EVIDENCE_OUTBOX_TARGETS` using the
    /// same string. Replacing an existing entry is allowed
    /// (last-write-wins) so a test fixture can override the
    /// production exporter without enum gymnastics.
    pub fn insert(&mut self, target_sink: impl Into<String>, exporter: Arc<dyn Exporter>) {
        self.by_target.insert(target_sink.into(), exporter);
    }

    pub fn get(&self, target_sink: &str) -> Option<&Arc<dyn Exporter>> {
        self.by_target.get(target_sink)
    }

    /// Number of registered targets. Used in the drain's
    /// startup log so an operator can confirm the registry
    /// matches the env config.
    pub fn len(&self) -> usize {
        self.by_target.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_target.is_empty()
    }

    /// Sorted list of registered target identifiers. Used by
    /// the drain to validate that every configured target has
    /// an exporter (no silent "target named, exporter missing"
    /// failure mode) and by the startup log for operator
    /// visibility.
    pub fn target_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.by_target.keys().cloned().collect();
        names.sort();
        names
    }
}

/// OCSF (Open Cybersecurity Schema Framework)
/// 1.7 exporter. Same HTTP-POST shape as [`WebhookExporter`]
/// but the payload is the OCSF-mapped form of the audit event
/// (see [`crate::ocsf::audit_event_to_ocsf`]). Targets the
/// `ocsf` identifier in `GATEWAY_EVIDENCE_OUTBOX_TARGETS`;
/// destination URL from `GATEWAY_EVIDENCE_OCSF_URL`. Common
/// destinations are fluentd's HTTP source, Datadog's logs
/// ingest endpoint, Splunk HEC, or any OCSF-aware SIEM with
/// a HTTP receiver.
///
/// The mapping is a pure function; this struct owns only the
/// HTTP transport + retry shape (which mirrors WebhookExporter
/// — `Transient` for 5xx + network errors, `Permanent` for
/// 4xx other than 408/429).
///
/// Payload-deserialisation failure (the outbox row's JSON
/// doesn't parse back as `AuditEvent`) is `Permanent` — that
/// row is unrecoverable; the recorder serialised something
/// the OCSF mapper can't read.
#[derive(Debug)]
pub struct OcsfExporter {
    client: reqwest::Client,
    url: String,
    /// When true, every emitted OCSF record
    /// gets an extra `aos_trace` enrichment block (see
    /// [`crate::ocsf::audit_event_to_ocsf_with_options`]).
    /// Default false — must be opt-in so existing OCSF
    /// destinations never see schema noise on upgrade.
    aos_trace: bool,
}

impl OcsfExporter {
    /// Identifier used by the shipped gateway configuration and registry.
    pub const TARGET: &'static str = "ocsf";

    /// Construct with the same URL validation + 10s client
    /// timeout as WebhookExporter. The mapping itself doesn't
    /// need a client; the client lives here for the actual
    /// POST. AOS-trace defaults off; use
    /// [`Self::with_aos_trace`] to enable.
    pub fn new(url: impl Into<String>) -> Result<Self, ExportError> {
        Self::with_aos_trace(url, false)
    }

    /// Construct with the AOS-trace
    /// enrichment toggle. Wired into the boot path via the
    /// `GATEWAY_OCSF_AOS_TRACE` env (default `false`).
    pub fn with_aos_trace(url: impl Into<String>, aos_trace: bool) -> Result<Self, ExportError> {
        let url_str = url.into();
        let parsed = reqwest::Url::parse(&url_str)
            .map_err(|e| ExportError::Permanent(format!("ocsf URL parse: {e}")))?;
        match parsed.scheme() {
            "http" | "https" => {}
            other => {
                return Err(ExportError::Permanent(format!(
                    "ocsf URL must be http or https, got `{other}`"
                )));
            }
        }
        let client = http_client::builder(Profile::Standard)
            .build()
            .map_err(|e| ExportError::Permanent(format!("ocsf client build: {e}")))?;
        Ok(Self {
            client,
            url: url_str,
            aos_trace,
        })
    }

    /// Same credential-stripping shape as
    /// [`WebhookExporter::sanitized_url`] — OCSF destinations
    /// (Splunk HEC, Datadog) often carry tokens in the path
    /// or query.
    pub fn sanitized_url(&self) -> String {
        match reqwest::Url::parse(&self.url) {
            Ok(mut u) => {
                let _ = u.set_username("");
                let _ = u.set_password(None);
                u.set_query(None);
                u.set_fragment(None);
                u.set_path("/");
                u.to_string()
            }
            Err(_) => "<ocsf>".to_owned(),
        }
    }
}

#[async_trait]
impl Exporter for OcsfExporter {
    async fn export(
        &self,
        _target_sink: &str,
        event_id: Uuid,
        payload: &Value,
    ) -> Result<(), ExportError> {
        // Deserialise the outbox payload back into AuditEvent
        // so the OCSF mapper sees typed fields, not
        // `serde_json::Value`-shaped bag. The recorder's
        // serialisation is the source of truth; a parse
        // failure here means the outbox row was written with
        // a shape this exporter can't read — permanent.
        let event: waygate_evidence::audit::AuditEvent = serde_json::from_value(payload.clone())
            .map_err(|e| {
                ExportError::Permanent(format!(
                    "ocsf: outbox payload doesn't deserialise as AuditEvent: {e}"
                ))
            })?;
        let ocsf_record =
            crate::ocsf::audit_event_to_ocsf_with_options(event_id, &event, self.aos_trace);
        let resp = self
            .client
            .post(&self.url)
            .header("content-type", "application/json")
            .header("x-evidence-event-id", event_id.to_string())
            .header("x-ocsf-version", crate::ocsf::OCSF_VERSION)
            .json(&ocsf_record)
            .send()
            .await
            .map_err(|e| {
                // Same `without_url()` rationale as
                // WebhookExporter:
                // reqwest's Display includes the URL, which
                // would leak the secret-bearing destination
                // into the drain log on every transient
                // failure.
                ExportError::Transient(format!("ocsf send: {}", e.without_url()))
            })?;
        match classify_response_status(resp.status()) {
            StatusClass::Ok => Ok(()),
            StatusClass::Transient => {
                Err(ExportError::Transient(format!("ocsf {}", resp.status())))
            }
            StatusClass::Permanent => {
                Err(ExportError::Permanent(format!("ocsf {}", resp.status())))
            }
        }
    }
}

/// Elastic Common Schema (ECS) 8.x exporter.
/// Same HTTP-POST shape as [`OcsfExporter`] (which itself
/// mirrors [`WebhookExporter`]); payload is the ECS-mapped
/// form of the audit event (see
/// [`crate::ecs::audit_event_to_ecs`]). Targets the `ecs`
/// identifier in `GATEWAY_EVIDENCE_OUTBOX_TARGETS`;
/// destination URL from `GATEWAY_EVIDENCE_ECS_URL`.
///
/// Ships **one ECS document per HTTP POST** with
/// `Content-Type: application/json`. The destination should
/// be a fluentd / logstash / Elasticsearch ingest pipeline
/// that aggregates per-event posts into bulk indexing — this
/// is how most ECS-shipping setups work in practice.
///
/// **Elasticsearch `_bulk` endpoints are NOT supported.**
/// `_bulk` requires NDJSON framing (action line + event line
/// per item) and `application/x-ndjson`; pointing this
/// exporter at a `_bulk` URL would 400 and dead-letter every
/// row.
///
/// Same retry shape (transient on 5xx + network, permanent
/// on 4xx other than 408/429), same payload-deserialise
/// failure handling (`Permanent` — that row is unrecoverable
/// because the recorder wrote a shape the ECS mapper can't
/// read).
#[derive(Debug)]
pub struct EcsExporter {
    client: reqwest::Client,
    url: String,
}

impl EcsExporter {
    /// Identifier used by the shipped gateway configuration and registry.
    pub const TARGET: &'static str = "ecs";

    pub fn new(url: impl Into<String>) -> Result<Self, ExportError> {
        let url_str = url.into();
        let parsed = reqwest::Url::parse(&url_str)
            .map_err(|e| ExportError::Permanent(format!("ecs URL parse: {e}")))?;
        match parsed.scheme() {
            "http" | "https" => {}
            other => {
                return Err(ExportError::Permanent(format!(
                    "ecs URL must be http or https, got `{other}`"
                )));
            }
        }
        let client = http_client::builder(Profile::Standard)
            .build()
            .map_err(|e| ExportError::Permanent(format!("ecs client build: {e}")))?;
        Ok(Self {
            client,
            url: url_str,
        })
    }

    pub fn sanitized_url(&self) -> String {
        match reqwest::Url::parse(&self.url) {
            Ok(mut u) => {
                let _ = u.set_username("");
                let _ = u.set_password(None);
                u.set_query(None);
                u.set_fragment(None);
                u.set_path("/");
                u.to_string()
            }
            Err(_) => "<ecs>".to_owned(),
        }
    }
}

#[async_trait]
impl Exporter for EcsExporter {
    async fn export(
        &self,
        _target_sink: &str,
        event_id: Uuid,
        payload: &Value,
    ) -> Result<(), ExportError> {
        let event: waygate_evidence::audit::AuditEvent = serde_json::from_value(payload.clone())
            .map_err(|e| {
                ExportError::Permanent(format!(
                    "ecs: outbox payload doesn't deserialise as AuditEvent: {e}"
                ))
            })?;
        let ecs_record = crate::ecs::audit_event_to_ecs(event_id, &event);
        let resp = self
            .client
            .post(&self.url)
            .header("content-type", "application/json")
            .header("x-evidence-event-id", event_id.to_string())
            .header("x-ecs-version", crate::ecs::ECS_VERSION)
            .json(&ecs_record)
            .send()
            .await
            .map_err(|e| ExportError::Transient(format!("ecs send: {}", e.without_url())))?;
        match classify_response_status(resp.status()) {
            StatusClass::Ok => Ok(()),
            StatusClass::Transient => Err(ExportError::Transient(format!("ecs {}", resp.status()))),
            StatusClass::Permanent => Err(ExportError::Permanent(format!("ecs {}", resp.status()))),
        }
    }
}

/// RFC 5424 syslog exporter over plain TCP.
/// Targets the `syslog` identifier in
/// `GATEWAY_EVIDENCE_OUTBOX_TARGETS`; destination from
/// `GATEWAY_EVIDENCE_SYSLOG_TARGET` (`host:port`).
///
/// Per-event TCP connect → newline-terminated RFC 5424
/// line → close. Connections are not pooled.
///
/// Transient on any connect/write failure (syslog is
/// fire-and-forget — no response to interpret). Permanent
/// only on configuration errors caught at boot time
/// (`SyslogExporter::new` validates the target).
///
/// **Plain TCP only.** Operators wanting `syslog+tls://`
/// front the receiver with stunnel / haproxy / a TLS sidecar.
#[derive(Debug)]
pub struct SyslogExporter {
    /// Resolved `host:port` target. Stored as a string and
    /// re-parsed per send so a temporary DNS hiccup doesn't
    /// pin a stale IP at boot — at audit rates the resolver
    /// cache covers cold-start latency.
    target: String,
    hostname: String,
    facility: u8,
    pen: u32,
}

impl SyslogExporter {
    /// Identifier used by the shipped gateway configuration and registry.
    pub const TARGET: &'static str = "syslog";

    /// Construct + validate. `target` is `host:port`; we
    /// parse it as a `SocketAddr`-compatible string but
    /// don't resolve at boot (DNS is per-send so a transient
    /// DNS failure doesn't pin the wrong IP). `hostname` is
    /// the value placed in the RFC 5424 HOSTNAME field
    /// (operator's host id; default `mcp-gateway`).
    pub fn new(
        target: impl Into<String>,
        hostname: impl Into<String>,
        facility: u8,
        pen: u32,
    ) -> Result<Self, ExportError> {
        let target = target.into();
        // Parse the `host:port`
        // shape at boot rather than just checking for `:`.
        // Bogus shapes like `localhost:notaport` or
        // `http://host:514` would otherwise pass
        // construction and only fail at the first drain
        // attempt as a transient "connection failed"
        // error — burning the per-event retry budget on a
        // permanent config bug. Splitting on the LAST `:`
        // handles bracketed IPv6 hosts (`[::1]:6514`)
        // correctly because the port colon is still the
        // rightmost.
        let (host, port_str) = target.rsplit_once(':').ok_or_else(|| {
            ExportError::Permanent(format!(
                "syslog target must be host:port, got `{target}` (no `:` separator)"
            ))
        })?;
        if host.is_empty() {
            return Err(ExportError::Permanent(format!(
                "syslog target host part is empty in `{target}`"
            )));
        }
        // Reject scheme-prefixed forms (`http://...`,
        // `tcp://...`) — operators sometimes copy a URL out
        // of habit. We don't speak HTTP here.
        if host.contains("//") || host.contains("://") {
            return Err(ExportError::Permanent(format!(
                "syslog target must be host:port (no scheme), got `{target}`"
            )));
        }
        port_str.parse::<u16>().map_err(|_| {
            ExportError::Permanent(format!(
                "syslog target port `{port_str}` is not a valid u16 (0..=65535) in `{target}`"
            ))
        })?;
        Ok(Self {
            target,
            hostname: hostname.into(),
            facility,
            pen,
        })
    }

    /// Sanitised target for the boot log. The TCP `host:port`
    /// shape doesn't usually carry credentials but staying
    /// consistent with the other exporters' loggers makes
    /// the operator's job easier.
    pub fn sanitized_target(&self) -> String {
        self.target.clone()
    }
}

#[async_trait]
impl Exporter for SyslogExporter {
    async fn export(
        &self,
        _target_sink: &str,
        event_id: Uuid,
        payload: &Value,
    ) -> Result<(), ExportError> {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpStream;
        use tokio::time::{timeout, Duration as TokioDuration};
        let event: waygate_evidence::audit::AuditEvent = serde_json::from_value(payload.clone())
            .map_err(|e| {
                ExportError::Permanent(format!(
                    "syslog: outbox payload doesn't deserialise as AuditEvent: {e}"
                ))
            })?;
        let mut line = crate::syslog::audit_event_to_rfc5424(
            event_id,
            &event,
            &self.hostname,
            self.facility,
            self.pen,
        );
        // RFC 6587 non-transparent framing: terminate the
        // message with `\n`. Most modern receivers
        // (rsyslog, syslog-ng) accept this by default.
        line.push('\n');

        // 5s per-send budget covers connect + write +
        // close. Without the timeout a wedged receiver
        // would block the drain task's whole tick.
        let result = timeout(TokioDuration::from_secs(5), async {
            let mut stream = TcpStream::connect(&self.target).await?;
            stream.write_all(line.as_bytes()).await?;
            stream.shutdown().await?;
            Ok::<_, std::io::Error>(())
        })
        .await;
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(ExportError::Transient(format!("syslog send: {e}"))),
            Err(_) => Err(ExportError::Transient(
                "syslog send: timed out after 5s".to_owned(),
            )),
        }
    }
}

/// `Transient` for 5xx + network errors and `Permanent` for
/// 4xx (a 400 on a JSON the remote rejects won't get any better
/// on retry).
///
/// Per-event headers are minimal: `Content-Type: application/json`
/// and `X-Evidence-Event-Id` so the remote can dedupe across
/// retries (since the drain re-ships on `failed` rows after
/// backoff, a remote that records every POST without
/// idempotency-keying would double-count).
#[derive(Debug)]
pub struct WebhookExporter {
    client: reqwest::Client,
    url: String,
}

impl WebhookExporter {
    /// Identifier used by the shipped gateway configuration and registry.
    pub const TARGET: &'static str = "webhook";

    /// Construct with a fresh `reqwest::Client`. The 10s
    /// timeout bounds tail-latency — without it a wedged
    /// remote would block the drain task's whole tick.
    ///
    /// Validates the URL so a malformed
    /// or unsupported scheme is rejected at boot rather than
    /// burning the per-event transient retry budget on every
    /// dispatched row. Only `http` and `https` are accepted —
    /// `file:`, `data:`, etc. would `reqwest::send` succeed in
    /// nonsensical ways or fail in ways the operator probably
    /// didn't mean.
    pub fn new(url: impl Into<String>) -> Result<Self, ExportError> {
        let url_str = url.into();
        let parsed = reqwest::Url::parse(&url_str)
            .map_err(|e| ExportError::Permanent(format!("webhook URL parse: {e}")))?;
        match parsed.scheme() {
            "http" | "https" => {}
            other => {
                return Err(ExportError::Permanent(format!(
                    "webhook URL must be http or https, got `{other}`"
                )));
            }
        }
        let client = http_client::builder(Profile::Standard)
            .build()
            .map_err(|e| ExportError::Permanent(format!("webhook client build: {e}")))?;
        Ok(Self {
            client,
            url: url_str,
        })
    }

    /// Sanitized form
    /// of the configured URL for logging — returns ONLY
    /// `<scheme>://<host>[:port]/`. The path is also stripped
    /// because real webhook providers routinely encode the
    /// credential in the path itself:
    /// - Slack: `/services/T00000000/B00000000/XXXXXXXX`
    /// - Discord: `/api/webhooks/{id}/{token}`
    /// - AWS S3 presigned URLs: signature in the path query
    ///
    /// Leaving the path intact would
    /// leak that token-bearing tail. Operators can still
    /// confirm "yes, this is pointing at our staging webhook
    /// host" from the scheme + host + port alone; debugging a
    /// wrong-URL config is the operator's job and should happen
    /// against the env, not the log stream.
    ///
    /// Falls back to the literal `<webhook>` for the (impossible-
    /// by-construction after `new()`) unparseable case.
    pub fn sanitized_url(&self) -> String {
        match reqwest::Url::parse(&self.url) {
            Ok(mut u) => {
                let _ = u.set_username("");
                let _ = u.set_password(None);
                u.set_query(None);
                u.set_fragment(None);
                // Collapse the path to root. set_path("/") works
                // for every URL shape this exporter accepts
                // (http/https with a host component).
                u.set_path("/");
                u.to_string()
            }
            Err(_) => "<webhook>".to_owned(),
        }
    }
}

#[async_trait]
impl Exporter for WebhookExporter {
    async fn export(
        &self,
        _target_sink: &str,
        event_id: Uuid,
        payload: &Value,
    ) -> Result<(), ExportError> {
        let resp = self
            .client
            .post(&self.url)
            .header("content-type", "application/json")
            .header("x-evidence-event-id", event_id.to_string())
            .json(payload)
            .send()
            .await
            .map_err(|e| {
                // reqwest::Error's
                // Display impl includes the request URL, which
                // would leak the secret-bearing webhook URL into
                // the drain's WARN log on every transient
                // failure. `without_url()` strips the URL before
                // we format, leaving the operator with a useful
                // diagnostic ("connection timed out", "DNS
                // resolution failed") without the credential
                // tail.
                ExportError::Transient(format!("webhook send: {}", e.without_url(),))
            })?;
        // The response body is
        // deliberately NOT included in the ExportError string.
        // A misconfigured sink that echoes the submitted JSON in
        // its rejection body would otherwise land audit content
        // (principal sub, tool name, args) in our drain log via
        // the error-payload path. Operators wanting body content
        // for diagnostics can enable DEBUG tracing on the
        // exporter directly. The status code alone is enough to
        // drive the operator's triage.
        match classify_response_status(resp.status()) {
            StatusClass::Ok => Ok(()),
            StatusClass::Transient => {
                Err(ExportError::Transient(format!("webhook {}", resp.status())))
            }
            StatusClass::Permanent => {
                Err(ExportError::Permanent(format!("webhook {}", resp.status())))
            }
        }
    }
}

/// Pure-function classifier so the
/// `(HTTP status) -> (Ok | Transient | Permanent)` decision is
/// unit-testable without a live server.
/// Standard HTTP retry semantics carve out two 4xx codes as
/// transient — every other 4xx is genuine client-rejection.
///
/// - 2xx → `Ok`
/// - `408 Request Timeout` → `Transient` (client should retry).
/// - `429 Too Many Requests` → `Transient` (rate limit; every
///   real provider — Slack / Discord / AWS SQS — returns this
///   on overload and expects the caller to back off and retry).
/// - other 4xx → `Permanent` (400 bad payload, 401 unauthorized,
///   404 wrong URL — retry won't fix).
/// - 5xx + 3xx + everything else → `Transient` (server-side
///   hiccup or unexpected redirect).
#[derive(Debug, PartialEq, Eq)]
enum StatusClass {
    Ok,
    Transient,
    Permanent,
}

fn classify_response_status(status: reqwest::StatusCode) -> StatusClass {
    if status.is_success() {
        return StatusClass::Ok;
    }
    if matches!(status.as_u16(), 408 | 429) {
        return StatusClass::Transient;
    }
    if status.is_client_error() {
        return StatusClass::Permanent;
    }
    StatusClass::Transient
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: a registered exporter is retrievable by its
    /// identifier; an unknown identifier returns None (the
    /// drain treats `None` as "no exporter for this target —
    /// log + dead_letter").
    #[test]
    fn registry_round_trips_identifier_to_exporter() {
        struct Noop;
        #[async_trait]
        impl Exporter for Noop {
            async fn export(&self, _: &str, _: Uuid, _: &Value) -> Result<(), ExportError> {
                Ok(())
            }
        }
        let mut reg = ExporterRegistry::new();
        reg.insert("webhook", Arc::new(Noop));
        assert!(reg.get("webhook").is_some());
        assert!(reg.get("ocsf").is_none());
        assert_eq!(reg.target_names(), vec!["webhook".to_owned()]);
    }

    /// A malformed target must reject at construction:
    /// syslog target
    /// validation rejects bogus shapes at boot rather
    /// than burning per-event retries on a permanent
    /// config bug.
    #[test]
    fn syslog_new_validates_target_shape() {
        // No colon at all.
        assert!(matches!(
            SyslogExporter::new("nocolon", "host", 16, 32_473).unwrap_err(),
            ExportError::Permanent(_)
        ));
        // Non-numeric port.
        assert!(matches!(
            SyslogExporter::new("localhost:notaport", "host", 16, 32_473).unwrap_err(),
            ExportError::Permanent(_)
        ));
        // Port out of u16 range.
        assert!(matches!(
            SyslogExporter::new("localhost:99999", "host", 16, 32_473).unwrap_err(),
            ExportError::Permanent(_)
        ));
        // Empty host.
        assert!(matches!(
            SyslogExporter::new(":6514", "host", 16, 32_473).unwrap_err(),
            ExportError::Permanent(_)
        ));
        // Scheme-prefixed URL (operator copy-paste from HTTP exporter).
        assert!(matches!(
            SyslogExporter::new("tcp://syslog.example:6514", "host", 16, 32_473).unwrap_err(),
            ExportError::Permanent(_)
        ));
        assert!(matches!(
            SyslogExporter::new("http://syslog.example:6514", "host", 16, 32_473).unwrap_err(),
            ExportError::Permanent(_)
        ));
        // Well-formed (IPv4, hostname, IPv6 bracketed).
        assert!(SyslogExporter::new("127.0.0.1:6514", "host", 16, 32_473).is_ok());
        assert!(SyslogExporter::new("syslog.example.com:6514", "host", 16, 32_473).is_ok());
        assert!(SyslogExporter::new("[::1]:6514", "host", 16, 32_473).is_ok());
    }

    /// `new()` rather than burn the per-event retry budget on
    /// every dispatched row.
    #[test]
    fn webhook_new_rejects_malformed_url() {
        let err = WebhookExporter::new("not a url").unwrap_err();
        assert!(matches!(err, ExportError::Permanent(_)));
    }

    #[test]
    fn webhook_new_rejects_non_http_scheme() {
        // `file://` would parse but isn't a sensible exporter
        // destination; bare scheme rejection at boot prevents
        // surprise behavior at runtime.
        let err = WebhookExporter::new("file:///etc/passwd").unwrap_err();
        match err {
            ExportError::Permanent(msg) => assert!(
                msg.contains("http or https"),
                "scheme-rejection error should explain the constraint: {msg}",
            ),
            ExportError::Transient(_) => panic!("scheme rejection must be Permanent"),
        }
        // ftp also rejected.
        assert!(matches!(
            WebhookExporter::new("ftp://example.com/").unwrap_err(),
            ExportError::Permanent(_)
        ));
    }

    /// 429 (rate limit) and 408
    /// (request timeout) must retry, not dead-letter. A
    /// blanket `is_client_error() → Permanent` mapping would
    /// kill any row whose first dispatch hit a rate
    /// limit. Pins every interesting status across the
    /// classifier surface.
    #[test]
    fn classify_response_status_matches_retry_policy() {
        use reqwest::StatusCode;
        // 2xx → Ok.
        for code in [200u16, 201, 202, 204] {
            assert_eq!(
                classify_response_status(StatusCode::from_u16(code).unwrap()),
                StatusClass::Ok,
                "{code} should be Ok",
            );
        }
        // 408 + 429 → Transient (retryable client errors).
        assert_eq!(
            classify_response_status(StatusCode::from_u16(408).unwrap()),
            StatusClass::Transient,
            "408 Request Timeout should retry",
        );
        assert_eq!(
            classify_response_status(StatusCode::from_u16(429).unwrap()),
            StatusClass::Transient,
            "429 Too Many Requests should retry (per RFC 6585 + every real-world rate-limited provider)",
        );
        // Other 4xx → Permanent (genuine client-rejection).
        for code in [400u16, 401, 403, 404, 405, 409, 410, 422] {
            assert_eq!(
                classify_response_status(StatusCode::from_u16(code).unwrap()),
                StatusClass::Permanent,
                "{code} should be Permanent (no retry fix)",
            );
        }
        // 5xx → Transient.
        for code in [500u16, 502, 503, 504] {
            assert_eq!(
                classify_response_status(StatusCode::from_u16(code).unwrap()),
                StatusClass::Transient,
                "{code} should be Transient (server-side hiccup, retry)",
            );
        }
    }

    #[test]
    fn webhook_new_accepts_valid_http_and_https() {
        assert!(WebhookExporter::new("http://example.com/").is_ok());
        assert!(WebhookExporter::new("https://example.com:8443/path").is_ok());
    }

    /// sanitized_url must strip
    /// ALL credential vectors — userinfo + query + fragment +
    /// PATH — before the URL reaches a log line. Path matters
    /// because real webhook providers encode the credential in
    /// the path itself (Slack, Discord, AWS S3 presigned URLs).
    #[test]
    fn webhook_sanitized_url_strips_credentials() {
        // Basic-auth userinfo + path.
        let e = WebhookExporter::new("https://alice:secret@example.com/hook").unwrap();
        let s = e.sanitized_url();
        assert!(!s.contains("alice"), "userinfo user must be stripped: {s}");
        assert!(
            !s.contains("secret"),
            "userinfo password must be stripped: {s}"
        );
        assert!(!s.contains("hook"), "path must be stripped: {s}");
        assert_eq!(
            s, "https://example.com/",
            "expected host-only sanitized form: {s}"
        );

        // Query-string token.
        let e = WebhookExporter::new("https://example.com/hook?token=supersecret123").unwrap();
        let s = e.sanitized_url();
        assert!(
            !s.contains("supersecret123"),
            "query token must be stripped: {s}"
        );
        assert!(!s.contains("token"), "query key must be stripped: {s}");
        assert!(!s.contains("hook"), "path must be stripped: {s}");

        // Fragment.
        let e = WebhookExporter::new("https://example.com/hook#auth=abc").unwrap();
        let s = e.sanitized_url();
        assert!(!s.contains("auth"), "fragment must be stripped: {s}");
        assert!(!s.contains("abc"), "fragment value must be stripped: {s}");

        // Slack incoming-webhook shape: the token IS the path tail.
        let e = WebhookExporter::new(
            "https://hooks.slack.com/services/T00000000/B11111111/XXXXXXXXXXXXXXXX",
        )
        .unwrap();
        let s = e.sanitized_url();
        assert!(
            !s.contains("T00000000"),
            "Slack workspace id must be stripped: {s}"
        );
        assert!(
            !s.contains("B11111111"),
            "Slack channel/bot id must be stripped: {s}"
        );
        assert!(
            !s.contains("XXXXXXXX"),
            "Slack webhook secret must be stripped: {s}"
        );
        assert!(
            !s.contains("services"),
            "Slack path segment must be stripped: {s}"
        );
        assert_eq!(s, "https://hooks.slack.com/");

        // Discord webhook shape: `/api/webhooks/{id}/{token}`.
        let e = WebhookExporter::new(
            "https://discord.com/api/webhooks/123456789012345678/aBcDeFgHiJkLmNoP",
        )
        .unwrap();
        let s = e.sanitized_url();
        assert!(
            !s.contains("123456789012345678"),
            "Discord webhook id must be stripped: {s}",
        );
        assert!(
            !s.contains("aBcDeFgHiJkLmNoP"),
            "Discord webhook token must be stripped: {s}",
        );
        assert!(
            !s.contains("webhooks"),
            "Discord path segment must be stripped: {s}"
        );
        assert_eq!(s, "https://discord.com/");

        // Port + path: port is operator-meaningful info ("yes,
        // pointing at staging on 8443"), path is not.
        let e = WebhookExporter::new("https://example.com:8443/hook?k=v").unwrap();
        let s = e.sanitized_url();
        assert_eq!(s, "https://example.com:8443/");
    }

    #[test]
    fn registry_target_names_are_sorted() {
        struct Noop;
        #[async_trait]
        impl Exporter for Noop {
            async fn export(&self, _: &str, _: Uuid, _: &Value) -> Result<(), ExportError> {
                Ok(())
            }
        }
        let mut reg = ExporterRegistry::new();
        reg.insert("zeta", Arc::new(Noop));
        reg.insert("alpha", Arc::new(Noop));
        reg.insert("mu", Arc::new(Noop));
        assert_eq!(
            reg.target_names(),
            vec!["alpha".to_owned(), "mu".to_owned(), "zeta".to_owned()],
        );
    }
}
