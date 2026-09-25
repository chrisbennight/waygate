use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::client_tool_projection;
use crate::database::DatabasePoolConfig;
use crate::file_transfer_config::{FileRetention, FileTransferConfig};
use waygate_upstream::{Transport, UpstreamManifest};

mod codemode;
mod codemode_limits;
pub use codemode::{CodeModeCapacityLimits, CodeModeResultStorage};
mod deployment_profile;
pub use deployment_profile::DeploymentProfile;
mod reconnect;
mod resource_response;
mod skills;

#[cfg(test)]
pub(crate) static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMode {
    Enforce,
    Disabled,
}

/// Audit failure posture. Set via `GATEWAY_AUDIT_MODE=best_effort|fail_closed`.
///
/// The enum lives in `waygate-mcp::audit`
/// so the `DefaultInvocationService` implementation (which lives in
/// `waygate-mcp::invocation`) can branch on the posture without
/// depending on `waygate-server`. `waygate-server::config` retains
/// the env-var parser + boot-time validation, and re-exports the
/// type for the existing `config::AuditMode` import path.
///
/// - `BestEffort` (default) — the pre-call evidence stage is disabled. Final
///   governed outcomes use chained best effort, whose write failures cannot
///   break tool or LLM calls. Independently fail-closed control-plane
///   mutations still use `record_required`.
/// - `FailClosed` — side-effecting (`facts.side_effects`) tool-call dispatch
///   calls `record_required` for the pre-call intent event; a failed
///   required-record returns `InvocationError::AuditUnavailable` (mapped to HTTP
///   5xx by the adapter) so the upstream call never happens without a durable
///   evidence-of-attempt row. Read-only (`!side_effects`) calls have no
///   required pre-call row and retain chained-best-effort final evidence. The
///   gate follows `side_effects` rather than risk so a mutating tool cannot
///   lose the guarantee when its risk tier changes.
pub use waygate_mcp::AuditMode;

fn audit_mode_from_env() -> Result<AuditMode> {
    let raw = std::env::var("GATEWAY_AUDIT_MODE").unwrap_or_else(|_| "best_effort".into());
    AuditMode::parse_env(&raw).ok_or_else(|| {
        anyhow::anyhow!("GATEWAY_AUDIT_MODE must be `best_effort` or `fail_closed` (got `{raw}`)")
    })
}

fn deployment_profile_from_env() -> Result<DeploymentProfile> {
    let raw = std::env::var("GATEWAY_DEPLOYMENT_PROFILE").unwrap_or_else(|_| "dev".into());
    DeploymentProfile::parse(&raw)
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub public_url: String,
    pub authentik_issuer: Option<String>,
    pub audience: String,
    pub auth_mode: AuthMode,
    #[allow(dead_code)]
    pub otel_endpoint: Option<String>,
    pub servers_dir: PathBuf,
    /// Optional Git repository used for progressive skill discovery. The
    /// credential field contains an environment-variable name only; the token
    /// value is resolved by the source client and never retained here.
    pub skills: Option<crate::skills_git::SkillsGitConfig>,
    /// Whether operators may EDIT policies through the dashboard / REST
    /// (`GATEWAY_POLICY_EDITING`, default `true`). `false` ⇒ the gateway is a
    /// read-only policy *viewer* — policy changes must be applied to the live
    /// `policies/*.cedar` volume through another governed operator path. Editing
    /// is offered only when this is true AND the policies dir is writable (the
    /// writable check lives in `waygate-server` boot).
    pub policy_editing: bool,
    pub policies_dir: PathBuf,
    pub database_url: Option<String>,
    pub database_pools: DatabasePoolConfig,
    pub identity: Option<IdentityConfig>,
    /// Optional RFC 7662 token-introspection
    /// validator. Set the three `GATEWAY_INTROSPECTION_*` env
    /// vars together to enable; `None` (default) means the
    /// bearer chain has only the JWT + API-key validators.
    pub introspection: Option<IntrospectionEnvConfig>,
    pub dashboard: Option<DashboardConfig>,
    pub token_exchange: Option<TokenExchangeConfig>,
    /// Gateway-as-Authorization-Server config. `Some` ⇒ the gateway runs its
    /// own OAuth AS endpoints (`/oauth/*` + `/.well-known/oauth-authorization-server`)
    /// and the resource metadata points at the gateway; `None` ⇒ resource
    /// metadata points at `authentik_issuer` (pre-CIMD behaviour).
    pub as_server: Option<AsServerConfig>,
    /// Accept Authentik-issued bearers in addition to gateway-minted tokens.
    /// The bearer layer runs its validators in order: gateway validator first,
    /// upstream (Authentik) validator as a fallback. Set
    /// `GATEWAY_ACCEPT_UPSTREAM_TOKENS=true` to enable.
    ///
    /// Available only outside the production deployment profile. Boot warns
    /// when enabled; `DeploymentProfile::Prod` refuses it. This permits
    /// development service-account clients to use the configured external
    /// issuer's client-credentials flow when the gateway AS is enabled.
    pub accept_upstream_tokens: bool,
    /// Extra `iss` values the upstream (Authentik) bearer validator will
    /// accept beyond `authentik_issuer`. Authentik's `issuer_mode=per_provider`
    /// mints a distinct issuer URL per OAuth2 provider — so M2M service
    /// accounts that have their own provider also have their own issuer.
    /// All providers share the realm's JWKS, so the same key material still
    /// validates them; only the issuer allowlist needs to widen.
    /// Set via `AUTHENTIK_ADDITIONAL_ISSUERS` (comma-separated).
    pub authentik_additional_issuers: Vec<String>,
    /// Host-header allowlist passed to rmcp's streamable-HTTP server
    /// (DNS-rebinding guard). `None` ⇒ derive from [`Self::public_url`]
    /// (host ± port, plus the loopback defaults). `Some(list)` ⇒ use the
    /// operator-supplied list verbatim — empty list disables the guard.
    /// Set via `GATEWAY_MCP_ALLOWED_HOSTS` (comma-separated).
    pub mcp_allowed_hosts: Option<Vec<String>>,
    /// Browser origins allowed on MCP HTTP. Defaults to the public URL origin.
    /// GATEWAY_MCP_ALLOWED_ORIGINS replaces that default; empty denies browsers.
    pub mcp_allowed_origins: waygate_mcp::origin::OriginPolicy,
    /// Legacy strict-client escape hatch. When `true`, session `tools/list`
    /// returns the full upstream catalog alongside the `<server>.searchTools`
    /// meta-tools instead of exposing tools only after that session reveals
    /// them. Intended for legacy clients that ignore
    /// `notifications/tools/list_changed` (e.g. Claude Code as of
    /// claude-code#13646) and therefore never pick up dynamically-disclosed
    /// tools. Off by default — turning it on defeats SEP #1888 progressive
    /// disclosure and will expand every legacy client's initial context. MCP
    /// 2026 already uses a stable full projection. Set via
    /// `GATEWAY_EAGER_TOOLS_LIST` (truthy).
    pub eager_tools_list: bool,
    /// Information-flow decision for persisting bounded Code Mode content.
    pub codemode_result_storage: CodeModeResultStorage,
    /// Process-wide Code Mode runner admission limits.
    pub codemode_capacity: CodeModeCapacityLimits,
    pub(crate) codemode_limits: crate::codemode_limits::CodeModeLimits,
    /// MCP `clientInfo.name` values that receive eager `tools/list` only for
    /// their own legacy session. Exact, ASCII-case-insensitive matches;
    /// defaults to `claude-code` and `codex-mcp-client`, whose current clients
    /// do not turn dynamic tool-list changes into callable bindings. Set
    /// `GATEWAY_EAGER_TOOLS_CLIENTS` to a comma-separated replacement list, or
    /// to an explicit empty value to disable the automatic fallback.
    pub eager_tools_clients: Vec<String>,
    /// MCP `clientInfo.name` values whose `tools/list` projection contains
    /// only authorized gateway built-ins. Code Mode remains available as the
    /// governed discovery and invocation facade. Set
    /// `GATEWAY_CODEMODE_ONLY_CLIENTS` to a comma-separated list. Client names
    /// are compatibility hints, not an authorization boundary.
    pub codemode_only_tools_clients: Vec<String>,
    /// Opt-in client names for root-composition schema presentation.
    pub root_composition_clients: Vec<String>,
    /// When `true`, each SEP #1888 `searchTools` discovery call records a
    /// best-effort `Discovery` audit row so discovery activity appears in
    /// the admin Activity feed (`searchTools` is otherwise unaudited). Off
    /// by default — discovery is high-volume, so opting in trades audit-log
    /// growth for visibility. Set via `GATEWAY_AUDIT_DISCOVERY` (truthy).
    pub audit_discovery: bool,
    /// Initial full-jitter reconnect window for an unhealthy upstream.
    pub upstream_reconnect_base: Duration,
    /// Maximum full-jitter reconnect window after exponential escalation.
    pub upstream_reconnect_ceiling: Duration,
    /// Total wall-clock budget for the
    /// post-SIGTERM cleanup sequence — axum HTTP drain PLUS
    /// DB pool close. Bounds both, not just the HTTP drain:
    /// a hung pool handle would otherwise undo the bound
    /// (`PgPool::close` waits for every cloned handle to
    /// drop, and background tasks that don't release theirs
    /// would block forever).
    ///
    /// Default 20s leaves ~10s of headroom inside the
    /// typical 30s `terminationGracePeriodSeconds` for the
    /// process to log + exit before the orchestrator
    /// escalates to SIGKILL. Operators with a longer
    /// grace period can raise this.
    ///
    /// The timer starts from the moment the shutdown signal
    /// fires, not from server boot. Set via
    /// `GATEWAY_DRAIN_TIMEOUT_SECONDS`. Floor 1s, max 600s.
    pub drain_timeout: Duration,
    /// Cadence of the background re-encrypt sweeper
    /// that migrates `user_upstream_sessions` rows whose `key_id`
    /// is not the active id. `None` ⇒ sweeper disabled (set
    /// `GATEWAY_UPSTREAM_REENCRYPT_INTERVAL_SECONDS=0`); otherwise
    /// the configured period (default 1h). The sweeper is only
    /// useful when key rotation is in progress, but leaving it
    /// running at idle is cheap — the SQL filter on
    /// `key_id <> active_id` returns zero rows in steady state.
    pub reencrypt_interval: Option<Duration>,
    /// Cadence of the background JWKS
    /// refresher that keeps the in-memory cache of
    /// federated peers' signing keys warm. Default 10
    /// minutes; floor 30s so a misconfigured deployment
    /// can't hammer every peer's JWKS endpoint. Set via
    /// `GATEWAY_PEER_JWKS_REFRESH_INTERVAL_SECONDS`.
    pub peer_jwks_refresh_interval: Duration,
    /// Idle timeout the streamable-HTTP session manager applies to each
    /// `Mcp-Session-Id`. After this much inactivity the rmcp session worker
    /// quits and the next request on that session ID gets `404 Session not
    /// found`. The MCP spec says clients SHOULD re-handshake on that error,
    /// but Claude Code (issue #27142) does not — so the practical effect of
    /// a short timeout is a hung CLI until the user restarts. Default 7 days
    /// — long enough to outlast any realistic CLI idle gap while still being
    /// a finite safety net for half-open HTTP/2 streams. Floor 60s. `0`
    /// disables the timeout entirely (`None`) — sessions then live until the
    /// worker channel closes, which can leak workers on RST_STREAM. Set via
    /// `GATEWAY_SESSION_KEEPALIVE_SECONDS`.
    pub session_keepalive: Option<Duration>,
    /// Interval between SSE keepalive comment frames (`:` heartbeats) on
    /// every open streamable-HTTP SSE stream — the standalone GET stream and
    /// long-running POST response streams. These bytes are what stop an
    /// intermediary with an idle-read timeout (squid `read_timeout`, nginx
    /// `proxy_read_timeout`, ALB idle timeout) from reaping a healthy but
    /// quiet stream between tool calls. Distinct from `session_keepalive`
    /// above: this keeps the *stream* warm; that bounds how long idle
    /// *session state* is retained server-side. Default 120s. Floor 5s. `0`
    /// disables (`None`) — streams then emit nothing between messages and
    /// WILL be reaped by any idle-timeout hop; rmcp's own 15s default is
    /// deliberately overridden in both directions so the operator-visible
    /// knob is the single source of truth. Set via
    /// `GATEWAY_SSE_KEEPALIVE_SECONDS`.
    pub sse_keepalive: Option<Duration>,
    /// Interval between server-initiated MCP `ping` requests to each
    /// connected session — the spec's connection-health probe, and an
    /// application-layer keepalive for clients that implement none of
    /// their own (each ping elicits a client response, so bytes flow in
    /// BOTH directions, unlike the server→client-only SSE comment frames
    /// above). A successfully-pinged session never idle-reaps: outbound
    /// pings re-arm the `session_keepalive` timer, which is why the loop
    /// stops itself after consecutive unanswered pings (see
    /// `waygate_mcp::ping`) — that hands control back to the idle timeout
    /// for dead clients. Default 120s. Floor 10s. `0` disables (`None`).
    /// Set via `GATEWAY_MCP_PING_INTERVAL_SECONDS`.
    pub mcp_ping_interval: Option<Duration>,
    /// Hard timeout the upstream pool applies to each `call_tool` invocation.
    /// Without this, a wedged stream (e.g. a long-idle HTTP/2 connection
    /// that silently half-closed) keeps the per-server `call_serializer`
    /// mutex held forever inside `waygate_upstream::pool` and blocks every
    /// subsequent call to that upstream until the gateway restarts. Default
    /// 300s (5 minutes). Floor 5s. `0` disables the timeout entirely
    /// (`None`) — only safe when every upstream is known to respond
    /// bounded-fast. Set via `GATEWAY_UPSTREAM_CALL_TIMEOUT_SECONDS`. The
    /// global value applies to every upstream and every tool; if you have
    /// one outlier that needs longer (e.g. an agentic synthesis tool), set
    /// the global to its envelope rather than a per-tool default — there is
    /// no per-tool override today.
    pub upstream_call_timeout: Option<Duration>,
    /// Raw response-body budget for one native `resources/read`. The bound is
    /// enforced by the streamable-HTTP client before rmcp deserializes the
    /// response. Default 4 MiB; maximum 1 GiB. Governed file bytes use the
    /// separate file-transfer limit because the MCP response carries only a
    /// bounded descriptor.
    pub resource_response_max_bytes: usize,
    /// Shared directory used for gateway-owned file bytes. Unset keeps file
    /// transfer authority available but does not advertise or process file
    /// outputs.
    pub file_storage_dir: Option<PathBuf>,
    /// How long a completed file reference remains available for refreshed
    /// download authorization, per retention class.
    pub file_retention: FileRetention,
    /// Optional operator/storage-provider byte limit. Unset means the gateway
    /// adds no file-size ceiling of its own.
    pub file_max_bytes: Option<u64>,
    /// File streams use a separate pool from ordinary tool calls.
    pub file_transfer_concurrency: usize,
    pub mrtr_state_key: Option<String>, // see `crate::continuation_key`
    /// Static API-key validator config. `Some` ⇒ the bearer middleware
    /// also accepts `Authorization: Bearer mcpgw_…` against the `api_keys`
    /// table; `None` ⇒ JWT-only. Off by default. See
    /// `docs/agents/identity.md` for the design rationale.
    pub api_keys: Option<ApiKeysConfig>,
    /// Deployment posture. Defaults to `Dev`. See [`DeploymentProfile`]
    /// for what `Prod` refuses.
    pub deployment_profile: DeploymentProfile,
    /// Audit failure posture. Defaults to `BestEffort` (historical).
    /// `FailClosed` surfaces required-record failures as 5xx. See
    /// [`AuditMode`].
    pub audit_mode: AuditMode,
    /// Cadence of the background sweep over the
    /// `approval_grants` table that prunes consumed/expired rows.
    /// `None` ⇒ sweeper disabled (set
    /// `GATEWAY_GRANT_SWEEP_INTERVAL_SECONDS=0`); otherwise the
    /// configured period (default 1h). Only spawned when a DB
    /// catalog store exists; DB-less deployments don't have an
    /// `approval_grants` table to sweep.
    pub grant_sweep_interval: Option<Duration>,
    /// Minimum age a dead grant row must reach
    /// before the sweep deletes it. Keeps recent dead rows around
    /// for the admin "history" view (`?include_consumed=true`).
    /// Default 7 days. Set via `GATEWAY_GRANT_RETENTION_DAYS`.
    pub grant_retention: Duration,
    /// Bounded broadcast-channel capacity for the
    /// HITL approval push hub (`/api/v1/admin/approval_grants/subscribe`).
    /// Each in-flight event takes one slot per subscriber until
    /// consumed; a subscriber that falls more than this many
    /// events behind receives `RecvError::Lagged(n)` and skips
    /// the gap (per [`waygate_admin::hitl_ws`] receive-loop
    /// contract). Default 256 — comfortable for a small operator
    /// team. Set via `GATEWAY_HITL_WS_BUFFER`; floor 1, ceiling
    /// 65_536 (above that an operator probably wants a real
    /// queue, not an in-process channel).
    pub hitl_ws_buffer: usize,
    /// Cadence of the evidence outbox drain worker.
    /// `None` ⇒ drain disabled
    /// (`GATEWAY_EVIDENCE_DRAIN_INTERVAL_SECONDS=0`); otherwise the
    /// configured period (default 30s). Only spawned when (a) a DB
    /// pool exists, (b) `GATEWAY_EVIDENCE_OUTBOX_TARGETS` named at
    /// least one sink, AND (c) at least one matching exporter is
    /// registered (today: `webhook` ↔ [`waygate_storage::WebhookExporter`]
    /// gated on `GATEWAY_EVIDENCE_WEBHOOK_URL`).
    pub evidence_drain_interval: Option<Duration>,
    /// Cadence of the periodic retention sweep
    /// scheduler. Default is hourly; `None` means the operator explicitly set
    /// `GATEWAY_RETENTION_SWEEP_INTERVAL_SECONDS=0`.
    /// Only spawned when a Postgres pool exists AND the
    /// retention store is wired AND a sweeper is wired (all
    /// three are gated on the same DB pool today). Each tick enforces explicit
    /// category policies and wildcard policies with most-specific precedence.
    pub retention_sweep_interval: Option<Duration>,
    /// Tier-2: cadence of the audit rollup maintenance worker. `Some(d)` spawns
    /// it (default 60s); `None` (env set to 0) disables it. Gated additionally
    /// on a DB pool existing.
    pub audit_rollup_interval: Option<Duration>,
    /// HTTP-POST destination for the `webhook`
    /// exporter. When set AND `webhook` is in
    /// `GATEWAY_EVIDENCE_OUTBOX_TARGETS`, the drain ships each
    /// audit event's JSON to this URL. The exporter retries on
    /// 5xx / network errors per the backoff schedule in
    /// `waygate_storage::drain`; 4xx is treated as permanent
    /// (dead_letter).
    pub evidence_webhook_url: Option<String>,
    /// HITL control-plane: optional out-of-band webhook fired when an
    /// agent proposes a change request that needs human approval. The body is
    /// an operator-safe summary + a deep link to the dashboard review queue —
    /// never the proposed params/justification, never an approve button.
    /// Point it at a Signal/SMTP/Slack relay or alerting pipeline. Empty
    /// string treated as absent (no out-of-band push; the dashboard queue
    /// still surfaces the change).
    pub hitl_webhook_url: Option<String>,
    /// Optional Grafana Explore → Tempo URL template for the
    /// activity-drawer "View trace" link. A string containing a `{trace_id}`
    /// placeholder the drawer substitutes per row; unset (`None`) hides the
    /// link. Set via `GATEWAY_TRACE_URL_TEMPLATE`.
    pub trace_url_template: Option<String>,
    /// HTTP-POST destination for the `ocsf`
    /// exporter. When set AND `ocsf` is in
    /// `GATEWAY_EVIDENCE_OUTBOX_TARGETS`, the drain ships each
    /// audit event as an OCSF 1.7 Application Activity record
    /// (see `waygate_storage::ocsf::audit_event_to_ocsf`).
    /// Typical destinations: fluentd HTTP source, Datadog logs
    /// ingest, Splunk HEC, any OCSF-aware SIEM with a HTTP
    /// receiver. Same retry shape as the webhook exporter:
    /// 4xx (except 408/429) → permanent dead-letter; 5xx +
    /// network errors → exponential backoff; dead-letter
    /// after 8 transient failures.
    pub evidence_ocsf_url: Option<String>,
    /// When true, every OCSF record gains an
    /// `aos_trace` enrichment block (OWASP Agentic Apps
    /// Security). Default false so existing OCSF destinations
    /// see no schema change. Set via `GATEWAY_OCSF_AOS_TRACE`.
    pub evidence_ocsf_aos_trace: bool,
    /// TCP target for the `syslog` exporter
    /// (RFC 5424 syslog over plain TCP, RFC 6587
    /// non-transparent framing). Format: `host:port`. When
    /// set AND `syslog` is in
    /// `GATEWAY_EVIDENCE_OUTBOX_TARGETS`, the drain ships
    /// each audit event as a syslog line. Plain TCP only;
    /// operators wanting TLS front the receiver with
    /// stunnel/haproxy.
    pub evidence_syslog_target: Option<String>,
    /// RFC 5424 HOSTNAME field value the
    /// syslog exporter places in each line. Default
    /// `mcp-gateway`. Operators with multiple gateways
    /// override per-host so SIEM rules can route by
    /// instance.
    pub evidence_syslog_hostname: String,
    /// Syslog facility code (0–23). Default `16` (local0).
    pub evidence_syslog_facility: u8,
    /// Private-enterprise number for the RFC 5424 structured-data blocks.
    /// Default `32473` (RFC 5612 example PEN).
    pub evidence_syslog_pen: u32,
    /// PKCS8-PEM-encoded Ed25519 private
    /// key the `POST /api/v1/audit/bundle` endpoint signs
    /// evidence bundles with. `None` ⇒ the endpoint 503s
    /// with a "signing key not configured" message. The
    /// boot path parses + derives the verifying-key id once
    /// at startup; the raw PEM stays in memory only inside
    /// the constructed `BundleSigner`.
    pub evidence_bundle_signing_key_pem: Option<String>,
    /// Optional human-readable label for
    /// the bundle signing key (e.g. `"bundle-2026-q2"`).
    /// `None` ⇒ derive from the verifying key's SHA256.
    /// Embedded in every bundle's header so recipients
    /// match against the operator's published key list.
    pub evidence_bundle_signing_key_id: Option<String>,
    /// HTTP-POST destination for the `ecs`
    /// exporter. When set AND `ecs` is in
    /// `GATEWAY_EVIDENCE_OUTBOX_TARGETS`, the drain ships each
    /// audit event as an Elastic Common Schema 8.x record
    /// (see `waygate_storage::ecs::audit_event_to_ecs`). Same
    /// retry + headers + sanitisation as the OCSF exporter.
    /// Typical destinations: Elasticsearch HTTP bulk endpoint
    /// proxied behind logstash/fluentd, or any HTTP-receiver
    /// SIEM that ingests ECS-shaped JSON.
    pub evidence_ecs_url: Option<String>,
    /// Dedup'd list of evidence outbox target
    /// identifiers (parsed from `GATEWAY_EVIDENCE_OUTBOX_TARGETS`).
    /// Both the recorder and the drain spawn path consume this:
    /// the recorder enqueues one outbox row per identifier per
    /// audit event; the drain only registers exporters whose
    /// identifier appears here (avoids spawning an idle drain
    /// when only `WEBHOOK_URL` is set without naming
    /// `webhook` as a target).
    pub evidence_outbox_targets: Vec<String>,
}

/// Env-derived config for RFC 8693 token exchange (Tier A identity chaining).
/// When `None`, the gateway runs in Tier B only — upstreams get the
/// gateway-minted identity JWT but never a downscoped IdP access token.
#[derive(Debug, Clone)]
pub struct TokenExchangeConfig {
    /// Full URL of the IdP token endpoint (Authentik posts the exchange here).
    pub token_endpoint: String,
    /// OAuth client id registered with the IdP for the gateway. Can be reused
    /// with the dashboard client id, or split for principle-of-least-privilege.
    pub client_id: String,
    pub client_secret: String,
}

/// Env-derived config for the PKCE + session-cookie auth on `/admin`.
/// `None` means the dashboard runs in dev/disabled mode — a synthetic
/// principal is injected and no IdP is contacted. See
/// [`waygate_admin::DashboardAuth`].
#[derive(Debug, Clone)]
pub struct DashboardConfig {
    /// OAuth client id registered with Authentik (or any OIDC provider).
    pub client_id: String,
    pub client_secret: String,
    /// Full `https://.../admin/auth/callback` URL. Must match the redirect
    /// URI registered in the IdP or the token exchange will fail.
    pub redirect_uri: String,
    /// 32-byte AEAD key (base64 or 64-char hex) for encrypting session +
    /// login-state cookies. Store in Infisical; rotate invalidates all
    /// live sessions.
    pub session_key_encoded: String,
    /// Emit the `Secure` cookie attribute. Defaults to true — set
    /// `GATEWAY_DASHBOARD_COOKIE_SECURE=0` for plain-HTTP local dev.
    pub secure_cookies: bool,
    /// Session cookie TTL, seconds. Default 12h.
    pub session_ttl_secs: i64,
    /// Login-state cookie TTL, seconds. Default 10 min.
    pub login_state_ttl_secs: i64,
    /// OAuth scopes requested at authorize time.
    pub scopes: Vec<String>,
    /// Whitelist of `step_up_scope=` values accepted on `/admin/login`.
    /// Unset env falls back to the compiled default (`mcp:invoke:high`,
    /// `mcp:admin`) — overriding is an advanced-deployment knob.
    pub allowed_step_up_scopes: Vec<String>,
}

/// Env-derived config for the gateway-as-AS mode. Set when
/// `GATEWAY_AS_ENABLED=true`. Requires `AUTHENTIK_ISSUER` and a set of
/// upstream OAuth client credentials (the gateway impersonates *one* client
/// to Authentik and mints its own per-MCP-client tokens off the back of
/// that login).
#[derive(Debug, Clone)]
pub struct AsServerConfig {
    /// OAuth client id registered with Authentik for the gateway's AS hop.
    /// Typically the same client used for the dashboard (the redirect URIs
    /// differ so reusing is fine) but can be split.
    pub upstream_client_id: String,
    pub upstream_client_secret: String,
    /// `<public_url>/oauth/callback` by default. Must match the redirect URI
    /// registered in Authentik for `upstream_client_id`.
    pub upstream_redirect_uri: String,
    /// Scopes the gateway asks Authentik for. Needs enough to resolve the
    /// user's sub/email/groups from the `id_token` on the callback.
    pub upstream_scopes: Vec<String>,
    /// Keyring of base64-encoded 32-byte AES-256-GCM keys for the
    /// upstream-token envelope. Each entry is `(key_id, base64_key)`.
    /// Rotation is online — operator adds a new key
    /// alongside the old, flips [`Self::upstream_token_active_id`],
    /// and the background re-encrypt sweeper updates rows encrypted
    /// under other keys. Preserve each stored row's key ID and key bytes
    /// until that row has been re-encrypted.
    pub upstream_token_keys: Vec<(String, String)>,
    /// Id of the entry in [`Self::upstream_token_keys`] used for new
    /// encrypts. Stored on each row's `key_id` column so future
    /// reads route to the right key after rotation.
    pub upstream_token_active_id: String,
    /// Optional allowlist of CIMD hosts. `None` ⇒ any public HTTPS host;
    /// non-empty ⇒ host must match one of these entries. Prefer narrow in
    /// prod ("cli.example.com,claude.ai"); empty for dev.
    pub cimd_allowed_hosts: Option<Vec<String>>,
    /// Optional directory from which the AS serves CIMD docs at
    /// `/cimd/dev-clients/<name>.json`. Local-dev workaround for the
    /// SSRF guard blocking LAN-hosted git servers. Unset in prod.
    pub cimd_dev_doc_dir: Option<std::path::PathBuf>,
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,
    pub transaction_ttl: Duration,
    pub code_ttl: Duration,
    /// Scope allow-list enforced at `/oauth/authorize`. Default covers the
    /// baseline and step-up scopes. Any scope request outside this set is
    /// rejected.
    pub allowed_scopes: Vec<String>,
}

/// Env-derived config for the static API-key validator. Enabled by
/// `GATEWAY_API_KEYS_ENABLED=true`; requires `GATEWAY_DATABASE_URL`
/// (the `api_keys` table lives in the same Postgres as the OAuth AS
/// state — see `migrations/0004_api_keys.sql`).
#[derive(Debug, Clone)]
pub struct ApiKeysConfig {
    /// Cache TTL for validated principals. Bounds the lag between a
    /// dashboard revoke and the next 401. Default 60s. Lower it for
    /// faster revocation; raise it to absorb more burst traffic.
    pub cache_ttl: Duration,
}

/// Env wiring for the RFC 7662 token
/// introspection validator. All three core fields are
/// required together; missing one is a config error so an
/// operator who only sets the URL gets a clear boot
/// failure instead of a silently-dead validator.
///
/// `Debug` is implemented manually to elide `client_secret`.
/// This struct lives on `Config`, which gets cloned into
/// long-lived state — any downstream `tracing::debug!(?cfg)`
/// would otherwise leak the introspection client secret.
#[derive(Clone)]
pub struct IntrospectionEnvConfig {
    pub introspection_url: String,
    pub client_id: String,
    pub client_secret: String,
    /// Positive cache ceiling. Default 300s. Lower for
    /// faster revocation propagation; raise to absorb
    /// burst traffic.
    pub max_positive_ttl: Duration,
    /// Negative cache TTL. Default 30s. Short on purpose so
    /// a transient IdP wobble doesn't strand a token long.
    pub negative_ttl: Duration,
}

impl std::fmt::Debug for IntrospectionEnvConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntrospectionEnvConfig")
            .field("introspection_url", &self.introspection_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("max_positive_ttl", &self.max_positive_ttl)
            .field("negative_ttl", &self.negative_ttl)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct IdentityKeySource {
    /// PKCS#8-encoded Ed25519 private key in PEM form.
    pub pem: String,
    /// JWT `kid` header value advertised in the JWKS for
    /// this key. Operators control this string so JWKS
    /// caches across the network agree on the identifier.
    pub kid: String,
}

#[derive(Debug, Clone)]
pub struct IdentityConfig {
    /// Every key in the rotation keyring.
    /// Always at least one entry (single-key deployments
    /// produce a vec of one). Order is preserved for
    /// deterministic boot logs but the runtime keyring
    /// re-orders by kid for stable JWKS output.
    pub keys: Vec<IdentityKeySource>,
    /// Which kid in `keys` is the active signing key.
    /// Required to be present in `keys`; the constructor
    /// fails fast if absent.
    pub active_kid: String,
    pub gateway_id: String,
    pub ttl: Duration,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let listen_addr = std::env::var("GATEWAY_LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8080".into())
            .parse::<SocketAddr>()
            .context("GATEWAY_LISTEN_ADDR must be ip:port")?;

        // Canonicalise once here. `GATEWAY_PUBLIC_URL` is the binary's
        // single issuer string — used as the `iss` claim on minted
        // access-token JWTs, the expected issuer in
        // `BearerValidator`, the `issuer` field in AS metadata, the
        // `iss` parameter on RFC 9207 auth-response redirects + token
        // responses, the `authorization_servers` entry in PRM, and as
        // the source for `AsConfig::issuer()` downstream.
        //
        // RFC 9207 §2.4 mandates exact-string match between any of
        // those values that a client might compare; trimming the
        // trailing slash exactly once at config load means every
        // consumer reads the same canonical form regardless of
        // whether the operator typed `https://x` or `https://x/`.
        let public_url = std::env::var("GATEWAY_PUBLIC_URL")
            .unwrap_or_else(|_| format!("http://{listen_addr}"))
            .trim_end_matches('/')
            .to_owned();

        let authentik_issuer = std::env::var("AUTHENTIK_ISSUER").ok();
        let audience = std::env::var("GATEWAY_AUDIENCE").unwrap_or_else(|_| public_url.clone());

        let auth_mode = match std::env::var("GATEWAY_AUTH_MODE")
            .unwrap_or_else(|_| "enforce".into())
            .as_str()
        {
            "enforce" => AuthMode::Enforce,
            "disabled" => {
                // Release builds reject the synthetic-admin path entirely.
                // The `Disabled` mode injects a `dev@local` principal with
                // admin scopes on every request (see
                // `waygate_oidc::middleware::dev_principal`); shipping that
                // in a non-debug binary is a complete bypass on misconfig.
                // The dev workflow in AGENTS.md uses `cargo run` (debug),
                // which still works.
                if !cfg!(debug_assertions) {
                    anyhow::bail!(
                        "GATEWAY_AUTH_MODE=disabled is rejected by release builds — \
                         the synthetic admin principal it injects is debug-only. \
                         Build a debug binary (`cargo run` or `cargo build` without \
                         `--release`) for unauthenticated local dev, or use \
                         `GATEWAY_AUTH_MODE=enforce` with a configured IdP."
                    );
                }
                AuthMode::Disabled
            }
            other => {
                anyhow::bail!("GATEWAY_AUTH_MODE must be `enforce` or `disabled` (got `{other}`)")
            }
        };
        if auth_mode == AuthMode::Enforce && authentik_issuer.is_none() {
            anyhow::bail!(
                "GATEWAY_AUTH_MODE=enforce requires AUTHENTIK_ISSUER (set GATEWAY_AUTH_MODE=disabled for dev)"
            );
        }

        let otel_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();

        let servers_dir = std::env::var("GATEWAY_SERVERS_DIR")
            .unwrap_or_else(|_| "/etc/mcp-gateway/servers".into())
            .into();
        let skills = skills::from_env()?;
        let policies_dir = std::env::var("GATEWAY_POLICIES_DIR")
            .unwrap_or_else(|_| "/etc/mcp-gateway/policies".into())
            .into();
        // Dashboard/REST policy editing. Default ON; opt out when another
        // governed operator path owns the live volume or the deployment is
        // read-only. Truthy = on; an explicit `0`/`false`/`no`/`off` turns it
        // off; any other value (or unset) keeps the on default.
        let policy_editing = waygate_core::env::bool_default_on("GATEWAY_POLICY_EDITING");
        let database_url = std::env::var("GATEWAY_DATABASE_URL").ok();
        let database_pools = DatabasePoolConfig::from_env_vars(
            "GATEWAY_DATABASE_AUDIT_MAX_CONNECTIONS",
            "GATEWAY_DATABASE_CONTROL_MAX_CONNECTIONS",
            "GATEWAY_DATABASE_READER_MAX_CONNECTIONS",
        )?;
        let identity = IdentityConfig::from_env()?;
        let introspection = IntrospectionEnvConfig::from_env()?;
        let dashboard = DashboardConfig::from_env(&public_url)?;
        let token_exchange = TokenExchangeConfig::from_env()?;
        let as_server = AsServerConfig::from_env(&public_url)?;
        if as_server.is_some() && authentik_issuer.is_none() {
            anyhow::bail!(
                "GATEWAY_AS_ENABLED=true requires AUTHENTIK_ISSUER (the gateway AS \
                 still delegates the human login hop to Authentik)"
            );
        }
        if as_server.is_some() && identity.is_none() {
            anyhow::bail!(
                "GATEWAY_AS_ENABLED=true requires an identity signing key \
                 (GATEWAY_IDENTITY_SIGNING_KEY_PEM or _PATH) — the AS mints \
                 gateway JWTs with the same Ed25519 key as identity chaining"
            );
        }
        if as_server.is_some() && database_url.is_none() {
            anyhow::bail!(
                "GATEWAY_AS_ENABLED=true requires GATEWAY_DATABASE_URL — the AS \
                 persists authorize transactions, issued codes, and refresh tokens \
                 in Postgres (see migrations/0003_oauth_as.sql)"
            );
        }
        let accept_upstream_tokens =
            waygate_core::env::bool_default_off("GATEWAY_ACCEPT_UPSTREAM_TOKENS");

        let authentik_additional_issuers = std::env::var("AUTHENTIK_ADDITIONAL_ISSUERS")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        // An explicit env entry — even an empty string — is an operator
        // decision. Empty ⇒ "disable the host guard" (recommended only
        // behind Traefik with its own host match).
        let mcp_allowed_hosts = std::env::var("GATEWAY_MCP_ALLOWED_HOSTS").ok().map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_ascii_lowercase())
                .collect::<Vec<_>>()
        });

        let configured_origins = match std::env::var("GATEWAY_MCP_ALLOWED_ORIGINS") {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                anyhow::bail!("GATEWAY_MCP_ALLOWED_ORIGINS must contain valid Unicode")
            }
        };
        let mcp_allowed_origins = waygate_mcp::origin::OriginPolicy::from_config(
            &public_url,
            configured_origins.as_deref(),
        )?;

        let eager_tools_list = waygate_core::env::bool_default_off("GATEWAY_EAGER_TOOLS_LIST");
        let codemode_result_storage = CodeModeResultStorage::parse(
            std::env::var("GATEWAY_CODEMODE_RESULT_STORAGE")
                .ok()
                .as_deref(),
        )?;
        if codemode_result_storage.allows_persistence() && database_url.is_none() {
            anyhow::bail!("GATEWAY_CODEMODE_RESULT_STORAGE=allow requires GATEWAY_DATABASE_URL");
        }
        let codemode_limits = codemode_limits::from_env()?;
        let codemode_capacity = CodeModeCapacityLimits::from_limits(&codemode_limits)?;
        let (eager_tools_clients, codemode_only_tools_clients) =
            client_tool_projection::from_env(eager_tools_list)?;
        let root_composition_clients = client_tool_projection::normalize_client_names(
            waygate_core::env::csv_default("GATEWAY_ROOT_COMPOSITION_CLIENTS", &[]),
        );

        let audit_discovery = waygate_core::env::bool_default_off("GATEWAY_AUDIT_DISCOVERY");

        let (upstream_reconnect_base, upstream_reconnect_ceiling) = reconnect::policy_from_env()?;

        // Cleanup-budget bound (axum drain + pool close). Default 20s
        // leaves ~10s headroom inside the typical 30s
        // `terminationGracePeriodSeconds` for the process to log + exit
        // before the orchestrator escalates to SIGKILL — a default equal
        // to the grace period would leave no margin. Floor 1s (shorter ≡
        // "no drain"; clients lose in-flight every restart). Ceiling 600s
        // (a deployer needing more is almost certainly papering over a
        // stuck handler that should be debugged).
        let drain_timeout =
            waygate_core::env::duration_secs("GATEWAY_DRAIN_TIMEOUT_SECONDS", 20, 1..=600, "")?;

        // Floor: the sweeper does an indexed scan each tick; running it more
        // than once per minute is overkill (rotation is days-scale) and a
        // misconfigured tight loop would burn DB CPU for no benefit.
        let reencrypt_interval = waygate_core::env::duration_secs_zero_disables(
            "GATEWAY_UPSTREAM_REENCRYPT_INTERVAL_SECONDS",
            3600,
            60,
            "set 0 to disable, otherwise pick ≥60s — the sweep is cheap but not free",
        )?;

        let peer_jwks_refresh_interval = waygate_core::env::duration_secs(
            "GATEWAY_PEER_JWKS_REFRESH_INTERVAL_SECONDS",
            600,
            30..=u64::MAX,
            "",
        )?;

        let session_keepalive = waygate_core::env::duration_secs_zero_disables(
            "GATEWAY_SESSION_KEEPALIVE_SECONDS",
            7 * 24 * 3600,
            60,
            "use 0 to disable",
        )?;

        let sse_keepalive = waygate_core::env::duration_secs_zero_disables(
            "GATEWAY_SSE_KEEPALIVE_SECONDS",
            120,
            5,
            "use 0 to disable",
        )?;

        let mcp_ping_interval = waygate_core::env::duration_secs_zero_disables(
            "GATEWAY_MCP_PING_INTERVAL_SECONDS",
            120,
            10,
            "use 0 to disable",
        )?;

        let upstream_call_timeout = waygate_core::env::duration_secs_zero_disables(
            "GATEWAY_UPSTREAM_CALL_TIMEOUT_SECONDS",
            300,
            5,
            "use 0 to disable",
        )?;
        let resource_response_max_bytes = resource_response::from_env()?;
        let file_transfer = FileTransferConfig::from_env(database_url.is_some())?;

        // HITL grant sweeper cadence + retention.
        // Defaults to 1h interval / 7d retention. `0`s disables
        // the interval (no sweep). The interval has a 60s floor
        // matching the re-encrypt sweeper — the sweep does a full
        // DELETE scan, cheap at idle but not zero-cost.
        let grant_sweep_interval = waygate_core::env::duration_secs_zero_disables(
            "GATEWAY_GRANT_SWEEP_INTERVAL_SECONDS",
            3600,
            60,
            "use 0 to disable, otherwise pick ≥60s — the sweep is a DELETE scan",
        )?;
        // Ceiling: the value is multiplied into seconds below; capping the
        // range at u64::MAX / 86_400 makes the multiply provably
        // non-overflowing, so an absurd value is a boot error rather than a
        // silent wrap.
        let grant_retention_days = waygate_core::env::u64_in(
            "GATEWAY_GRANT_RETENTION_DAYS",
            7,
            0..=u64::MAX / 86_400,
            "days; multiplied into seconds internally",
        )?;
        let grant_retention = Duration::from_secs(grant_retention_days * 24 * 3600);

        // HITL push hub broadcast capacity.
        // Default 256 — comfortable for a small operator team.
        // Floor 1 (a zero-cap broadcast channel is a footgun),
        // ceiling 65_536 (above that pick a real queue).
        let hitl_ws_buffer =
            waygate_core::env::u64_in("GATEWAY_HITL_WS_BUFFER", 256, 0..=usize::MAX as u64, "")?
                as usize;
        if hitl_ws_buffer == 0 {
            anyhow::bail!(
                "GATEWAY_HITL_WS_BUFFER=0 is invalid; pick a positive integer (default 256)"
            );
        }
        if hitl_ws_buffer > 65_536 {
            anyhow::bail!(
                "GATEWAY_HITL_WS_BUFFER={hitl_ws_buffer} above 65536 ceiling — \
                 an in-process broadcast that large probably wants a real queue"
            );
        }

        // Evidence outbox drain worker cadence.
        // Default 30s — short enough to catch up quickly after a
        // transient exporter outage; not so short the idle path
        // burns DB round-trips. `0` disables. Floor 5s to bound
        // a misconfigured tight loop.
        let evidence_drain_interval = waygate_core::env::duration_secs_zero_disables(
            "GATEWAY_EVIDENCE_DRAIN_INTERVAL_SECONDS",
            30,
            5,
            "use 0 to disable, otherwise pick ≥5s",
        )?;
        let retention_sweep_interval = crate::retention_config::sweep_interval_from_env()?;

        // Tier-2: cadence of the audit rollup worker that keeps
        // `audit_rollup_hourly` current for wide-window dashboard reads.
        // Default 60s (Q4: ~1-min currency). Unlike the retention sweep this
        // is default-ON. Steady-state ticks recompute only the recent
        // (in-window) hours and are cheap; the FIRST tick after a deploy/reset
        // does a one-time full backfill (it scans all of audit_log to populate
        // historical hours). `0` disables it; floor 10s so a mistyped tiny
        // value can't busy-loop the fold.
        let audit_rollup_interval = waygate_core::env::duration_secs_zero_disables(
            "GATEWAY_AUDIT_ROLLUP_INTERVAL_SECONDS",
            60,
            10,
            "use 0 to disable",
        )?;

        let evidence_webhook_url = std::env::var("GATEWAY_EVIDENCE_WEBHOOK_URL")
            .ok()
            .filter(|s| !s.trim().is_empty());
        // HITL control-plane out-of-band change-proposed webhook. Empty
        // string treated as absent, matching the other optional-URL env vars.
        let hitl_webhook_url = std::env::var("GATEWAY_HITL_WEBHOOK_URL")
            .ok()
            .filter(|s| !s.trim().is_empty());
        // Grafana Explore → Tempo URL template for the
        // activity-drawer "View trace" link. Empty string treated as absent,
        // matching the other optional-URL env vars.
        let trace_url_template = std::env::var("GATEWAY_TRACE_URL_TEMPLATE")
            .ok()
            .filter(|s| !s.trim().is_empty());
        // OCSF exporter destination. Same
        // empty-string-treated-as-absent convention as
        // GATEWAY_EVIDENCE_WEBHOOK_URL so operators using
        // env files can leave the var present-but-empty
        // without accidentally trying to POST to an empty URL.
        let evidence_ocsf_url = std::env::var("GATEWAY_EVIDENCE_OCSF_URL")
            .ok()
            .filter(|s| !s.trim().is_empty());
        // Opt-in OWASP AOS trace enrichment
        // on the OCSF exporter. Default false (no schema
        // change for existing SIEM destinations).
        let evidence_ocsf_aos_trace = waygate_core::env::bool_default_off("GATEWAY_OCSF_AOS_TRACE");
        // Syslog exporter env. Target
        // (host:port) is the activation switch; hostname,
        // facility, PEN are knobs with sensible defaults.
        let evidence_syslog_target = std::env::var("GATEWAY_EVIDENCE_SYSLOG_TARGET")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let evidence_syslog_hostname = std::env::var("GATEWAY_EVIDENCE_SYSLOG_HOSTNAME")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "mcp-gateway".to_owned());
        let evidence_syslog_facility = waygate_core::env::u64_in(
            "GATEWAY_EVIDENCE_SYSLOG_FACILITY",
            16,
            0..=23,
            "16 = local0; see RFC 5424 §6.2.1",
        )? as u8;
        let evidence_syslog_pen = waygate_core::env::u64_in(
            "GATEWAY_EVIDENCE_SYSLOG_PEN",
            32_473,
            0..=u32::MAX as u64,
            "IANA PEN",
        )? as u32;
        // Bundle signing key + optional id.
        // Same empty-string-treated-as-absent convention.
        // The PEM stays in env (and lives in memory inside
        // BundleSigner after parse); never logged.
        let evidence_bundle_signing_key_pem =
            std::env::var("GATEWAY_EVIDENCE_BUNDLE_SIGNING_KEY_PEM")
                .ok()
                .filter(|s| !s.trim().is_empty());
        let evidence_bundle_signing_key_id =
            std::env::var("GATEWAY_EVIDENCE_BUNDLE_SIGNING_KEY_ID")
                .ok()
                .filter(|s| !s.trim().is_empty());
        // ECS exporter destination. Same
        // empty-string-treated-as-absent convention.
        let evidence_ecs_url = std::env::var("GATEWAY_EVIDENCE_ECS_URL")
            .ok()
            .filter(|s| !s.trim().is_empty());

        let evidence_outbox_targets = parse_evidence_outbox_targets(
            &std::env::var("GATEWAY_EVIDENCE_OUTBOX_TARGETS").unwrap_or_default(),
        )?;

        let api_keys = ApiKeysConfig::from_env()?;
        if api_keys.is_some() && database_url.is_none() {
            anyhow::bail!(
                "GATEWAY_API_KEYS_ENABLED=true requires GATEWAY_DATABASE_URL — the \
                 `api_keys` table lives in Postgres (see migrations/0004_api_keys.sql)"
            );
        }

        let deployment_profile = deployment_profile_from_env()?;
        let audit_mode = audit_mode_from_env()?;

        let cfg = Config {
            listen_addr,
            public_url,
            authentik_issuer,
            audience,
            auth_mode,
            otel_endpoint,
            servers_dir,
            skills,
            policy_editing,
            policies_dir,
            database_url,
            database_pools,
            identity,
            introspection,
            dashboard,
            token_exchange,
            as_server,
            accept_upstream_tokens,
            authentik_additional_issuers,
            mcp_allowed_hosts,
            mcp_allowed_origins,
            eager_tools_list,
            codemode_result_storage,
            codemode_capacity,
            codemode_limits,
            eager_tools_clients,
            codemode_only_tools_clients,
            root_composition_clients,
            audit_discovery,
            upstream_reconnect_base,
            upstream_reconnect_ceiling,
            drain_timeout,
            reencrypt_interval,
            peer_jwks_refresh_interval,
            session_keepalive,
            sse_keepalive,
            mcp_ping_interval,
            upstream_call_timeout,
            resource_response_max_bytes,
            file_storage_dir: file_transfer.storage_dir,
            file_retention: file_transfer.retention,
            file_max_bytes: file_transfer.max_bytes,
            file_transfer_concurrency: file_transfer.concurrency,
            mrtr_state_key: crate::continuation_key::key_from_env(),
            api_keys,
            deployment_profile,
            audit_mode,
            grant_sweep_interval,
            grant_retention,
            hitl_ws_buffer,
            evidence_drain_interval,
            retention_sweep_interval,
            audit_rollup_interval,
            evidence_webhook_url,
            hitl_webhook_url,
            trace_url_template,
            evidence_ocsf_url,
            evidence_ocsf_aos_trace,
            evidence_syslog_target,
            evidence_syslog_hostname,
            evidence_syslog_facility,
            evidence_syslog_pen,
            evidence_bundle_signing_key_pem,
            evidence_bundle_signing_key_id,
            evidence_ecs_url,
            evidence_outbox_targets,
        };
        cfg.enforce_prod_safety()
            .context("GATEWAY_DEPLOYMENT_PROFILE=prod safety check")?;
        Ok(cfg)
    }

    /// Prod-profile safety check over `Config` fields that don't require
    /// the manifests. Called automatically at the end of [`Self::from_env`];
    /// also useful in tests that construct a `Config` directly.
    ///
    /// No-op outside [`DeploymentProfile::Prod`].
    pub fn enforce_prod_safety(&self) -> Result<()> {
        if self.deployment_profile != DeploymentProfile::Prod {
            return Ok(());
        }
        if self.auth_mode == AuthMode::Disabled {
            // Defense in depth — the release-build gate in
            // `Self::from_env` already refuses Disabled. This catches a
            // debug binary that someone happened to set the prod profile
            // on (intentionally or by accident).
            anyhow::bail!(
                "GATEWAY_DEPLOYMENT_PROFILE=prod refuses GATEWAY_AUTH_MODE=disabled \
                 (allow-all gate with synthetic admin). Set \
                 GATEWAY_DEPLOYMENT_PROFILE=dev for local, or configure a real IdP."
            );
        }
        if self.accept_upstream_tokens {
            anyhow::bail!(
                "GATEWAY_DEPLOYMENT_PROFILE=prod refuses GATEWAY_ACCEPT_UPSTREAM_TOKENS=true \
                 (token-passthrough anti-pattern; deprecated and slated for removal). \
                 Migrate clients to first-party tokens via the built-in AS \
                 (GATEWAY_AS_ENABLED=true), or set GATEWAY_DEPLOYMENT_PROFILE=dev for local."
            );
        }
        if self.database_url.is_none() {
            anyhow::bail!(
                "GATEWAY_DEPLOYMENT_PROFILE=prod requires GATEWAY_DATABASE_URL — \
                 without it the audit sink is a NullSink and every event is \
                 silently dropped. Set GATEWAY_DEPLOYMENT_PROFILE=dev for local."
            );
        }
        if self.dashboard.is_none() {
            anyhow::bail!(
                "GATEWAY_DEPLOYMENT_PROFILE=prod requires dashboard auth — set all of \
                 GATEWAY_DASHBOARD_CLIENT_ID / _CLIENT_SECRET / _SESSION_KEY, \
                 otherwise /admin is wide open with a synthetic admin principal. \
                 Set GATEWAY_DEPLOYMENT_PROFILE=dev for local."
            );
        }
        Ok(())
    }

    /// Prod-profile safety check that needs the loaded manifests. Call
    /// after `waygate_upstream::load_manifests` in the boot path.
    ///
    /// `Prod` profile: refuses to boot when any manifest uses
    /// `transport: stdio` and names the offending entries.
    ///
    /// `Dev` profile: emits a `tracing::warn!` naming the offending
    /// entries so a local operator gets a heads-up that the same
    /// configuration would be refused under `prod`. Returns `Ok` so the
    /// local-dev workflow keeps working. The "every unsafe-in-prod
    /// choice warns at boot" claim in `docs/deployment.md` depends on
    /// this WARN.
    pub fn enforce_prod_manifest_safety(
        &self,
        manifests: &BTreeMap<String, UpstreamManifest>,
    ) -> Result<()> {
        enforce_prod_manifest_safety_for_profile(self.deployment_profile, manifests)
    }
}

/// Free-function core of [`Config::enforce_prod_manifest_safety`], taking
/// the deployment profile directly. Boot calls the method; the SIGHUP
/// reload task calls this with the `DeploymentProfile` it
/// carries in `ReloadDeps`, so a DB-sourced active bundle that bypassed
/// the importer's gate is still vetted at activation time — without
/// threading a whole `Config` into the long-lived reload task.
pub(crate) fn enforce_prod_manifest_safety_for_profile(
    profile: DeploymentProfile,
    manifests: &BTreeMap<String, UpstreamManifest>,
) -> Result<()> {
    match profile {
        // Canonical refusal lives in `waygate-upstream` so the admin
        // dashboard's in-place reload applies exactly the same gate without a
        // `waygate-admin → waygate-server` dependency, and the security check
        // can't drift between two copies.
        DeploymentProfile::Prod => {
            waygate_upstream::enforce_no_prod_stdio(true, manifests).map_err(|m| anyhow::anyhow!(m))
        }
        DeploymentProfile::Dev => {
            let stdio_names: Vec<&str> = manifests
                .values()
                .filter(|m| matches!(m.transport, Transport::Stdio))
                .map(|m| m.name.as_str())
                .collect();
            if !stdio_names.is_empty() {
                tracing::warn!(
                    stdio_manifests = ?stdio_names,
                    "GATEWAY_DEPLOYMENT_PROFILE=prod would refuse to boot — \
                     upstream manifests use `transport: stdio` and the gateway \
                     provides no sandbox. Acceptable in dev; flag for migration \
                     before deploying with prod profile."
                );
            }
            Ok(())
        }
    }
}

impl ApiKeysConfig {
    /// `Ok(None)` unless `GATEWAY_API_KEYS_ENABLED=true`. Cache TTL
    /// defaults to 60 seconds; floor 5 seconds (anything shorter and the
    /// argon2 cost dominates per-request latency).
    fn from_env() -> Result<Option<Self>> {
        let enabled = waygate_core::env::bool_default_off("GATEWAY_API_KEYS_ENABLED");
        if !enabled {
            return Ok(None);
        }
        let cache_ttl = waygate_core::env::duration_secs(
            "GATEWAY_API_KEYS_CACHE_TTL_SECONDS",
            60,
            5..=u64::MAX,
            "",
        )?;
        Ok(Some(Self { cache_ttl }))
    }
}

impl AsServerConfig {
    /// Returns `Ok(None)` unless `GATEWAY_AS_ENABLED=true`. When enabled,
    /// requires the upstream client credentials and the token-encryption key.
    /// The rest are optional with sensible defaults.
    fn from_env(public_url: &str) -> Result<Option<Self>> {
        let enabled = waygate_core::env::bool_default_off("GATEWAY_AS_ENABLED");
        if !enabled {
            return Ok(None);
        }

        let upstream_client_id = std::env::var("GATEWAY_AS_UPSTREAM_CLIENT_ID")
            .context("GATEWAY_AS_ENABLED=true requires GATEWAY_AS_UPSTREAM_CLIENT_ID")?;
        let upstream_client_secret = std::env::var("GATEWAY_AS_UPSTREAM_CLIENT_SECRET")
            .context("GATEWAY_AS_ENABLED=true requires GATEWAY_AS_UPSTREAM_CLIENT_SECRET")?;
        let upstream_redirect_uri = std::env::var("GATEWAY_AS_UPSTREAM_REDIRECT_URI")
            .unwrap_or_else(|_| format!("{}/oauth/callback", public_url.trim_end_matches('/')));
        let upstream_scopes = std::env::var("GATEWAY_AS_UPSTREAM_SCOPES")
            .ok()
            .map(|s| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
            .unwrap_or_else(|| {
                vec![
                    "openid".into(),
                    "profile".into(),
                    "email".into(),
                    "groups".into(),
                ]
            });
        let (upstream_token_keys, upstream_token_active_id) =
            load_upstream_token_keyring().context("GATEWAY_UPSTREAM_TOKEN_KEY_<id>")?;

        let cimd_allowed_hosts = std::env::var("GATEWAY_AS_CIMD_ALLOWED_HOSTS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .filter(|v: &Vec<String>| !v.is_empty());

        let cimd_dev_doc_dir = std::env::var("GATEWAY_AS_CIMD_DEV_DOC_DIR")
            .ok()
            .map(std::path::PathBuf::from);

        let access_token_ttl = waygate_core::env::duration_secs(
            "GATEWAY_AS_ACCESS_TOKEN_TTL_SECONDS",
            3600,
            0..=u64::MAX,
            "",
        )?;
        let refresh_token_ttl = waygate_core::env::duration_secs(
            "GATEWAY_AS_REFRESH_TOKEN_TTL_SECONDS",
            30 * 86_400,
            0..=u64::MAX,
            "",
        )?;
        let transaction_ttl = waygate_core::env::duration_secs(
            "GATEWAY_AS_TRANSACTION_TTL_SECONDS",
            15 * 60,
            0..=u64::MAX,
            "",
        )?;
        let code_ttl =
            waygate_core::env::duration_secs("GATEWAY_AS_CODE_TTL_SECONDS", 60, 0..=u64::MAX, "")?;

        let allowed_scopes = std::env::var("GATEWAY_AS_ALLOWED_SCOPES")
            .ok()
            .map(|s| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
            .unwrap_or_else(|| {
                vec![
                    "mcp:invoke".into(),
                    "mcp:invoke:high".into(),
                    "mcp:read".into(),
                    "mcp:admin".into(),
                    // The maker scope, so the built-in AS can
                    // mint propose-only tokens for automated callers (a
                    // client following the advertised AS can obtain the
                    // token require_propose checks). Without this the maker
                    // surface is unreachable via the default AS.
                    "mcp:propose".into(),
                    // The read-only observability scope, so the built-in AS can
                    // mint tokens for a monitoring agent reaching the
                    // `gateway-observe.*` read plane. Read-only and tenant-
                    // scoped; never grants mutate authority.
                    "mcp:observe".into(),
                    // SCIM scopes in the
                    // default allowlist so the built-in AS
                    // can mint OAuth tokens carrying SCIM
                    // privileges (when an IdP front-ends
                    // the built-in AS rather than ingest
                    // directly).
                    "scim:read".into(),
                    "scim:write".into(),
                ]
            });

        Ok(Some(Self {
            upstream_client_id,
            upstream_client_secret,
            upstream_redirect_uri,
            upstream_scopes,
            upstream_token_keys,
            upstream_token_active_id,
            cimd_allowed_hosts,
            cimd_dev_doc_dir,
            access_token_ttl,
            refresh_token_ttl,
            transaction_ttl,
            code_ttl,
            allowed_scopes,
        }))
    }
}

/// Load named upstream-token encryption keys from the environment.
/// `GATEWAY_UPSTREAM_TOKEN_KEY_<ID>` supplies each base64-encoded key.
/// IDs are normalized to lowercase. `GATEWAY_UPSTREAM_TOKEN_KEY_ACTIVE_ID`
/// selects the writer key and is optional only for a one-key keyring.
fn load_upstream_token_keyring() -> Result<(Vec<(String, String)>, String)> {
    let mut keyed: Vec<(String, String)> = Vec::new();
    for (k, v) in std::env::vars() {
        let Some(rest) = k.strip_prefix("GATEWAY_UPSTREAM_TOKEN_KEY_") else {
            continue;
        };
        if rest == "ACTIVE_ID" {
            continue;
        }
        keyed.push((rest.to_ascii_lowercase(), v));
    }
    let active_env = std::env::var("GATEWAY_UPSTREAM_TOKEN_KEY_ACTIVE_ID").ok();

    if keyed.is_empty() {
        anyhow::bail!(
            "GATEWAY_AS_ENABLED=true requires at least one GATEWAY_UPSTREAM_TOKEN_KEY_<id> \
             containing a base64-encoded 32-byte key; set GATEWAY_UPSTREAM_TOKEN_KEY_ACTIVE_ID \
             when configuring multiple keys"
        );
    }

    let active = match (active_env, keyed.len()) {
        (Some(id), _) => id.to_ascii_lowercase(),
        // Single-key deployments don't need to set _ACTIVE_ID — the
        // only present id is unambiguously active.
        (None, 1) => keyed[0].0.clone(),
        (None, _) => anyhow::bail!(
            "GATEWAY_UPSTREAM_TOKEN_KEY_<id> set without \
             GATEWAY_UPSTREAM_TOKEN_KEY_ACTIVE_ID. With multiple keys \
             the operator must pick which is active."
        ),
    };

    if !keyed.iter().any(|(id, _)| id == &active) {
        anyhow::bail!(
            "GATEWAY_UPSTREAM_TOKEN_KEY_ACTIVE_ID={active} does not match any \
             configured key. Known ids: {:?}",
            keyed.iter().map(|(id, _)| id).collect::<Vec<_>>()
        );
    }

    Ok((keyed, active))
}

impl TokenExchangeConfig {
    /// All three of `GATEWAY_TOKEN_EXCHANGE_ENDPOINT`, `_CLIENT_ID`,
    /// `_CLIENT_SECRET` required. Missing any ⇒ `Ok(None)` (Tier A off).
    fn from_env() -> Result<Option<Self>> {
        let endpoint = std::env::var("GATEWAY_TOKEN_EXCHANGE_ENDPOINT").ok();
        let client_id = std::env::var("GATEWAY_TOKEN_EXCHANGE_CLIENT_ID").ok();
        let client_secret = std::env::var("GATEWAY_TOKEN_EXCHANGE_CLIENT_SECRET").ok();
        match (endpoint, client_id, client_secret) {
            (Some(e), Some(i), Some(s)) => Ok(Some(Self {
                token_endpoint: e,
                client_id: i,
                client_secret: s,
            })),
            (None, None, None) => Ok(None),
            _ => anyhow::bail!(
                "token exchange partially configured — set all of \
                 GATEWAY_TOKEN_EXCHANGE_ENDPOINT, \
                 GATEWAY_TOKEN_EXCHANGE_CLIENT_ID, \
                 GATEWAY_TOKEN_EXCHANGE_CLIENT_SECRET, or none"
            ),
        }
    }
}

impl DashboardConfig {
    /// Load from env. Any of `GATEWAY_DASHBOARD_CLIENT_ID`,
    /// `GATEWAY_DASHBOARD_CLIENT_SECRET`, or `GATEWAY_DASHBOARD_SESSION_KEY`
    /// unset ⇒ returns `Ok(None)` (dev/disabled dashboard mode). All three
    /// set ⇒ full PKCE + session-cookie auth.
    ///
    /// The redirect URI defaults to `<public_url>/admin/auth/callback` but
    /// can be overridden with `GATEWAY_DASHBOARD_REDIRECT_URI` for split
    /// deployments (e.g., public hostname differs from public_url).
    fn from_env(public_url: &str) -> Result<Option<Self>> {
        let client_id = std::env::var("GATEWAY_DASHBOARD_CLIENT_ID").ok();
        let client_secret = std::env::var("GATEWAY_DASHBOARD_CLIENT_SECRET").ok();
        let session_key_encoded = std::env::var("GATEWAY_DASHBOARD_SESSION_KEY").ok();
        let (client_id, client_secret, session_key_encoded) =
            match (client_id, client_secret, session_key_encoded) {
                (Some(a), Some(b), Some(c)) => (a, b, c),
                (None, None, None) => return Ok(None),
                _ => anyhow::bail!(
                    "dashboard auth partially configured — set all of \
                     GATEWAY_DASHBOARD_CLIENT_ID, GATEWAY_DASHBOARD_CLIENT_SECRET, \
                     GATEWAY_DASHBOARD_SESSION_KEY, or none"
                ),
            };

        let redirect_uri = std::env::var("GATEWAY_DASHBOARD_REDIRECT_URI").unwrap_or_else(|_| {
            format!("{}/admin/auth/callback", public_url.trim_end_matches('/'))
        });

        let secure_cookies = waygate_core::env::bool_default_on("GATEWAY_DASHBOARD_COOKIE_SECURE");

        // The dashboard config carries these as i64 (cookie Max-Age math).
        // u64->i64: the env parser caps at u64::MAX, but a value above
        // i64::MAX seconds (292 billion years) is not a real TTL — reject
        // via the range rather than wrapping.
        let session_ttl_secs = waygate_core::env::duration_secs(
            "GATEWAY_DASHBOARD_SESSION_TTL_SECONDS",
            12 * 3600,
            0..=i64::MAX as u64,
            "",
        )?
        .as_secs() as i64;
        let login_state_ttl_secs = waygate_core::env::duration_secs(
            "GATEWAY_DASHBOARD_LOGIN_STATE_TTL_SECONDS",
            600,
            0..=i64::MAX as u64,
            "",
        )?
        .as_secs() as i64;

        let scopes = std::env::var("GATEWAY_DASHBOARD_SCOPES")
            .ok()
            .map(|s| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
            .unwrap_or_else(|| {
                vec![
                    "openid".into(),
                    "profile".into(),
                    "email".into(),
                    "groups".into(),
                ]
            });

        let allowed_step_up_scopes = std::env::var("GATEWAY_DASHBOARD_ALLOWED_STEP_UP_SCOPES")
            .ok()
            .map(|s| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
            .unwrap_or_else(|| {
                vec![
                    "mcp:invoke:high".into(),
                    // Keeps the Identity-page "Re-authorize with the admin
                    // scope" link in api_keys.html / oauth_clients_section.html
                    // self-consistent with defaults — otherwise login_get
                    // silently drops the requested scope and the user loops
                    // back to the same gate. Membership is gated at the IdP.
                    "mcp:admin".into(),
                ]
            });

        Ok(Some(DashboardConfig {
            client_id,
            client_secret,
            redirect_uri,
            session_key_encoded,
            secure_cookies,
            session_ttl_secs,
            login_state_ttl_secs,
            scopes,
            allowed_step_up_scopes,
        }))
    }
}

impl IdentityConfig {
    /// Load from env. Returns `Ok(None)` when no signing key is configured —
    /// the gateway then starts without minting identity tokens (upstream
    /// integration is deferred).
    ///
    /// Two configuration modes:
    ///
    /// 1. **Single-key (original shape, still supported):**
    ///    `GATEWAY_IDENTITY_SIGNING_KEY_PEM` or
    ///    `GATEWAY_IDENTITY_SIGNING_KEY_PATH` set the one PEM;
    ///    `GATEWAY_IDENTITY_KID` names it (default
    ///    `gateway-v1`). The resulting keyring has one entry,
    ///    that kid is active.
    ///
    /// 2. **Multi-key (rotation):**
    ///    `GATEWAY_IDENTITY_JWT_KEYS=<kid1>:<path1>,<kid2>:<path2>,…`
    ///    declares the keyring; `GATEWAY_IDENTITY_JWT_ACTIVE=<kid>`
    ///    selects the active signing key. Both must be set
    ///    together. When set, the single-key vars are ignored.
    fn from_env() -> Result<Option<Self>> {
        let gateway_id =
            std::env::var("GATEWAY_IDENTITY_GATEWAY_ID").unwrap_or_else(|_| "mcp-gateway".into());
        let ttl =
            waygate_core::env::duration_secs("GATEWAY_IDENTITY_TTL_SECONDS", 60, 0..=u64::MAX, "")?;

        // Prefer the keyring shape when set.
        // Both keys and active must be set together; setting
        // one without the other is a config error (caller
        // probably forgot to flip the active kid during a
        // rotation step).
        //
        // docker-compose interpolation forwards `${VAR:-}` as a
        // literal empty string when the host env is unset, so an
        // existing single-key compose deployment ends up with
        // BOTH new vars present as "" via passthrough. Treat
        // empty-string the same as unset here so those
        // deployments boot cleanly on the single-key fallback
        // below instead of erroring out before reaching it.
        let keyring_csv = std::env::var("GATEWAY_IDENTITY_JWT_KEYS")
            .ok()
            .filter(|s| !s.is_empty());
        let keyring_active = std::env::var("GATEWAY_IDENTITY_JWT_ACTIVE")
            .ok()
            .filter(|s| !s.is_empty());
        match (keyring_csv.as_deref(), keyring_active.as_deref()) {
            (Some(csv), Some(active)) => {
                let keys = parse_identity_keyring_csv(csv)?;
                if !keys.iter().any(|k| k.kid == active) {
                    anyhow::bail!(
                        "GATEWAY_IDENTITY_JWT_ACTIVE={active} not present in \
                         GATEWAY_IDENTITY_JWT_KEYS (kids: {:?})",
                        keys.iter().map(|k| &k.kid).collect::<Vec<_>>()
                    );
                }
                return Ok(Some(IdentityConfig {
                    keys,
                    active_kid: active.to_owned(),
                    gateway_id,
                    ttl,
                }));
            }
            (Some(_), None) | (None, Some(_)) => anyhow::bail!(
                "GATEWAY_IDENTITY_JWT_KEYS and GATEWAY_IDENTITY_JWT_ACTIVE must be set together \
                 (rotation requires the operator to name which key is active)",
            ),
            (None, None) => {}
        }

        // Fall back to the single-key shape.
        let inline = std::env::var("GATEWAY_IDENTITY_SIGNING_KEY_PEM").ok();
        let path = std::env::var("GATEWAY_IDENTITY_SIGNING_KEY_PATH").ok();
        let signing_key_pem = match (inline, path) {
            (Some(_), Some(_)) => anyhow::bail!(
                "set exactly one of GATEWAY_IDENTITY_SIGNING_KEY_PEM or \
                 GATEWAY_IDENTITY_SIGNING_KEY_PATH, not both"
            ),
            (Some(pem), None) => pem,
            (None, Some(p)) => std::fs::read_to_string(&p)
                .with_context(|| format!("read GATEWAY_IDENTITY_SIGNING_KEY_PATH: {p}"))?,
            (None, None) => return Ok(None),
        };

        let kid = std::env::var("GATEWAY_IDENTITY_KID").unwrap_or_else(|_| "gateway-v1".into());

        Ok(Some(IdentityConfig {
            keys: vec![IdentityKeySource {
                pem: signing_key_pem,
                kid: kid.clone(),
            }],
            active_kid: kid,
            gateway_id,
            ttl,
        }))
    }
}

impl IntrospectionEnvConfig {
    /// Load from env. `Ok(None)` ⇒ introspection disabled
    /// (default). The three core vars
    /// (`GATEWAY_INTROSPECTION_URL` / `_CLIENT_ID` /
    /// `_CLIENT_SECRET`) must be set together; missing one is
    /// a fatal config error so an operator who only sets the
    /// URL gets a clear boot failure rather than a silently
    /// dead validator.
    fn from_env() -> Result<Option<Self>> {
        let url = std::env::var("GATEWAY_INTROSPECTION_URL")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let client_id = std::env::var("GATEWAY_INTROSPECTION_CLIENT_ID")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let client_secret = std::env::var("GATEWAY_INTROSPECTION_CLIENT_SECRET")
            .ok()
            .filter(|s| !s.trim().is_empty());
        match (url, client_id, client_secret) {
            (None, None, None) => Ok(None),
            (Some(url), Some(cid), Some(secret)) => {
                let max_positive_ttl = waygate_core::env::duration_secs(
                    "GATEWAY_INTROSPECTION_CACHE_TTL_SECONDS",
                    300,
                    1..=u64::MAX,
                    "0 = always cache-miss, which would hammer the IdP; set 60s if you \
                     want effectively-no-cache",
                )?;
                let negative_ttl = waygate_core::env::duration_secs(
                    "GATEWAY_INTROSPECTION_NEG_CACHE_TTL_SECONDS",
                    30,
                    1..=u64::MAX,
                    "use 1 for effectively-no-cache",
                )?;
                Ok(Some(IntrospectionEnvConfig {
                    introspection_url: url,
                    client_id: cid,
                    client_secret: secret,
                    max_positive_ttl,
                    negative_ttl,
                }))
            }
            _ => anyhow::bail!(
                "GATEWAY_INTROSPECTION_URL, GATEWAY_INTROSPECTION_CLIENT_ID, and \
                 GATEWAY_INTROSPECTION_CLIENT_SECRET must be set together (or all unset). \
                 Setting only some leaves the validator unable to authenticate to the IdP."
            ),
        }
    }
}

/// Parse a `kid:path,kid:path,…` comma-separated list into
/// loaded PEM contents. Whitespace around delimiters is
/// tolerated; empty entries (e.g. trailing commas) are
/// rejected to catch operator typos.
fn parse_identity_keyring_csv(csv: &str) -> Result<Vec<IdentityKeySource>> {
    let mut keys = Vec::new();
    let mut seen_kids = std::collections::HashSet::new();
    for raw in csv.split(',') {
        let entry = raw.trim();
        if entry.is_empty() {
            anyhow::bail!("GATEWAY_IDENTITY_JWT_KEYS: empty entry (check for trailing commas)");
        }
        let (kid, path) = entry.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("GATEWAY_IDENTITY_JWT_KEYS entry {entry:?} must be `<kid>:<path>`")
        })?;
        let kid = kid.trim();
        let path = path.trim();
        if kid.is_empty() || path.is_empty() {
            anyhow::bail!(
                "GATEWAY_IDENTITY_JWT_KEYS entry {entry:?}: kid and path must both be non-empty"
            );
        }
        // Duplicate kids must be rejected here, at parse time — not left
        // for `IdentityKeyring::new` to catch. Downstream, `find` for the
        // active kid picks the first match, and the `verify_only` filter
        // on `k.kid != active_kid` drops both copies of a duplicate active
        // kid, so a duplicate could otherwise reach `IdentityKeyring::new`
        // without ever tripping its `DuplicateKid` invariant. Catching it
        // here lets the operator-facing error name the line.
        if !seen_kids.insert(kid.to_owned()) {
            anyhow::bail!(
                "GATEWAY_IDENTITY_JWT_KEYS: duplicate kid {kid:?} (each rotation kid must \
                 appear exactly once in the CSV)"
            );
        }
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("read identity key for kid {kid:?} from {path}"))?;
        keys.push(IdentityKeySource {
            pem,
            kid: kid.to_owned(),
        });
    }
    if keys.is_empty() {
        anyhow::bail!("GATEWAY_IDENTITY_JWT_KEYS: at least one entry required");
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    //! `enforce_prod_safety` + `enforce_prod_manifest_safety` are pure
    //! functions over `Config` fields; the tests construct `Config`
    //! directly via a small helper rather than mutating process env, so
    //! they're parallelism-safe.
    //!
    //! Environment-parser tests are gated to a serial scope via a mutex so
    //! parallel test runners do not trample each other, and each restores the
    //! values it changed.

    use super::*;
    use crate::client_tool_projection::DEFAULT_EAGER_TOOLS_CLIENTS;
    use waygate_mcp::protocol::RiskTier;
    use waygate_upstream::{ToolClassification, Transport, UpstreamManifest};

    fn base_cfg(profile: DeploymentProfile) -> Config {
        Config {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            public_url: "http://localhost".into(),
            authentik_issuer: None,
            audience: "http://localhost".into(),
            auth_mode: AuthMode::Enforce,
            otel_endpoint: None,
            servers_dir: PathBuf::from("/tmp/none"),
            skills: None,
            policy_editing: true,
            policies_dir: PathBuf::from("/tmp/none"),
            database_url: Some("postgres://test".into()),
            database_pools: DatabasePoolConfig::default(),
            identity: None,
            introspection: None,
            dashboard: Some(DashboardConfig {
                client_id: "id".into(),
                client_secret: "sec".into(),
                redirect_uri: "http://localhost/cb".into(),
                session_key_encoded: "k".into(),
                secure_cookies: true,
                session_ttl_secs: 60,
                login_state_ttl_secs: 60,
                scopes: vec![],
                allowed_step_up_scopes: vec![],
            }),
            token_exchange: None,
            as_server: None,
            accept_upstream_tokens: false,
            authentik_additional_issuers: vec![],
            mcp_allowed_hosts: None,
            mcp_allowed_origins: waygate_mcp::origin::OriginPolicy::from_config(
                "https://gateway.example",
                None,
            )
            .unwrap(),
            eager_tools_list: false,
            codemode_result_storage: CodeModeResultStorage::Disabled,
            codemode_capacity: CodeModeCapacityLimits::default(),
            codemode_limits: crate::codemode_limits::CodeModeLimits::default(),
            eager_tools_clients: DEFAULT_EAGER_TOOLS_CLIENTS
                .iter()
                .map(|client| (*client).to_owned())
                .collect(),
            codemode_only_tools_clients: Vec::new(),
            root_composition_clients: Vec::new(),
            audit_discovery: false,
            upstream_reconnect_base: Duration::from_secs(60),
            upstream_reconnect_ceiling: Duration::from_secs(900),
            drain_timeout: Duration::from_secs(20),
            reencrypt_interval: None,
            peer_jwks_refresh_interval: Duration::from_secs(600),
            session_keepalive: None,
            sse_keepalive: None,
            mcp_ping_interval: None,
            upstream_call_timeout: None,
            resource_response_max_bytes: waygate_mcp::DEFAULT_RESOURCE_RESPONSE_MAX_BYTES,
            file_storage_dir: None,
            file_retention: FileRetention::DEFAULT,
            file_max_bytes: None,
            file_transfer_concurrency: 8,
            mrtr_state_key: None,
            api_keys: None,
            deployment_profile: profile,
            audit_mode: AuditMode::BestEffort,
            grant_sweep_interval: None,
            grant_retention: Duration::from_secs(7 * 24 * 3600),
            hitl_ws_buffer: 256,
            evidence_drain_interval: None,
            retention_sweep_interval: None,
            audit_rollup_interval: None,
            evidence_webhook_url: None,
            hitl_webhook_url: None,
            trace_url_template: None,
            evidence_ocsf_url: None,
            evidence_ocsf_aos_trace: false,
            evidence_syslog_target: None,
            evidence_syslog_hostname: "mcp-gateway".to_owned(),
            evidence_syslog_facility: 16,
            evidence_syslog_pen: 32_473,
            evidence_bundle_signing_key_pem: None,
            evidence_bundle_signing_key_id: None,
            evidence_ecs_url: None,
            evidence_outbox_targets: Vec::new(),
        }
    }

    fn manifest(name: &str, transport: Transport) -> UpstreamManifest {
        // Non-load-bearing fields come from the serde defaults — the same
        // source a parsed production manifest gets them from.
        let base: UpstreamManifest =
            serde_yaml::from_str("name: base\ntransport: http\n").expect("base manifest");
        UpstreamManifest {
            name: name.into(),
            transport,
            url: Some("http://up.local".into()),
            tools: vec![ToolClassification::new("noop", RiskTier::Low, false, false)],
            ..base
        }
    }

    fn manifests(list: Vec<UpstreamManifest>) -> BTreeMap<String, UpstreamManifest> {
        list.into_iter().map(|m| (m.name.clone(), m)).collect()
    }

    #[test]
    fn dev_profile_skips_all_checks() {
        let mut cfg = base_cfg(DeploymentProfile::Dev);
        // Stack every prod-refused condition. Dev profile should pass anyway.
        cfg.auth_mode = AuthMode::Disabled;
        cfg.accept_upstream_tokens = true;
        cfg.database_url = None;
        cfg.dashboard = None;
        cfg.enforce_prod_safety().expect("dev profile is no-op");
        cfg.enforce_prod_manifest_safety(&manifests(vec![manifest("local", Transport::Stdio)]))
            .expect("dev profile is no-op on manifests too");
    }

    #[test]
    fn prod_profile_allows_safe_config() {
        let cfg = base_cfg(DeploymentProfile::Prod);
        cfg.enforce_prod_safety().expect("safe prod config passes");
        let m = manifests(vec![
            manifest("a", Transport::Http),
            manifest("b", Transport::Sse),
        ]);
        cfg.enforce_prod_manifest_safety(&m)
            .expect("http+sse manifests OK in prod");
    }

    #[test]
    fn prod_refuses_auth_disabled() {
        let mut cfg = base_cfg(DeploymentProfile::Prod);
        cfg.auth_mode = AuthMode::Disabled;
        let err = cfg.enforce_prod_safety().unwrap_err().to_string();
        assert!(err.contains("GATEWAY_AUTH_MODE=disabled"), "got: {err}");
    }

    #[test]
    fn prod_refuses_accept_upstream_tokens() {
        let mut cfg = base_cfg(DeploymentProfile::Prod);
        cfg.accept_upstream_tokens = true;
        let err = cfg.enforce_prod_safety().unwrap_err().to_string();
        assert!(
            err.contains("GATEWAY_ACCEPT_UPSTREAM_TOKENS=true"),
            "got: {err}",
        );
    }

    #[test]
    fn prod_refuses_missing_database_url() {
        let mut cfg = base_cfg(DeploymentProfile::Prod);
        cfg.database_url = None;
        let err = cfg.enforce_prod_safety().unwrap_err().to_string();
        assert!(err.contains("GATEWAY_DATABASE_URL"), "got: {err}");
    }

    #[test]
    fn prod_refuses_missing_dashboard_auth() {
        let mut cfg = base_cfg(DeploymentProfile::Prod);
        cfg.dashboard = None;
        let err = cfg.enforce_prod_safety().unwrap_err().to_string();
        assert!(err.contains("dashboard auth"), "got: {err}");
    }

    #[test]
    fn prod_refuses_stdio_manifest_naming_offender() {
        let cfg = base_cfg(DeploymentProfile::Prod);
        let m = manifests(vec![
            manifest("good_http", Transport::Http),
            manifest("local_subprocess", Transport::Stdio),
        ]);
        let err = cfg
            .enforce_prod_manifest_safety(&m)
            .unwrap_err()
            .to_string();
        assert!(err.contains("transport: stdio"), "got: {err}");
        assert!(err.contains("local_subprocess"), "got: {err}");
    }

    /// The free-function gate the SIGHUP reload path applies
    /// behaves identically to the boot method: `stdio` is refused under
    /// prod and accepted (with a warn) under dev. This is what stops a
    /// DB-sourced active bundle that bypassed the importer from
    /// activating a prod-forbidden `transport: stdio` upstream on reload.
    #[test]
    fn manifest_safety_free_fn_gates_stdio_by_profile() {
        let m = manifests(vec![manifest("local_subprocess", Transport::Stdio)]);
        let err = enforce_prod_manifest_safety_for_profile(DeploymentProfile::Prod, &m)
            .unwrap_err()
            .to_string();
        assert!(err.contains("transport: stdio"), "got: {err}");
        assert!(err.contains("local_subprocess"), "got: {err}");
        enforce_prod_manifest_safety_for_profile(DeploymentProfile::Dev, &m)
            .expect("dev profile permits stdio (warns)");
    }

    #[test]
    fn deployment_profile_env_var_parses_dev_and_prod() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("GATEWAY_DEPLOYMENT_PROFILE").ok();

        std::env::remove_var("GATEWAY_DEPLOYMENT_PROFILE");
        assert_eq!(
            deployment_profile_from_env().unwrap(),
            DeploymentProfile::Dev
        );

        std::env::set_var("GATEWAY_DEPLOYMENT_PROFILE", "dev");
        assert_eq!(
            deployment_profile_from_env().unwrap(),
            DeploymentProfile::Dev
        );

        std::env::set_var("GATEWAY_DEPLOYMENT_PROFILE", "prod");
        assert_eq!(
            deployment_profile_from_env().unwrap(),
            DeploymentProfile::Prod
        );

        std::env::set_var("GATEWAY_DEPLOYMENT_PROFILE", "production");
        let err = deployment_profile_from_env().unwrap_err().to_string();
        assert!(err.contains("`dev`"), "got: {err}");
        assert!(err.contains("`prod`"), "got: {err}");

        match prev {
            Some(v) => std::env::set_var("GATEWAY_DEPLOYMENT_PROFILE", v),
            None => std::env::remove_var("GATEWAY_DEPLOYMENT_PROFILE"),
        }
    }

    #[test]
    fn public_url_canonicalised_at_config_load() {
        // RFC 9207 §2.4 requires byte-identical match between every
        // gateway-emitted `iss` (access-token JWT, AS metadata
        // `issuer`, auth-redirect `iss`, token-response `iss`, PRM
        // `authorization_servers`). They all read from
        // `cfg.public_url`, so canonicalising at config load is the
        // single source of truth. Both shapes — with and without
        // trailing slash — must produce the same canonical value.
        //
        // Serialises on ENV_GUARD because we mutate process env.
        let _g = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let prev_public = std::env::var("GATEWAY_PUBLIC_URL").ok();
        let prev_auth = std::env::var("GATEWAY_AUTH_MODE").ok();
        // Disable real validators so from_env runs to completion under
        // a debug build without an IdP set up.
        std::env::set_var("GATEWAY_AUTH_MODE", "disabled");

        std::env::set_var("GATEWAY_PUBLIC_URL", "https://mcp.example/");
        let cfg = Config::from_env().expect("from_env with trailing slash");
        assert_eq!(cfg.public_url, "https://mcp.example");

        std::env::set_var("GATEWAY_PUBLIC_URL", "https://mcp.example");
        let cfg = Config::from_env().expect("from_env without trailing slash");
        assert_eq!(cfg.public_url, "https://mcp.example");

        // Restore.
        match prev_public {
            Some(v) => std::env::set_var("GATEWAY_PUBLIC_URL", v),
            None => std::env::remove_var("GATEWAY_PUBLIC_URL"),
        }
        match prev_auth {
            Some(v) => std::env::set_var("GATEWAY_AUTH_MODE", v),
            None => std::env::remove_var("GATEWAY_AUTH_MODE"),
        }
    }

    #[test]
    fn policy_editing_flag_defaults_on_and_parses_falsey() {
        // `GATEWAY_POLICY_EDITING` is an opt-OUT switch — unset defaults ON,
        // an explicit falsey value turns editing off, and any other value keeps
        // it on. Pins the parse contract so a deploy that means to disable
        // editing must use a recognised falsey string (a typo'd "flase" stays
        // ON, the safe-for-availability default). Serialises on ENV_GUARD.
        let _g = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let prev_edit = std::env::var("GATEWAY_POLICY_EDITING").ok();
        let prev_auth = std::env::var("GATEWAY_AUTH_MODE").ok();
        let prev_public = std::env::var("GATEWAY_PUBLIC_URL").ok();
        // Let from_env run to completion without an IdP.
        std::env::set_var("GATEWAY_AUTH_MODE", "disabled");
        std::env::set_var("GATEWAY_PUBLIC_URL", "https://mcp.example");

        // Unset ⇒ default ON.
        std::env::remove_var("GATEWAY_POLICY_EDITING");
        assert!(
            Config::from_env().unwrap().policy_editing,
            "unset GATEWAY_POLICY_EDITING must default editing ON",
        );

        // Recognised falsey values ⇒ OFF.
        for v in ["0", "false", "no", "off"] {
            std::env::set_var("GATEWAY_POLICY_EDITING", v);
            assert!(
                !Config::from_env().unwrap().policy_editing,
                "`{v}` must turn policy editing OFF",
            );
        }

        // Truthy / any unrecognised value ⇒ stays ON (fail-open for availability).
        for v in ["1", "true", "yes", "on", "flase"] {
            std::env::set_var("GATEWAY_POLICY_EDITING", v);
            assert!(
                Config::from_env().unwrap().policy_editing,
                "`{v}` must keep policy editing ON",
            );
        }

        // Restore.
        match prev_edit {
            Some(v) => std::env::set_var("GATEWAY_POLICY_EDITING", v),
            None => std::env::remove_var("GATEWAY_POLICY_EDITING"),
        }
        match prev_auth {
            Some(v) => std::env::set_var("GATEWAY_AUTH_MODE", v),
            None => std::env::remove_var("GATEWAY_AUTH_MODE"),
        }
        match prev_public {
            Some(v) => std::env::set_var("GATEWAY_PUBLIC_URL", v),
            None => std::env::remove_var("GATEWAY_PUBLIC_URL"),
        }
    }

    #[test]
    fn mcp_origin_environment_controls_browser_admission() {
        let _g = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let names = [
            "GATEWAY_MCP_ALLOWED_ORIGINS",
            "GATEWAY_PUBLIC_URL",
            "GATEWAY_AUTH_MODE",
        ];
        let previous = names.map(std::env::var_os);
        std::env::set_var("GATEWAY_PUBLIC_URL", "https://gateway.example/mcp");
        std::env::set_var("GATEWAY_AUTH_MODE", "disabled");
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "origin",
            axum::http::HeaderValue::from_static("https://gateway.example"),
        );
        std::env::remove_var("GATEWAY_MCP_ALLOWED_ORIGINS");
        assert!(Config::from_env()
            .unwrap()
            .mcp_allowed_origins
            .allows(&headers));
        std::env::set_var("GATEWAY_MCP_ALLOWED_ORIGINS", "https://client.example:8443");
        let policy = Config::from_env().unwrap().mcp_allowed_origins;
        assert!(!policy.allows(&headers));
        headers.insert(
            "origin",
            axum::http::HeaderValue::from_static("https://client.example:8443"),
        );
        assert!(policy.allows(&headers));
        std::env::set_var("GATEWAY_MCP_ALLOWED_ORIGINS", "");
        assert!(!Config::from_env()
            .unwrap()
            .mcp_allowed_origins
            .allows(&headers));
        std::env::set_var("GATEWAY_MCP_ALLOWED_ORIGINS", "https://client.example/path");
        assert!(Config::from_env().is_err());
        for (name, value) in names.into_iter().zip(previous) {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }

    #[test]
    fn sse_keepalive_env_parses_through_from_env_into_rmcp_config() {
        // Pins the whole operator-visible chain: process env →
        // `Config::from_env` → `streamable_http_server_config` → rmcp's
        // `sse_keep_alive` field. The helper-level tests alone can't catch
        // an env-parse regression (they pass the Duration directly), so
        // this one drives the real parse. Serialises on ENV_GUARD because
        // it mutates process env.
        let _g = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        // `var_os`, not `var`: these are opaque save/restore snapshots with
        // no parsing, so the UTF-8-validating reader is the wrong API — and
        // the boot-parse ratchet (scripts/check-env-parsing.sh) counts raw
        // env reads in this file, a count that must stay meaningful as a
        // measure of config parsing, not test fixtures.
        let prev_keepalive = std::env::var_os("GATEWAY_SSE_KEEPALIVE_SECONDS");
        let prev_auth = std::env::var_os("GATEWAY_AUTH_MODE");
        let prev_public = std::env::var_os("GATEWAY_PUBLIC_URL");
        // Let from_env run to completion without an IdP.
        std::env::set_var("GATEWAY_AUTH_MODE", "disabled");
        std::env::set_var("GATEWAY_PUBLIC_URL", "https://mcp.example");

        // Unset ⇒ documented default (120s), heartbeat ON.
        std::env::remove_var("GATEWAY_SSE_KEEPALIVE_SECONDS");
        let cfg = Config::from_env().expect("from_env with keepalive unset");
        assert_eq!(cfg.sse_keepalive, Some(Duration::from_secs(120)));

        // Explicit value ⇒ parsed AND threaded into the rmcp config the
        // composition root builds.
        std::env::set_var("GATEWAY_SSE_KEEPALIVE_SECONDS", "45");
        let cfg = Config::from_env().expect("from_env with keepalive=45");
        assert_eq!(cfg.sse_keepalive, Some(Duration::from_secs(45)));
        let rmcp_cfg = crate::boot::streamable_http_server_config(
            cfg.sse_keepalive,
            tokio_util::sync::CancellationToken::new(),
            vec![],
        );
        assert_eq!(rmcp_cfg.sse_keep_alive, Some(Duration::from_secs(45)));

        // `0` ⇒ disabled end-to-end.
        std::env::set_var("GATEWAY_SSE_KEEPALIVE_SECONDS", "0");
        let cfg = Config::from_env().expect("from_env with keepalive=0");
        assert_eq!(cfg.sse_keepalive, None);
        let rmcp_cfg = crate::boot::streamable_http_server_config(
            cfg.sse_keepalive,
            tokio_util::sync::CancellationToken::new(),
            vec![],
        );
        assert_eq!(rmcp_cfg.sse_keep_alive, None);

        // Below-floor values are a boot error, not a silent clamp.
        std::env::set_var("GATEWAY_SSE_KEEPALIVE_SECONDS", "3");
        assert!(
            Config::from_env().is_err(),
            "sub-floor keepalive must refuse to boot",
        );

        // Restore.
        match prev_keepalive {
            Some(v) => std::env::set_var("GATEWAY_SSE_KEEPALIVE_SECONDS", v),
            None => std::env::remove_var("GATEWAY_SSE_KEEPALIVE_SECONDS"),
        }
        match prev_auth {
            Some(v) => std::env::set_var("GATEWAY_AUTH_MODE", v),
            None => std::env::remove_var("GATEWAY_AUTH_MODE"),
        }
        match prev_public {
            Some(v) => std::env::set_var("GATEWAY_PUBLIC_URL", v),
            None => std::env::remove_var("GATEWAY_PUBLIC_URL"),
        }
    }

    #[test]
    fn mcp_ping_interval_env_parses_through_from_env() {
        // Drives the real parse for `GATEWAY_MCP_PING_INTERVAL_SECONDS`
        // (default, explicit value, 0-disables, sub-floor boot error) so
        // an env-wiring regression can't hide behind builder-level tests.
        // Serialises on ENV_GUARD because it mutates process env; `var_os`
        // snapshots keep the boot-parse ratchet counting parse sites only.
        let _g = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let prev_ping = std::env::var_os("GATEWAY_MCP_PING_INTERVAL_SECONDS");
        let prev_auth = std::env::var_os("GATEWAY_AUTH_MODE");
        let prev_public = std::env::var_os("GATEWAY_PUBLIC_URL");
        // Let from_env run to completion without an IdP.
        std::env::set_var("GATEWAY_AUTH_MODE", "disabled");
        std::env::set_var("GATEWAY_PUBLIC_URL", "https://mcp.example");

        // Unset ⇒ documented default (120s), pings ON.
        std::env::remove_var("GATEWAY_MCP_PING_INTERVAL_SECONDS");
        let cfg = Config::from_env().expect("from_env with ping interval unset");
        assert_eq!(cfg.mcp_ping_interval, Some(Duration::from_secs(120)));

        // Explicit value ⇒ parsed.
        std::env::set_var("GATEWAY_MCP_PING_INTERVAL_SECONDS", "45");
        let cfg = Config::from_env().expect("from_env with ping interval=45");
        assert_eq!(cfg.mcp_ping_interval, Some(Duration::from_secs(45)));

        // `0` ⇒ disabled.
        std::env::set_var("GATEWAY_MCP_PING_INTERVAL_SECONDS", "0");
        let cfg = Config::from_env().expect("from_env with ping interval=0");
        assert_eq!(cfg.mcp_ping_interval, None);

        // Below-floor values are a boot error, not a silent clamp.
        std::env::set_var("GATEWAY_MCP_PING_INTERVAL_SECONDS", "5");
        assert!(
            Config::from_env().is_err(),
            "sub-floor ping interval must refuse to boot",
        );

        // Restore.
        match prev_ping {
            Some(v) => std::env::set_var("GATEWAY_MCP_PING_INTERVAL_SECONDS", v),
            None => std::env::remove_var("GATEWAY_MCP_PING_INTERVAL_SECONDS"),
        }
        match prev_auth {
            Some(v) => std::env::set_var("GATEWAY_AUTH_MODE", v),
            None => std::env::remove_var("GATEWAY_AUTH_MODE"),
        }
        match prev_public {
            Some(v) => std::env::set_var("GATEWAY_PUBLIC_URL", v),
            None => std::env::remove_var("GATEWAY_PUBLIC_URL"),
        }
    }

    /// Keyring loader semantics. These tests mutate
    /// process env so they're serialised on `ENV_GUARD`.
    mod keyring {
        use super::*;

        fn snapshot_env() -> Vec<(String, Option<String>)> {
            [
                "GATEWAY_UPSTREAM_TOKEN_KEY_V1",
                "GATEWAY_UPSTREAM_TOKEN_KEY_V2",
                "GATEWAY_UPSTREAM_TOKEN_KEY_V3",
                "GATEWAY_UPSTREAM_TOKEN_KEY_ACTIVE_ID",
            ]
            .iter()
            .map(|k| ((*k).to_owned(), std::env::var(k).ok()))
            .collect()
        }

        fn restore_env(prev: &[(String, Option<String>)]) {
            for (k, v) in prev {
                match v {
                    Some(s) => std::env::set_var(k, s),
                    None => std::env::remove_var(k),
                }
            }
        }

        fn clear_env() {
            for k in [
                "GATEWAY_UPSTREAM_TOKEN_KEY_V1",
                "GATEWAY_UPSTREAM_TOKEN_KEY_V2",
                "GATEWAY_UPSTREAM_TOKEN_KEY_V3",
                "GATEWAY_UPSTREAM_TOKEN_KEY_ACTIVE_ID",
            ] {
                std::env::remove_var(k);
            }
        }

        #[test]
        fn named_v1_key_preserves_its_id_and_bytes() {
            let _g = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
            let prev = snapshot_env();
            clear_env();
            std::env::set_var("GATEWAY_UPSTREAM_TOKEN_KEY_V1", "test-key-bytes");
            let (keys, active) = load_upstream_token_keyring().unwrap();
            assert_eq!(keys, vec![("v1".into(), "test-key-bytes".into())]);
            assert_eq!(active, "v1");
            restore_env(&prev);
        }

        #[test]
        fn single_keyed_entry_defaults_to_its_id() {
            let _g = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
            let prev = snapshot_env();
            clear_env();
            std::env::set_var("GATEWAY_UPSTREAM_TOKEN_KEY_V2", "k2");
            let (keys, active) = load_upstream_token_keyring().unwrap();
            assert_eq!(keys, vec![("v2".into(), "k2".into())]);
            assert_eq!(
                active, "v2",
                "single-key keyring's only id is the active id"
            );
            restore_env(&prev);
        }

        #[test]
        fn multi_key_requires_explicit_active_id() {
            let _g = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
            let prev = snapshot_env();
            clear_env();
            std::env::set_var("GATEWAY_UPSTREAM_TOKEN_KEY_V1", "k1");
            std::env::set_var("GATEWAY_UPSTREAM_TOKEN_KEY_V2", "k2");
            let err = load_upstream_token_keyring()
                .expect_err("multi-key without ACTIVE_ID must fail loud");
            assert!(
                err.to_string().contains("ACTIVE_ID"),
                "error must name the missing env var: {err}",
            );
            restore_env(&prev);
        }

        #[test]
        fn multi_key_with_active_id_loads() {
            let _g = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
            let prev = snapshot_env();
            clear_env();
            std::env::set_var("GATEWAY_UPSTREAM_TOKEN_KEY_V1", "k1");
            std::env::set_var("GATEWAY_UPSTREAM_TOKEN_KEY_V2", "k2");
            std::env::set_var("GATEWAY_UPSTREAM_TOKEN_KEY_ACTIVE_ID", "v2");
            let (keys, active) = load_upstream_token_keyring().unwrap();
            let mut sorted: Vec<_> = keys.into_iter().collect();
            sorted.sort();
            assert_eq!(
                sorted,
                vec![("v1".into(), "k1".into()), ("v2".into(), "k2".into())]
            );
            assert_eq!(active, "v2");
            restore_env(&prev);
        }

        #[test]
        fn active_id_not_in_keyring_is_rejected() {
            let _g = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
            let prev = snapshot_env();
            clear_env();
            std::env::set_var("GATEWAY_UPSTREAM_TOKEN_KEY_V1", "k1");
            std::env::set_var("GATEWAY_UPSTREAM_TOKEN_KEY_ACTIVE_ID", "v9");
            let err = load_upstream_token_keyring().expect_err(
                "ACTIVE_ID pointing at a missing key must fail loud (operator typo guard)",
            );
            assert!(
                err.to_string().contains("does not match"),
                "error must name the mismatch: {err}",
            );
            restore_env(&prev);
        }

        #[test]
        fn nothing_set_errors_with_actionable_message() {
            let _g = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
            let prev = snapshot_env();
            clear_env();
            let err = load_upstream_token_keyring().expect_err("no key configured must fail loud");
            let msg = err.to_string();
            assert!(msg.contains("GATEWAY_UPSTREAM_TOKEN_KEY_<id>"));
            restore_env(&prev);
        }
    }
}

/// Validate before any recorder can enqueue work for an unsupported exporter.
fn parse_evidence_outbox_targets(raw: &str) -> anyhow::Result<Vec<String>> {
    use waygate_storage::{EcsExporter, OcsfExporter, SyslogExporter, WebhookExporter};
    let supported = [
        WebhookExporter::TARGET,
        OcsfExporter::TARGET,
        EcsExporter::TARGET,
        SyslogExporter::TARGET,
    ];
    let mut targets = Vec::new();
    for (index, ident) in raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .enumerate()
    {
        if !supported.contains(&ident) {
            // A misplaced URL may contain credentials. Only identifier-shaped
            // values are safe to include in the diagnostic.
            let label = if ident.len() <= 64
                && ident
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_:-".contains(&b))
            {
                format!("`{ident}`")
            } else {
                format!("at position {} (invalid identifier)", index + 1)
            };
            anyhow::bail!("GATEWAY_EVIDENCE_OUTBOX_TARGETS has unsupported target {label}; supported targets: {}", supported.join(", "));
        }
        if !targets.iter().any(|target| target == ident) {
            targets.push(ident.to_owned());
        }
    }
    Ok(targets)
}

#[cfg(test)]
mod evidence_target_tests {
    use super::parse_evidence_outbox_targets;

    #[test]
    fn startup_configuration_rejects_unknown_exporter() {
        let _guard = super::ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let keys = [
            "GATEWAY_AUTH_MODE",
            "GATEWAY_PUBLIC_URL",
            "GATEWAY_EVIDENCE_OUTBOX_TARGETS",
        ];
        let previous = keys.map(std::env::var_os);
        std::env::set_var(keys[0], "disabled");
        std::env::set_var(keys[1], "https://gateway.example");
        std::env::set_var(keys[2], "webhook,s3:cold-storage");
        let result = super::Config::from_env();
        for (key, value) in keys.into_iter().zip(previous) {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
        let error = match result {
            Ok(_) => panic!("startup must reject unknown exporters"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("unsupported target `s3:cold-storage`"),
            "{error}"
        );
    }

    #[test]
    fn supported_targets_are_trimmed_and_deduplicated() {
        assert_eq!(
            parse_evidence_outbox_targets("webhook, ocsf,ecs,syslog,webhook").unwrap(),
            ["webhook", "ocsf", "ecs", "syslog"]
        );
        for empty in ["", " , "] {
            assert!(parse_evidence_outbox_targets(empty).unwrap().is_empty());
        }
    }

    #[test]
    fn unsupported_targets_refuse_the_entire_configuration() {
        for raw in ["s3:cold-storage", "webhook,s3:cold-storage"] {
            let error = parse_evidence_outbox_targets(raw).unwrap_err().to_string();
            assert!(error.contains("s3:cold-storage"));
            assert!(error.contains("webhook, ocsf, ecs, syslog"));
        }
        let error =
            parse_evidence_outbox_targets("https://user:synthetic-password@example.invalid")
                .unwrap_err()
                .to_string();
        assert!(!error.contains("synthetic-password"));
    }
}
