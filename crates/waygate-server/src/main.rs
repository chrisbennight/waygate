mod boot;
mod catalog_freshness;
mod change_notify;
mod client_tool_projection;
mod codemode_limits;
mod codemode_spool;
mod config;
mod continuation_key;
mod database;
mod ema;
mod file_transfer;
mod file_transfer_config;
mod health;
mod healthcheck;
mod import_cmd;
mod llm;
mod llm_cred_reload;
mod llm_discovery;
mod mcp_builtin;
mod mcp_codemode;
mod mcp_control;
mod mcp_discovery;
mod mcp_factory;
mod mcp_files;
mod mcp_http_promote;
mod mcp_observe;
mod mcp_preparse_gate;
mod process_mode;
mod reconnect_scheduler;
mod reload;
mod retention_config;
mod skills_git;
mod state;
mod subscription_listen;
// Split-module items remain available at their historical crate-root paths for main and main_tests.
use crate::{boot::*, database::*, reload::*};

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Context;
use axum::Router;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use tokio_util::sync::CancellationToken;
use tower::make::Shared;
use tower::Layer;
use tower_http::normalize_path::NormalizePathLayer;
use tower_http::trace::TraceLayer;

use sqlx::postgres::PgPool;
use waygate_admin::{AdminState, DashboardAuth, DashboardOidcConfig};
use waygate_apikeys::{ApiKeyStore, ApiKeyValidator, ValidatorConfig as ApiKeyValidatorConfig};
use waygate_as::store::{run_sweeper, OauthStore};
use waygate_as::{AsConfig, UpstreamCrypto};
use waygate_authz::{AuthzEngine, CedarEngine, CedarGate, ReloadableCedar};
use waygate_mcp::audit::{NullSink, SharedEvidence};
use waygate_mcp::authz::{AllowAllGate, SharedAuthz};
use waygate_mcp::SharedCatalog;
use waygate_oidc::middleware::bearer_middleware;
use waygate_oidc::{
    AuthAttemptOutcome, AuthAttemptRecorder, BearerLayer, BearerValidator, HeaderValidator,
    IdTokenValidator, IdentityIssuer, JwksProvider, OidcEndpoints, ResourceMetadata, SessionKey,
    SharedIdentityIssuer, SharedIdentityKeyring, TokenCache, TokenExchangeClient,
};
use waygate_storage::{AuditReader, PgAuditSink};
use waygate_upstream::{
    load_manifests, parse_manifest_set, pool::UpstreamPool, ExchangeBundle, UpstreamManifest,
};

use crate::config::{
    AsServerConfig, AuthMode, Config, DeploymentProfile, IdentityConfig, IdentityKeySource,
    TokenExchangeConfig,
};
use crate::state::AppState;

fn main() -> anyhow::Result<()> {
    if process_mode::run_requested()? {
        Ok(())
    } else {
        gateway_main()
    }
}

#[tokio::main]
async fn gateway_main() -> anyhow::Result<()> {
    let _telemetry_guard =
        waygate_telemetry::init(waygate_telemetry::TelemetryConfig::from_env("mcp-gateway"))
            .context("telemetry init")?;

    // `mut` so `build_identity_keyring` can `.take()` the `identity`
    // field out of Config: PEM bytes must not survive into the
    // long-lived Config clone in AppState.
    let mut cfg = Config::from_env().context("config load")?;
    codemode_limits::install(cfg.codemode_limits.clone())?;
    // Validated with the rest of the startup config — before the listener
    // binds and boot activation evidence persists — so a bad value fails
    // the boot at the config stage, never after the serving point.
    let catalog_freshness_cfg = catalog_freshness::CatalogFreshnessConfig::from_env()
        .context("catalog-freshness config load")?;

    // One-shot catalog import. Runs to completion and exits without
    // starting the HTTP server. Detected after config load so it reuses
    // GATEWAY_DATABASE_URL + GATEWAY_SERVERS_DIR.
    if let Some(dir_override) = import_cmd::parse_import_flag() {
        return import_cmd::run(&cfg, dir_override).await;
    }
    // One-shot policy import (policies/*.cedar → published policy_bundles
    // row). Same exit-without-serving shape; reuses GATEWAY_DATABASE_URL +
    // GATEWAY_POLICIES_DIR.
    if let Some(dir_override) = import_cmd::parse_import_policies_flag() {
        return import_cmd::run_policies(&cfg, dir_override).await;
    }
    // One-shot server-bundle import (servers/*.yaml → published
    // server_manifests row). Same exit-without-serving shape; reuses
    // GATEWAY_DATABASE_URL + GATEWAY_SERVERS_DIR. Seeds the durable recovery
    // ledger; boot remains file-first.
    if let Some(dir_override) = import_cmd::parse_import_server_bundle_flag() {
        return import_cmd::run_server_bundle(&cfg, dir_override).await;
    }
    tracing::info!(
        listen = %cfg.listen_addr,
        public = %cfg.public_url,
        auth = ?cfg.auth_mode,
        profile = ?cfg.deployment_profile,
        audit_mode = ?cfg.audit_mode,
        "starting gateway"
    );
    if cfg.accept_upstream_tokens {
        tracing::warn!(
            "DEPRECATED: GATEWAY_ACCEPT_UPSTREAM_TOKENS=true accepts Authentik-issued \
             bearer tokens directly. This is the OAuth `token passthrough` anti-pattern \
             called out in the MCP security best-practices doc. Migrate clients to \
             first-party tokens via the built-in AS (GATEWAY_AS_ENABLED=true); this \
             flag will be removed in a future release."
        );
    }

    // Audit sink first so its isolated control-plane pool is available to
    // build the durable policy store the authz gate now prefers.
    let (audit_sink, audit_reader, database_pools, mut evidence_queue_handle) =
        build_audit_sink(&cfg).await?;
    let db_pool = database_pools.as_ref().map(DatabasePools::control_pool);
    // Stamp every audit row with the active OpenTelemetry trace id by wrapping
    // the sink once at its source; all downstream clones (dispatch path, bearer
    // middleware, sweepers) inherit the stamping. `audit_reader` keeps reading
    // the unwrapped Postgres sink — the decorator is write-side only.
    let audit_sink: SharedEvidence =
        Arc::new(waygate_mcp::audit::TraceStampingRecorder::new(audit_sink));

    let transfer_runtime = file_transfer::TransferRuntime::from_pool(
        db_pool.clone(),
        audit_sink.clone(),
        cfg.file_storage_dir.as_deref(),
    )
    .await?;

    // When a DB is configured, the authz gate loads the active policy
    // bundle from this store, falling back to the on-disk policies dir on
    // a miss / error (dual-read cutover, mirroring the catalog). Without a
    // DB, behaviour is unchanged (filesystem only).
    let policy_store: Option<waygate_policy::SharedPolicyStore> = db_pool.clone().map(|pg| {
        Arc::new(waygate_policy::PgPolicyStore::new(pg)) as waygate_policy::SharedPolicyStore
    });
    // HITL control-plane: the change-request store backs BOTH the REST maker
    // surface (`/api/v1/admin/change_requests/*`, via `AdminState`) AND the
    // built-in `gateway-admin.*` MCP tools (via the per-session
    // `GatewayServer` factory). Build it ONCE here and share the single Arc —
    // same DB-pool gating as every other durable store. `None` ⇒ the REST
    // surface 503s and the MCP tools are not wired.
    let change_request_store: Option<waygate_changeset::SharedChangeRequestStore> =
        db_pool.clone().map(|pg| {
            Arc::new(waygate_changeset::PgChangeRequestStore::new(pg))
                as waygate_changeset::SharedChangeRequestStore
        });
    // HITL control-plane out-of-band notifier fired when a change is
    // proposed. Built once from `GATEWAY_HITL_WEBHOOK_URL` and shared (one
    // Arc) by both the per-session GatewayServer factory (MCP propose) and
    // AdminState (REST propose), so either surface pushes the same heads-up.
    // `None` ⇒ no out-of-band push; the dashboard review queue still surfaces
    // the change.
    let change_notifier: Option<waygate_admin::change_notify::SharedChangeNotifier> =
        match cfg.hitl_webhook_url.clone() {
            None => None,
            // An invalid URL disables the (best-effort) notifier with a warning
            // rather than crashing boot. The error string carries only the
            // parse failure / scheme, never the raw credential-bearing URL.
            Some(url) => match change_notify::WebhookChangeNotifier::new(url) {
                Ok(notifier) => {
                    tracing::info!(
                        "GATEWAY_HITL_WEBHOOK_URL set — proposed change requests POST an \
                         out-of-band summary (binding code + deep link, no params) to the \
                         configured webhook"
                    );
                    Some(Arc::new(notifier) as waygate_admin::change_notify::SharedChangeNotifier)
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "GATEWAY_HITL_WEBHOOK_URL invalid — out-of-band change notifications \
                         disabled (the dashboard review queue still surfaces changes)"
                    );
                    None
                }
            },
        };
    // HITL control-plane: the secret-return channel keyring. A
    // secret-producing change action (e.g. api_key.mint) encrypts the minted
    // secret at rest with this key and the maker retrieves it once via
    // burn-on-read. `GATEWAY_CHANGE_SECRET_KEY` = base64 of 32 bytes; unset
    // ⇒ `None` ⇒ secret-producing executors fail closed (they refuse to mint
    // an orphan the maker could never retrieve). A present-but-INVALID key
    // fails boot loudly — the operator meant to enable the channel.
    let change_secret_crypto: Option<UpstreamCrypto> =
        match std::env::var("GATEWAY_CHANGE_SECRET_KEY") {
            Ok(b64) if !b64.trim().is_empty() => {
                let crypto = UpstreamCrypto::from_base64(b64.trim()).context(
                    "GATEWAY_CHANGE_SECRET_KEY must be base64 of exactly 32 bytes \
                     (AES-256-GCM); fix the value or unset it to disable the \
                     change-request secret channel",
                )?;
                tracing::info!(
                    "GATEWAY_CHANGE_SECRET_KEY set — secret-producing change actions \
                     (e.g. api_key.mint) are enabled; minted secrets are encrypted at \
                     rest and returned to the maker once via burn-on-read"
                );
                Some(crypto)
            }
            _ => None,
        };
    // Durable upstream-manifest store, the manifest analogue of
    // `policy_store`. Under the file-as-truth model it is the history /
    // rollback ledger and a last-resort recovery
    // source — NOT the boot source: `resolve_manifests` loads
    // `servers/*.yaml` directly and consults the store's newest snapshot
    // only when the on-disk set is unreadable. The same handle is threaded
    // into the SIGHUP reload task and the admin write paths (which mirror
    // each published/rolled-back set onto disk and record a snapshot here).
    let manifest_store: Option<waygate_manifest_store::SharedManifestStore> =
        db_pool.clone().map(|pg| {
            Arc::new(waygate_manifest_store::PgManifestStore::new(pg))
                as waygate_manifest_store::SharedManifestStore
        });
    let ResolvedManifests {
        manifests,
        recovered,
    } = resolve_manifests(&cfg.servers_dir, manifest_store.as_ref()).await?;
    // Apply the prod safety policy to either the on-disk or ledger-recovered set.
    cfg.enforce_prod_manifest_safety(&manifests)
        .context("GATEWAY_DEPLOYMENT_PROFILE=prod manifest safety check")?;
    reload::ensure_manifest_snapshot_ready_for_boot(manifest_store.as_ref(), &manifests).await?;
    // A live catalog row overrides legacy manifest risk, side-effect, and PII
    // facts during invocation. Reconcile the exact accepted boot generation
    // before the catalog can be attached to the runtime, or a manifest changed
    // while the gateway was stopped could serve under stale authorization facts.
    // The accepted set has already passed parsing, prod safety, and the
    // coordinated-write snapshot fence above. A catalog failure is therefore a
    // fail-closed boot error, not a reason to attach stale rows.
    if let Some(catalog_pool) = db_pool.as_ref() {
        let stats = import_cmd::reconcile_catalog_from_manifests(catalog_pool, &manifests)
            .await
            .context("reconcile accepted boot manifest generation into catalog")?;
        tracing::info!(
            servers = stats.servers,
            tools = stats.tools,
            quarantined = stats.quarantined,
            "accepted boot manifest generation reconciled into catalog",
        );
    }
    // Per-upstream RFC 9728 resource ids (`{public_url}/servers/<name>`),
    // captured here while `manifests` is still in scope (the pool consumes it
    // below). Used to (a) widen the /mcp bearer validator's accepted audiences so
    // a resource-scoped (EMA-redeemed) token is accepted AND confined to its one
    // upstream, and (b) seed the ID-JAG mint resource allowlist so mint + redeem
    // agree on the canonical resource id format.
    let idjag_resource_base = format!("{}/servers", cfg.public_url.trim_end_matches('/'));
    let idjag_resource_audiences: std::collections::HashMap<String, String> = manifests
        .keys()
        .map(|name| (format!("{idjag_resource_base}/{name}"), name.clone()))
        .collect();
    // Config-health signal: healthy when the live set is the intended
    // on-disk set (`recovered` is None). When boot RECOVERED from the ledger
    // because servers/*.yaml was unreadable, the running set may be stale —
    // start DEGRADED so the dashboard shows the Config STALE banner from the
    // first render, not only after a later failed SIGHUP. The SIGHUP reload
    // task and the dashboard Reload both refresh this signal.
    let config_health: waygate_upstream::SharedConfigHealth =
        std::sync::Arc::new(waygate_upstream::ConfigHealth::default());
    let disk_loaded_cleanly = recovered.is_none();
    match recovered {
        None => config_health.set_healthy(format!(
            "{} upstream(s) loaded from servers/*.yaml",
            manifests.len()
        )),
        Some(detail) => config_health.set_degraded(detail),
    }
    // Reconcile the turnstile pointer to the on-disk hash so an
    // out-of-band edit to servers/*.yaml (or a fresh disk set this replica
    // boots into) doesn't leave the pointer stale — a stale pointer makes
    // every later CAS lose and dashboard saves permanently fail. Only when
    // disk loaded cleanly: a ledger-recovered boot has a broken disk, so its
    // hash is not the authoritative pointer value.
    let replica_id = derive_replica_id();
    tracing::info!(replica_id = %replica_id, "fleet replica id");
    if disk_loaded_cleanly {
        if let Some(store) = manifest_store.as_ref() {
            // Snapshot BEFORE reconcile so the in-flight-write guard reads
            // the pre-reconcile pointer timestamp.
            record_out_of_band_snapshot(store, &manifests, &audit_sink).await;
            reconcile_manifest_pointer(store, &manifests, &audit_sink, "filesystem-boot").await;
        }
    }
    // BUILD the boot activation event now, while `manifests` is in
    // hand (it's moved into the pool below), but DON'T record it yet — boot
    // can still fail building auth/router state or binding the listener, and
    // a persisted "activated" claim for a replica that never served would
    // break the convergence signal. It's recorded after the listener binds.
    // Boot is always a FULL activation (the pool is built fresh from the
    // whole config); built after reconcile/synthesis so the version resolves.
    let boot_activation =
        build_activation_event(manifest_store.as_ref(), &replica_id, &manifests, true).await;
    // Likewise capture the boot fleet-heartbeat inputs now (manifests is
    // moved into the pool below); the UPSERT happens at the serving point
    // so a boot that fails before serving doesn't advertise a live replica.
    let boot_heartbeat = disk_hash_and_version(manifest_store.as_ref(), &manifests).await;
    // The policy analogue of the manifest config-health signal above: a
    // SEPARATE liveness signal for the on-disk POLICY set, so a broken /
    // ledger-recovered `policies/*.cedar` surfaces its own degraded banner
    // instead of the gateway silently serving a stale ledger set. Distinct
    // instance from the manifest `config_health` (they share the
    // `ConfigHealth` type but not the snapshot) so a manifest reload never
    // clobbers a live policy degradation, and vice versa. `build_authz_gate`
    // sets it from the boot load's recovered status.
    let policy_config_health: waygate_upstream::SharedConfigHealth =
        std::sync::Arc::new(waygate_upstream::ConfigHealth::default());
    let (authz_gate, cedar_engine, tenant_policy_hash) = build_authz_gate(
        &cfg,
        policy_store.as_ref(),
        &audit_sink,
        &policy_config_health,
    )
    .await?;
    // Wrap the Cedar gate in a BreakGlassGate when a
    // Postgres pool exists, so an operator-issued
    // single-use token can override a Deny verdict at
    // incident time. The same `SharedBreakGlassStore` is
    // also handed to `AdminState` (see
    // `.with_break_glass_store(...)` below) so admin
    // reads / mints / revokes the same rows the runtime
    // claims. Without a DB pool we keep the bare
    // `authz_gate` — no override path, Deny is final.
    let authz_gate = match db_pool.as_ref() {
        Some(pg) => {
            let store: waygate_authz::SharedBreakGlassStore =
                Arc::new(waygate_authz::PgBreakGlassStore::new(pg.clone()));
            tracing::info!(
                "break-glass override gate wired: Deny verdicts now consult \
                 break_glass_tokens before becoming final",
            );
            Arc::new(waygate_authz::BreakGlassGate::new(
                authz_gate,
                store,
                audit_sink.clone(),
            )) as waygate_mcp::authz::SharedAuthz
        }
        None => authz_gate,
    };
    // Split the active signing issuer from the
    // JWKS-publishing keyring. Downstream sign paths
    // keep the same `SharedIdentityIssuer` shape; the
    // keyring is fed only into the `/.well-known/jwks.json`
    // route so verifiers see every kid the gateway might
    // have signed a still-valid token under.
    let (identity_issuer, identity_keyring) = match build_identity_keyring(&mut cfg)? {
        Some((active, ring)) => (Some(active), Some(ring)),
        None => (None, None),
    };

    let oidc_http = build_oidc_http_clients(&cfg)?;
    let exchange_bundle = build_exchange_bundle(&cfg)?;
    // Build the Tier-A subject-token bundle early so we
    // can chain it onto the pool's builder. Only wired when ALL of:
    //   - the gateway runs its own AS (GATEWAY_AS_ENABLED → cfg.as_server),
    //   - the upstream IdP issuer is known (AUTHENTIK_ISSUER), and
    //   - the audit database is configured (db_pool — same Postgres
    //     instance the AS already uses for upstream_session storage).
    // Otherwise the pool's existing `principal.raw_token` fallback
    // path stays in effect — Tier-A keeps working in legacy / dev
    // modes that haven't moved to durable sessions yet.
    let tier_a_bundle =
        build_tier_a_session_bundle(&cfg, db_pool.as_ref(), oidc_http.as_ref()).await?;
    // Share the durable session store with the admin API (list +
    // revoke endpoints) before the bundle is consumed by the pool
    // builder below. `Arc<dyn _>` so cloning is cheap.
    let admin_upstream_sessions = tier_a_bundle.as_ref().map(|b| b.sessions.clone());
    // Clone the crypto handle too so the background
    // re-encrypt sweeper can use it after the bundle is moved into
    // the pool builder.
    let reencrypt_handles = tier_a_bundle
        .as_ref()
        .map(|b| (b.sessions.clone(), b.crypto.clone()));
    let pool_builder = match (identity_issuer.clone(), exchange_bundle) {
        (Some(issuer), Some(bundle)) => {
            UpstreamPool::connect_with_identity_and_exchange(manifests, issuer, bundle).await
        }
        (Some(issuer), None) => UpstreamPool::connect_with_identity(manifests, issuer).await,
        (None, _) => UpstreamPool::connect(manifests).await,
    }
    .with_call_timeout(cfg.upstream_call_timeout)
    .with_reconnect_policy(cfg.upstream_reconnect_base, cfg.upstream_reconnect_ceiling)
    // Share the gateway's `SharedEvidence` with the upstream pool so
    // reconnect outcomes produce `UpstreamHealth`-category audit rows
    // alongside the existing `tracing` warn/info lines.
    .with_evidence(audit_sink.clone());
    let pool_builder = match tier_a_bundle {
        Some(TierABundle {
            sessions,
            crypto,
            upstream_issuer,
            refresher,
        }) => {
            tracing::info!(
                %upstream_issuer,
                refresh_on_demand = refresher.is_some(),
                "Tier-A durable session lookup enabled: every \
                 identity-forwarding call_tool will consult \
                 user_upstream_sessions for the subject token",
            );
            pool_builder.with_upstream_sessions(sessions, crypto, upstream_issuer, refresher)
        }
        None => pool_builder,
    };
    // Wire the governed-catalog read handle when a Postgres pool exists. Boot
    // has already atomically reconciled the exact accepted manifest set above,
    // so this catalog is authoritative: a miss or read failure refuses the
    // call instead of reviving a withdrawn tool through manifest fallback.
    // Without a DB, the pool keeps pure manifest behaviour.
    // Hoist the governed-catalog store so both the upstream pool's
    // `resolve_invocation_tool` AND the invocation pipeline's HITL
    // `check_approval` stage read from the same handle. `None` when no
    // DB pool: the pool uses manifest classification, while HITL is a
    // no-op only for a manifest tool that authoritatively requires no
    // approval. A manifest tool marked `requires_approval` fails closed
    // because there is no durable grant store to claim from.
    let catalog_store: Option<waygate_catalog::SharedCatalogStore> = db_pool
        .clone()
        .map(|pg| Arc::new(waygate_catalog::PgCatalogStore::new(pg)) as _);
    // Inference-plane model catalog read handle for the read-only
    // `/llm_models` dashboard page. Present whenever a Postgres pool exists;
    // `None` ⇒ the page renders the "store not configured" card (mirrors the
    // catalog/audit gating).
    let llm_model_catalog: Option<waygate_storage::SharedLlmModelCatalog> = db_pool
        .clone()
        .map(|pg| Arc::new(waygate_storage::PgLlmModelCatalog::new(pg)) as _);
    // federated_peers store handle, bound here so both the
    // admin builder (read/write CRUD) and the JWKS refresher
    // (read-only cross-tenant scan) share one Arc instead of
    // constructing two against the same pool.
    let federated_peers_store: Option<waygate_federation::SharedPeersStore> = db_pool
        .clone()
        .map(|pg| std::sync::Arc::new(waygate_federation::PgFederatedPeersStore::new(pg)) as _);
    // In-memory cache populated by the refresher below and
    // consumed by the per-call verifier in the bearer chain.
    // Lives at the composition root so both wiring sites see
    // the same Arc.
    let peer_jwks_cache =
        std::sync::Arc::new(waygate_federation::jwks::InMemoryPeerJwksCache::new());
    let pool_builder = match catalog_store.clone() {
        Some(catalog) => {
            tracing::info!(
                "authoritative governed catalog enabled: catalog misses and read failures \
                 refuse dispatch",
            );
            pool_builder.with_authoritative_catalog(catalog)
        }
        None => pool_builder,
    };
    // Wire the peer JWKS cache into the pool so manifests
    // opting into Tier-C peer assertion via `tier_c_peer:` can
    // resolve the peer's canonical issuer URL at per-call
    // IdentityContext build time. The same `Arc` backs the
    // refresh task (below) and the bearer chain's
    // PeerJwtValidator — one cache, three consumers, populated
    // once per `peer_jwks_refresh_interval`.
    let pool_builder: waygate_upstream::UpstreamPool = pool_builder.with_peer_jwks_cache(
        peer_jwks_cache.clone() as waygate_federation::jwks::SharedPeerJwksCache,
    );
    let pool_builder = match db_pool.clone() {
        Some(pg) => {
            pool_builder
                .with_tool_reviews(Arc::new(
                    waygate_catalog::tool_reviews::PgCatalogStore::new(pg),
                ))
                .await
        }
        None => pool_builder,
    };
    let pool = Arc::new(pool_builder);
    let tool_catalog_epoch = pool.tool_catalog_epoch();
    match cfg.upstream_call_timeout {
        Some(d) => tracing::info!(
            timeout_secs = d.as_secs(),
            "configured upstream call_tool timeout"
        ),
        None => tracing::warn!(
            "GATEWAY_UPSTREAM_CALL_TIMEOUT_SECONDS=0 — upstream call_tool timeout disabled. \
             A wedged upstream stream will hold the per-server serializer mutex indefinitely \
             and block every subsequent call to that upstream until the gateway restarts."
        ),
    }
    // One quota service governs ordinary tool calls and the compatibility
    // helper that creates short-lived file download grants.
    let quota_service: Option<Arc<dyn waygate_quota::QuotaService>> = db_pool.as_ref().map(|pg| {
        Arc::new(waygate_quota::PgQuotaService::new(pg.clone()))
            as Arc<dyn waygate_quota::QuotaService>
    });
    if quota_service.is_some() {
        tracing::info!(
            "rate-limit gate enabled — `check_quota` consults rate_limit_policies + counters"
        );
    }
    let catalog: SharedCatalog = pool.clone();
    let file_transfer::FileServices {
        input_processor: file_input_processor,
        output_processor: file_output_processor,
        tools: gateway_file_tools,
        native_download_authorizer: native_file_download_authorizer,
        native_upload_authorizer: native_file_upload_authorizer,
        admission: file_transfer_admission,
    } = file_transfer::build_file_services(
        transfer_runtime.as_ref(),
        catalog.clone(),
        quota_service.clone(),
        &cfg.public_url,
        cfg.file_retention,
        cfg.file_max_bytes,
        cfg.file_transfer_concurrency,
    )?;
    let ct = CancellationToken::new();
    let skills = skills_git::configure(&cfg, &ct, &tool_catalog_epoch, &db_pool)?;
    let _database_pool_pressure_task = database_pools
        .as_ref()
        .map(|pools| pools.spawn_pressure_monitor(ct.clone()));
    let search_index = pool.search_index().cloned();
    let mcp_allowed_hosts =
        resolve_mcp_allowed_hosts(&cfg.public_url, cfg.mcp_allowed_hosts.as_deref())?;
    tracing::info!(
        allowed_hosts = ?mcp_allowed_hosts,
        source = if cfg.mcp_allowed_hosts.is_some() { "env" } else { "public_url" },
        "configured rmcp host allowlist"
    );
    let eager_tools_list = cfg.eager_tools_list;
    let eager_tools_clients = cfg.eager_tools_clients.clone();
    let codemode_only_tools_clients = cfg.codemode_only_tools_clients.clone();
    let audit_discovery = cfg.audit_discovery;
    let mcp_ping_interval = cfg.mcp_ping_interval;
    // Advertise the `io.modelcontextprotocol/enterprise-managed-authorization`
    // capability in `ServerCapabilities.extensions` only when the operator opted
    // in (`GATEWAY_AS_IDJAG_ADVERTISE=true`) AND the AS + ID-JAG mint/redeem are
    // actually enabled — so the gateway never advertises a grant `/oauth/token`
    // can't service. This mirrors the RFC 8414 metadata advert gate
    // (`idjag_advertise && ema.is_some()`); `ema.is_some()` ⟺ AS enabled +
    // `GATEWAY_AS_IDJAG_ENABLED`.
    let idjag_advertise_ema = cfg.as_server.is_some()
        && waygate_core::env::bool_default_off("GATEWAY_AS_IDJAG_ENABLED")
        && waygate_core::env::bool_default_off("GATEWAY_AS_IDJAG_ADVERTISE");
    client_tool_projection::log_selection(
        eager_tools_list,
        &eager_tools_clients,
        &codemode_only_tools_clients,
    );
    // Stretch the streamable-HTTP idle session timeout past Claude Code's
    // idle-CLI gap. rmcp's `SessionConfig::DEFAULT_KEEP_ALIVE` is 5 minutes;
    // a Claude Code session that idles past that gets a stale Mcp-Session-Id
    // and (per claude-code#27142) never re-handshakes, so the CLI hangs until
    // restart. Operators override via `GATEWAY_SESSION_KEEPALIVE_SECONDS`
    // (0 disables the timeout).
    let session_manager = {
        let mut mgr = LocalSessionManager::default();
        mgr.session_config.keep_alive = cfg.session_keepalive;
        Arc::new(mgr)
    };
    match cfg.session_keepalive {
        Some(d) => tracing::info!(
            keepalive_secs = d.as_secs(),
            "configured streamable-HTTP session idle timeout"
        ),
        None => tracing::warn!(
            "GATEWAY_SESSION_KEEPALIVE_SECONDS=0 — streamable-HTTP session idle \
             timeout disabled. Sessions whose HTTP connection silently drops \
             (e.g. HTTP/2 RST_STREAM) will leak worker tasks."
        ),
    }
    // SSE heartbeat frames on open streams — distinct from the session idle
    // timeout above: this keeps the *stream* itself producing bytes so
    // intermediaries with idle-read timeouts (proxy read_timeout, LB idle
    // timeout) don't reap a healthy-but-quiet connection between tool calls.
    match cfg.sse_keepalive {
        Some(d) => tracing::info!(
            keepalive_secs = d.as_secs(),
            "configured SSE keepalive heartbeat on streamable-HTTP streams"
        ),
        None => tracing::warn!(
            "GATEWAY_SSE_KEEPALIVE_SECONDS=0 — SSE keepalive frames disabled. \
             Idle SSE streams emit no bytes and will be reaped by any \
             intermediary idle timeout (squid read_timeout, nginx \
             proxy_read_timeout, ALB idle timeout)."
        ),
    }
    // Server-initiated MCP pings — the spec's connection-health probe,
    // layered on top of the transport heartbeat above. Per-session loop;
    // stops itself after consecutive unanswered pings so a dead client's
    // session still idle-reaps (outbound pings re-arm the session timer).
    match cfg.mcp_ping_interval {
        Some(d) => tracing::info!(
            ping_interval_secs = d.as_secs(),
            "configured server-initiated MCP ping per session"
        ),
        None => tracing::info!(
            "GATEWAY_MCP_PING_INTERVAL_SECONDS=0 — server-initiated MCP pings \
             disabled; connection health is only observed when clients call."
        ),
    }
    // HITL approval push hub. One per
    // process; both the per-session `DefaultInvocationService`
    // (as the `HitlNotifier`) and the `AdminState`
    // (`hitl_hub` field for the WS route) hold the same
    // `Arc`. Buffer capacity comes from `Config` (with the
    // canonical default + range validation in `from_env`);
    // the operator knob is `GATEWAY_HITL_WS_BUFFER`.
    let hitl_hub = Arc::new(waygate_admin::hitl_ws::ApprovalHub::new(cfg.hitl_ws_buffer));
    // Response-inspector pipeline.
    // Each inspector toggles independently via its own env var
    // (`GATEWAY_PII_REDACT=on`, `GATEWAY_SECRET_REDACT=on`,
    // `GATEWAY_POISONING_REDACT=on`); default off so existing
    // deployments see zero behavior change. Inspectors are
    // stateless + Arc-cheap, so we build the shared Vec once
    // at boot. Order matters: PII first (cheapest, most
    // frequent matches), secrets second, poisoning third
    // (most complex rules — case-insensitive regex with
    // multiple alternations).
    let mut inspectors: Vec<waygate_mcp::inspection::SharedInspector> = Vec::new();
    if std::env::var("GATEWAY_PII_REDACT").as_deref() == Ok("on") {
        // GATEWAY_PII_MODE selects between `block` (default —
        // refuses calls on match) and `redact` (forwards with
        // `[REDACTED:<RULE>]` substitutions). Any value other
        // than `redact` keeps the block behavior so existing
        // deployments under GATEWAY_PII_REDACT=on don't flip
        // semantics on upgrade.
        let redact_mode = std::env::var("GATEWAY_PII_MODE").as_deref() == Ok("redact");
        if redact_mode {
            tracing::info!(
                "GATEWAY_PII_REDACT=on + GATEWAY_PII_MODE=redact — `inspect_response` redacts PII matches in upstream responses"
            );
        } else {
            tracing::info!(
                "GATEWAY_PII_REDACT=on — `inspect_response` blocks responses matching default PII rules"
            );
        }
        inspectors.push(Arc::new(
            waygate_mcp::inspection::pii::PiiInspector::new().with_redaction(redact_mode),
        ) as waygate_mcp::inspection::SharedInspector);
    }
    if std::env::var("GATEWAY_SECRET_REDACT").as_deref() == Ok("on") {
        tracing::info!(
            "GATEWAY_SECRET_REDACT=on — `inspect_response` blocks responses matching default secret rules"
        );
        inspectors.push(
            Arc::new(waygate_mcp::inspection::secrets::SecretsInspector::new())
                as waygate_mcp::inspection::SharedInspector,
        );
    }
    if std::env::var("GATEWAY_POISONING_REDACT").as_deref() == Ok("on") {
        tracing::info!(
            "GATEWAY_POISONING_REDACT=on — `inspect_response` blocks responses matching prompt-injection / tool-poisoning markers"
        );
        inspectors.push(
            Arc::new(waygate_mcp::inspection::poisoning::PoisoningInspector::new())
                as waygate_mcp::inspection::SharedInspector,
        );
    }
    // Parse the discovery targets up front: they gate whether the LLM path is
    // built at all (a discovery-only deployment has no GATEWAY_LLM_MODELS pins
    // but still needs the dispatcher/resolver/`/v1`), and they drive the
    // refresher spawned further below. Parsed once and reused.
    let discovery_targets =
        llm_discovery::parse_targets(&std::env::var("GATEWAY_LLM_DISCOVERY").unwrap_or_default());
    // Build the inference-plane dispatch path. `None` only when neither
    // pins nor discovery are configured (MCP-only, unchanged). Credentials are
    // injected (Infisical) and read by the store; we're a pure consumer (I4).
    // Provider calls are bounded by the same upstream call timeout as MCP tool
    // calls.
    let llm_deps = llm::build_from_env(cfg.upstream_call_timeout, !discovery_targets.is_empty())?;
    // The SAME in-process credential store the dispatcher resolves
    // bearers from, handed to the admin credential-status panel so it reads live
    // pool health (not a separate snapshot that could drift). `None` when no LLM
    // path is configured ⇒ the panel shows the "not configured" card.
    let llm_credentials = llm_deps
        .as_ref()
        .map(|(dispatcher, _resolver)| dispatcher.credentials());
    // The opt-in response inspectors (PII / secret / poisoning) do not yet run
    // over LLM responses — that lands with the streaming-inspector slice, where
    // the inspector applies uniformly to unary and streamed completions. Warn
    // so an operator who has enabled them is not silently surprised.
    if llm_deps.is_some() && !inspectors.is_empty() {
        tracing::warn!(
            "response inspectors are configured but do not yet apply to LLM (/v1) \
             responses; LLM response inspection lands with the streaming-inspector slice"
        );
    }
    // Materialize the configured models into the `llm_models` catalog so
    // the inference plane's governance reads (cost via the usage ledger,
    // budgets via the budget gate, both wired below) and discovery have a
    // DB row per configured model. Idempotent — the upsert is keyed on
    // (tenant, alias) and preserves operator-set costing on conflict — so
    // it is safe on every boot. Skipped when no DB pool is wired
    // (audit-less dev mode); routing still works from the env resolver.
    // Runs before the listener accepts, so no call observes a half-seeded
    // catalog.
    if let Some(pool) = db_pool.as_ref() {
        let rows = llm::configured_model_rows()?;
        if !rows.is_empty() {
            llm::seed_models(pool, &rows).await?;
            tracing::info!(
                models = rows.len(),
                "seeded llm_models catalog from GATEWAY_LLM_MODELS"
            );
        }
    }
    // Load any persisted discovered models from the catalog into the
    // resolver's discovered layer, so a restart after a prior discovery run
    // makes them routable immediately (before the first refresh cycle). Empty
    // until the discovery refresher slice writes discovered rows — until then
    // the resolver resolves env pins only (behavior-preserving). Runs before the
    // listener accepts, so no call observes a half-loaded resolver.
    if let (Some(pool), Some((_, resolver))) = (db_pool.as_ref(), llm_deps.as_ref()) {
        let loaded = llm::boot_load_discovered(pool, resolver).await?;
        if loaded > 0 {
            tracing::info!(
                discovered = loaded,
                "loaded discovered models into the resolver"
            );
        }
    }
    // Spawn the discovery refresher when GATEWAY_LLM_DISCOVERY names at
    // least one target with a wired adapter (OpenRouter today) AND a DB pool +
    // LLM path exist. It fetches each provider's live model list on boot and
    // every interval, upserts the discovered models, reconciles, and reloads the
    // resolver — all in a background task that never blocks the listener. Unset /
    // empty ⇒ discovery is off (the resolver serves env pins only).
    let _llm_discovery_task = match (db_pool.as_ref(), llm_deps.as_ref()) {
        (Some(pool), Some((dispatcher, resolver))) => {
            let targets = discovery_targets;
            if targets.is_empty() {
                None
            } else {
                let interval = waygate_core::env::duration_secs(
                    "GATEWAY_LLM_DISCOVERY_INTERVAL_SECS",
                    llm_discovery::DEFAULT_INTERVAL_SECS,
                    llm_discovery::MIN_INTERVAL_SECS..=u64::MAX,
                    "how often the discovery refresher re-fetches provider model lists",
                )?;
                // A bounded client: a discovery GET is unary, so a total request
                // timeout is safe (unlike the streaming chat client).
                let http =
                    waygate_core::http_client::builder(waygate_core::http_client::Profile::Slow)
                        .build()
                        .map_err(|e| anyhow::anyhow!("building the discovery HTTP client: {e}"))?;
                let credentials = dispatcher.credentials();
                // The SAME handle dispatch reads for the /responses User-Agent:
                // the refresher keeps it current with the listing's version.
                let codex_ua = dispatcher.codex_ua_version();
                let pool = pool.clone();
                let resolver = resolver.clone();
                let shutdown = ct.clone();
                tracing::info!(
                    targets = targets.len(),
                    interval_secs = interval.as_secs(),
                    "spawning llm discovery refresher"
                );
                Some(tokio::spawn(async move {
                    llm_discovery::run_discovery_scheduler(
                        targets,
                        http,
                        credentials,
                        pool,
                        resolver,
                        interval,
                        codex_ua,
                        shutdown.cancelled_owned(),
                    )
                    .await
                }))
            }
        }
        _ => None,
    };
    // The per-call inference usage ledger. Wired only when both
    // an LLM path and a DB pool exist — the sink is consulted only on the LLM
    // dispatch path, and it needs Postgres to write to. Shared by the client
    // and admin try-it pipelines (cloned into both below) so usage is recorded
    // identically regardless of entry point.
    let llm_usage_store: Option<waygate_mcp::SharedLlmUsage> = match (&db_pool, &llm_deps) {
        (Some(pool), Some(_)) => Some(Arc::new(waygate_storage::PgLlmUsageSink::new(pool.clone()))),
        _ => None,
    };
    // The lagging LLM budget gate. Same wiring conditions as the
    // usage ledger — only when an LLM path and a DB pool exist (it reads the
    // llm_budgets + llm_usage tables). Shared by client + admin try-it paths.
    let llm_budget_gate: Option<waygate_mcp::SharedLlmBudgetGate> = match (&db_pool, &llm_deps) {
        (Some(pool), Some(_)) => Some(Arc::new(waygate_storage::PgLlmBudgetGate::new(
            pool.clone(),
        ))),
        _ => None,
    };
    // The per-principal completion cache. Same wiring conditions as the
    // usage ledger / budget gate. Built — and thus available to opt-in
    // models — only when ALL hold: the operator enabled it
    // (GATEWAY_LLM_CACHE_ENABLED, default OFF), a DB pool exists, AND an
    // LLM path exists (it reads/writes the llm_cache table). This is the
    // one place the gateway stores response *content*, so it is opt-in at
    // the system level (this flag) as well as per-model. Whether any given
    // call actually caches is still gated per-model (a model's configured
    // cache TTL); this just makes the cache available. Shared by client +
    // admin try-it paths.
    let llm_cache_enabled = waygate_core::env::bool_default_off("GATEWAY_LLM_CACHE_ENABLED");
    // Per-tenant row cap: evict-oldest beyond this many entries per
    // tenant after each store, so a within-TTL diversity burst can't balloon the
    // table. Default 10k; `0` ⇒ unbounded by count (TTL + sweep only).
    let llm_cache_max_rows = llm_cache_row_cap(waygate_core::env::u64_in(
        "GATEWAY_LLM_CACHE_MAX_ROWS_PER_TENANT",
        DEFAULT_LLM_CACHE_MAX_ROWS_PER_TENANT as u64,
        0..=i64::MAX as u64,
        "per-tenant completion-cache row cap; 0 = unbounded by count",
    )?);
    let llm_cache_store: Option<waygate_mcp::cache::SharedLlmCache> =
        match (llm_cache_enabled, &db_pool, &llm_deps) {
            (true, Some(pool), Some(_)) => {
                tracing::info!(
                    max_rows_per_tenant = ?llm_cache_max_rows,
                    "GATEWAY_LLM_CACHE_ENABLED — per-principal completion cache active for \
                     models with a configured cache TTL"
                );
                Some(Arc::new(
                    waygate_storage::PgLlmCache::new(pool.clone())
                        .with_max_rows_per_tenant(llm_cache_max_rows),
                ))
            }
            (true, _, _) => {
                tracing::warn!(
                    "GATEWAY_LLM_CACHE_ENABLED set, but the completion cache needs both a \
                     database pool and a configured LLM path — caching is OFF"
                );
                None
            }
            (false, _, _) => None,
        };
    // Reclaim expired cache rows on a timer. Spawned only when
    // caching is active (`llm_cache_store` is `Some` ⇒ a DB pool + LLM path both
    // exist) AND the operator left the sweep interval non-zero
    // (`GATEWAY_LLM_CACHE_SWEEP_SECONDS`, default 300; `0` disables). Shares the
    // global cancellation token so SIGTERM drains it cleanly. Reads already
    // filter on expiry, so this only reclaims disk — never affects correctness.
    let llm_cache_sweep = waygate_core::env::duration_secs_zero_disables(
        "GATEWAY_LLM_CACHE_SWEEP_SECONDS",
        300,
        1,
        "completion-cache TTL sweep interval; 0 disables the sweeper",
    )?;
    let _llm_cache_sweeper_task = match (llm_cache_store.is_some(), &db_pool, llm_cache_sweep) {
        (true, Some(pool), Some(interval)) => {
            let pool = pool.clone();
            let shutdown = ct.clone();
            tracing::info!(
                interval_secs = interval.as_secs(),
                "spawning llm cache TTL sweeper",
            );
            Some(tokio::spawn(async move {
                waygate_storage::run_llm_cache_sweep_scheduler(
                    pool,
                    interval,
                    shutdown.cancelled_owned(),
                )
                .await
            }))
        }
        _ => None,
    };
    // Reclaim SCIM user tombstones on a timer. Soft-deleted
    // rows block deprovisioned users via the enricher's tombstone
    // fallback; this GC drops the ones past the retention window
    // (`GATEWAY_SCIM_TOMBSTONE_RETENTION_DAYS`, default 90; `0`
    // disables). Spawned only when a DB pool exists. Pure housekeeping —
    // a retained tombstone keeps blocking, so disabling only grows the
    // table. Shares the global cancellation token for clean SIGTERM.
    // Range cap: the retention is multiplied by 86_400 below, so bound it to
    // preclude the overflow (same guard as GATEWAY_AUDIT_RETENTION_DAYS).
    let scim_tombstone_retention_days = waygate_core::env::u64_in(
        "GATEWAY_SCIM_TOMBSTONE_RETENTION_DAYS",
        90,
        0..=u64::MAX / 86_400,
        "SCIM tombstone retention in days; 0 disables the sweeper",
    )?;
    let _scim_tombstone_sweeper_task = match &db_pool {
        Some(pool) if scim_tombstone_retention_days > 0 => {
            let pool = pool.clone();
            let shutdown = ct.clone();
            let retention = std::time::Duration::from_secs(scim_tombstone_retention_days * 86_400);
            let interval = std::time::Duration::from_secs(86_400);
            tracing::info!(
                retention_days = scim_tombstone_retention_days,
                "spawning SCIM tombstone sweeper",
            );
            Some(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        _ = tokio::time::sleep(interval) => {
                            match waygate_scim::sweep_scim_tombstones(&pool, retention).await {
                                Ok(n) if n > 0 => {
                                    tracing::info!(reclaimed = n, "swept SCIM tombstones")
                                }
                                Ok(_) => {}
                                Err(e) => {
                                    tracing::warn!(error = %e, "SCIM tombstone sweep failed")
                                }
                            }
                        }
                    }
                }
            }))
        }
        _ => None,
    };
    // In-process re-read of externally-refreshed LLM credentials. Spawned
    // only when an LLM path exists (the dispatcher's credential store), a scoped
    // read-only Infisical client is configured (GATEWAY_INFISICAL_*), the reload
    // mapping (GATEWAY_LLM_CRED_RELOAD) is non-empty, AND the interval is > 0.
    // Keeps the Codex access token fresh from Infisical without an
    // in-process OAuth refresh (which would fight the external refresher's
    // single-use rotation). Shares the global cancellation token.
    // Do not initialize an otherwise-unused Infisical transport in MCP-only
    // mode. A configured LLM path owns this optional dependency and is the only
    // path whose startup should fail if its client cannot be built.
    let infisical_read_client = match &llm_credentials {
        Some(_) => llm_cred_reload::InfisicalReadClient::from_env()?,
        None => None,
    };
    let _llm_cred_reload_task = match (&llm_credentials, infisical_read_client) {
        (Some(store), Some(client)) => {
            let entries = llm_cred_reload::parse_reload_config(
                &std::env::var("GATEWAY_LLM_CRED_RELOAD").unwrap_or_default(),
            );
            let reload_interval = waygate_core::env::duration_secs_zero_disables(
                "GATEWAY_LLM_CRED_RELOAD_SECS",
                llm_cred_reload::DEFAULT_RELOAD_SECS,
                1,
                "credential re-read poll interval; 0 disables the poller",
            )?;
            match reload_interval {
                Some(interval) if !entries.is_empty() => {
                    let store = store.clone();
                    let shutdown = ct.clone();
                    // Mark the managed credentials externally-refreshed SYNCHRONOUSLY
                    // here — before the listener accepts traffic below — so `bearer()`
                    // never attempts a doomed in-process refresh on a credential whose
                    // re-read poller hasn't run yet. (Marking inside the spawned task
                    // would race the first request.)
                    llm_cred_reload::mark_external(&store, &entries).await;
                    tracing::info!(
                        interval_secs = interval.as_secs(),
                        entries = entries.len(),
                        "spawning llm credential re-read poller",
                    );
                    Some(tokio::spawn(async move {
                        llm_cred_reload::run_reload_scheduler(
                            client,
                            store,
                            entries,
                            interval,
                            shutdown.cancelled_owned(),
                        )
                        .await
                    }))
                }
                _ => None,
            }
        }
        _ => None,
    };
    // One process-wide admission cache is shared by every per-session MCP
    // service and the dashboard try-it service. The services themselves are
    // constructed independently, but stable approved schemas compile once and
    // total validator residency remains bounded for the process.
    let schema_validator_cache = waygate_mcp::SchemaValidatorCache::shared();
    // Deferred handle to `AdminState`, shared with the built-in MCP
    // propose tool so its propose path can capture the target's freshness token
    // (the execute-time guard needs the target stores `AdminState` holds). The
    // server-factory closure below is defined BEFORE `admin_state` is built, so
    // it captures this empty cell and we fill it once, right after building
    // `admin_state`. Set before the listener accepts connections, so any tool
    // call observes it populated.
    let admin_state_cell: Arc<std::sync::OnceLock<Arc<waygate_admin::AdminState>>> =
        Arc::new(std::sync::OnceLock::new());
    let continuation_sealer = continuation_key::sealer(cfg.mrtr_state_key.as_deref())?;
    let mcp_factory = Arc::new(mcp_factory::McpServerFactory {
        catalog: catalog.clone(),
        catalog_store: catalog_store.clone(),
        authz: authz_gate.clone(),
        audit: audit_sink.clone(),
        index: search_index.clone(),
        tool_catalog_epoch: tool_catalog_epoch.clone(),
        audit_mode: cfg.audit_mode,
        result_storage: cfg.codemode_result_storage,
        execution_limit: mcp_codemode::execution_limit_from_env()?,
        execution_capacity: mcp_codemode::CodeModeExecutionCapacity::shared(cfg.codemode_capacity),
        quota: quota_service.clone(),
        hitl_hub: hitl_hub.clone(),
        inspectors: inspectors.clone(),
        resource_response_max_bytes: cfg.resource_response_max_bytes,
        file_input_processor: file_input_processor.clone(),
        file_output_processor: file_output_processor.clone(),
        source_file_reader: file_transfer::source_file_reader(transfer_runtime.as_ref()),
        continuation_sealer: continuation_sealer.clone(),
        tool_list_cursor_sealer: continuation_key::cursor_sealer(cfg.mrtr_state_key.as_deref())?,
        skills: skills.catalog(),
        reviewed_skills: skills.reviewed(),
        discovery_cursor_sealer: continuation_key::discovery(cfg.mrtr_state_key.as_deref())?,
        gateway_file_tools: gateway_file_tools.clone(),
        native_file_download_authorizer: native_file_download_authorizer.clone(),
        native_file_upload_authorizer: native_file_upload_authorizer.clone(),
        llm_deps: llm_deps.clone(),
        llm_usage_store: llm_usage_store.clone(),
        llm_budget_gate: llm_budget_gate.clone(),
        llm_cache_store: llm_cache_store.clone(),
        schema_validator_cache: schema_validator_cache.clone(),
        change_request_store: change_request_store.clone(),
        codemode_db_pool: db_pool.clone(),
        change_notifier: change_notifier.clone(),
        public_url: cfg.public_url.clone(),
        admin_state_cell: admin_state_cell.clone(),
        eager_tools_list,
        eager_tools_clients: eager_tools_clients.clone(),
        codemode_only_tools_clients: codemode_only_tools_clients.clone(),
        audit_discovery,
        idjag_advertise_ema,
        mcp_ping_interval,
    });
    let mcp_service = StreamableHttpService::new(
        move || mcp_factory.build(),
        session_manager,
        streamable_http_server_config(cfg.sse_keepalive, ct.child_token(), mcp_allowed_hosts),
    );

    // Pass the peer JWKS cache so the bearer
    // chain can include a `PeerJwtValidator` that turns
    // peer-asserted JWTs (iss matches a registered
    // `federated_peers.issuer`) into PeerAssertion-flavored
    // principals. The cache only populates when a peers store
    // is configured; the validator is added even when the
    // cache is empty so a peer registered at runtime starts
    // being trusted on the next refresh cycle without a
    // gateway restart.
    let peer_jwks_cache_for_bearer: waygate_federation::jwks::SharedPeerJwksCache =
        peer_jwks_cache.clone();
    let (bearer_layer, api_key_validator_arc) = build_bearer_layer(
        &cfg,
        identity_keyring.as_ref(),
        db_pool.as_ref(),
        federated_peers_store
            .as_ref()
            .map(|_| peer_jwks_cache_for_bearer),
        idjag_resource_audiences.clone(),
    )
    .await?;
    // Wire the bearer middleware into the gateway-wide `EvidenceRecorder`
    // so every rejected validation produces an `AuthAttempt`-category
    // audit row alongside the existing 401/503 response. Skipping the
    // success path is deliberate — the subsequent `Invocation` row
    // already carries the principal, and recording both would 2× the
    // audit-log volume with no security signal.
    let bearer_layer =
        bearer_layer.with_attempt_recorder(Arc::new(EvidenceAuthAttempts(audit_sink.clone())));
    // When a Postgres pool exists, build the
    // chained principal enricher (SCIM → RBAC) once and share it
    // across every principal-bearing surface — bearer middleware
    // (covers /mcp, /api/v1, /scim/v2) AND the dashboard session
    // middleware. Chain order matters: SCIM runs first so RBAC
    // can read `principal.scim.groups` for group→role mapping.
    // Both stages are best-effort by contract; a store outage
    // leaves the corresponding fields unchanged but still permits
    // the request through. The SCIM-deactivation deny must live in
    // the middleware itself so it applies on every surface, not
    // only Cedar-gated paths.
    // Keep the RbacEnricher in its
    // concrete type so AdminState can call its
    // `invalidate_all()` after a successful mutation. The
    // bearer middleware receives the same Arc via the chained
    // PrincipalEnricher — both reads (middleware) and writes
    // (admin) must see the invalidation for it to take effect.
    let rbac_enricher_concrete: Option<Arc<waygate_rbac::RbacEnricher>> = db_pool
        .as_ref()
        .map(|pg| Arc::new(waygate_rbac::RbacEnricher::new(pg.clone())));
    // Build the tenant enricher in its concrete type so
    // AdminState can call invalidate() after a successful tenant
    // PATCH/DELETE — same pattern as rbac_enricher_concrete.
    let tenant_enricher_concrete: Option<Arc<waygate_tenants::PgTenantEnricher>> = db_pool
        .as_ref()
        .map(|pg| Arc::new(waygate_tenants::PgTenantEnricher::new(pg.clone())));
    // Build the SCIM enricher concretely
    // (like rbac/tenant) so AdminState can call invalidate() after a SCIM
    // user DELETE — the same Arc the chained bearer enricher consumes, so a
    // deprovisioned principal is evicted on every surface, not after the TTL.
    let scim_enricher_concrete: Option<Arc<waygate_scim::PgScimEnricher>> = db_pool
        .as_ref()
        .map(|pg| Arc::new(waygate_scim::PgScimEnricher::new(pg.clone())));
    let principal_enricher: Option<Arc<dyn waygate_oidc::PrincipalEnricher>> =
        db_pool.as_ref().map(|_pg| {
            // Tenant gate runs FIRST so a missing or
            // suspended tenant short-circuits the more expensive
            // SCIM + RBAC lookups (both honor
            // `enrichment_blocked.is_some()` and return early).
            let tenant_enricher: Arc<dyn waygate_oidc::PrincipalEnricher> = tenant_enricher_concrete
                .clone()
                .expect("tenant_enricher_concrete is Some iff db_pool is Some")
                as Arc<dyn waygate_oidc::PrincipalEnricher>;
            let scim_enricher: Arc<dyn waygate_oidc::PrincipalEnricher> = scim_enricher_concrete
                .clone()
                .expect("scim_enricher_concrete is Some iff db_pool is Some")
                as Arc<dyn waygate_oidc::PrincipalEnricher>;
            let rbac_enricher: Arc<dyn waygate_oidc::PrincipalEnricher> = rbac_enricher_concrete
                .clone()
                .expect("rbac_enricher_concrete is Some iff db_pool is Some")
                as Arc<dyn waygate_oidc::PrincipalEnricher>;
            tracing::info!(
                "Tenant + SCIM + RBAC principal enrichers chained (cache TTL = 60s each) — \
                 principals are tenant-gated, SCIM-resolved, and RBAC-resolved on every \
                 gateway surface"
            );
            Arc::new(waygate_rbac::ChainedEnricher::new(vec![
                tenant_enricher,
                scim_enricher,
                rbac_enricher,
            ])) as Arc<dyn waygate_oidc::PrincipalEnricher>
        });
    let bearer_layer = if let Some(e) = principal_enricher.as_ref() {
        bearer_layer.with_principal_enricher(e.clone())
    } else {
        bearer_layer
    };
    // `cfg.public_url` is the gateway's canonical issuer string —
    // `Config::from_env` already trimmed the trailing slash so this
    // value is byte-identical with every other place the gateway
    // emits `iss` (access-token JWT, AS metadata `issuer`,
    // authorization-response redirect, token-response, PRM
    // `authorization_servers`). See the doc on
    // `crates/waygate-server/src/config.rs::Config::from_env` for the
    // single-source-of-truth invariant.
    let resource_metadata_url = format!("{}{}", cfg.public_url, ResourceMetadata::PATH);
    // Resource-metadata `authorization_servers` points at whoever actually
    // mints tokens: the gateway itself in CIMD mode, Authentik otherwise.
    // Pre-CIMD clients that haven't read the resource metadata doc will keep
    // hitting Authentik directly — `accept_upstream_tokens` covers them on
    // the validator side during the cutover.
    let well_known: Router<()> = if cfg.as_server.is_some() {
        waygate_oidc::metadata::router::<()>(ResourceMetadata::with_issuers(
            cfg.public_url.clone(),
            vec![cfg.public_url.clone()],
        ))
    } else {
        match &cfg.authentik_issuer {
            Some(iss) => waygate_oidc::metadata::router::<()>(ResourceMetadata::new(
                cfg.public_url.clone(),
                iss.clone(),
            )),
            None => Router::new(),
        }
    };
    tracing::info!(%resource_metadata_url, "exposing resource metadata");

    let well_known = match identity_keyring.as_ref() {
        Some(keyring) => {
            tracing::info!(
                active_kid = %keyring.active().kid,
                kids = ?keyring.kids(),
                path = waygate_oidc::JWKS_PATH,
                "publishing gateway identity JWKS (rotation-aware)",
            );
            well_known.merge(waygate_oidc::jwks_router::<()>(keyring.clone()))
        }
        None => well_known,
    };

    let as_router = build_as_router(
        &cfg,
        db_pool.as_ref(),
        oidc_http.as_ref(),
        identity_issuer.as_ref(),
        audit_sink.clone(),
        authz_gate.clone(),
        principal_enricher.as_ref(),
        identity_keyring.as_ref(),
        // Seed the mint resource allowlist from the per-upstream
        // resource ids so mint + redeem agree on the canonical format (unioned
        // with any operator GATEWAY_AS_IDJAG_RESOURCES).
        idjag_resource_audiences.keys().cloned().collect(),
        // The shared peer JWKS cache (Tier-C), so redeem can verify a
        // peer-minted ID-JAG against the peer's keys.
        Some(peer_jwks_cache.clone() as waygate_federation::jwks::SharedPeerJwksCache),
    )
    .await?;

    // Frozen-at-boot system info snapshot for the
    // dashboard Settings page. Built once here from the
    // resolved `Config` plus the constructed identity
    // keyring; surface is read-only so the page just
    // re-renders the snapshot. Never carries any secret
    // material — the introspection `client_secret` is
    // deliberately omitted from `IntrospectionSummary`, and
    // the JWKS summary only sees public `kid`s.
    let system_info = Arc::new(build_system_info(&cfg, identity_keyring.as_ref()));

    // Governed "Try this tool" admin surface. Build a second
    // invocation-service handle from the SAME shared builder the
    // per-session MCP dispatch path uses (see the rmcp factory above),
    // so an operator invoking a tool from the dashboard runs the
    // identical authorize → step-up → quota → HITL → audit → redact
    // pipeline a real client would — never a bypass with weaker stages.
    // The service is stateless across calls (all-`Arc` deps), so one
    // handle is safe to reuse for every try-it request. Divergence
    // between this and the client path is impossible by construction:
    // both call `build_default_invocation_service`.
    let admin_try_invocation: waygate_mcp::SharedInvocation =
        waygate_mcp::build_default_invocation_service(
            catalog.clone(),
            authz_gate.clone(),
            audit_sink.clone(),
            cfg.audit_mode,
            catalog_store.clone(),
            quota_service.clone(),
            Some(hitl_hub.clone() as waygate_invocation::SharedHitlNotifier),
            inspectors.clone(),
            file_input_processor.clone(),
            file_output_processor.clone(),
            continuation_sealer.clone(),
            schema_validator_cache.clone(),
            llm_deps.as_ref().map(crate::llm::deps_as_dyn),
            llm_usage_store.clone(),
            llm_budget_gate.clone(),
            llm_cache_store.clone(),
        );

    // Descriptors for the read-only "Built-in surfaces" view. Mirror the
    // per-session registration conditions (the factory closure above) so the
    // Advertise only namespaces the gateway serves. `gateway-admin.*` is
    // conditional; discovery, observability, control, and Code Mode are not.
    let builtin_surfaces = {
        let mut s = vec![
            mcp_discovery::surface_descriptor(),
            mcp_observe::surface_descriptor(),
            mcp_control::surface_descriptor(),
            mcp_codemode::surface_descriptor(),
        ];
        if change_request_store.is_some() {
            s.insert(0, mcp_builtin::surface_descriptor());
        }
        if gateway_file_tools.is_some() {
            s.push(mcp_files::surface_descriptor());
        }
        if cfg.skills.is_some() {
            s.push(waygate_mcp::server::skill_tools::surface_catalog().descriptor());
        }
        s
    };

    // Disk-as-truth editing: editing is offered only when the operator
    // allows it (GATEWAY_POLICY_EDITING, default on) AND the policies dir is
    // actually writable — a dashboard publish mirrors the bundle onto
    // policies/*.cedar, so a read-only live-volume mount would
    // fail at publish. Detect that here and disable editing cleanly with a reason
    // shown in the UI, rather than letting the editor appear then error.
    let policy_editing_off_reason = if !cfg.policy_editing {
        Some(
            "policy editing is turned off (GATEWAY_POLICY_EDITING=off); policies are \
             managed from policies/*.cedar"
                .to_string(),
        )
    } else if policies_dir_writable(&cfg.policies_dir) {
        None
    } else {
        tracing::warn!(
            dir = %cfg.policies_dir.display(),
            "GATEWAY_POLICY_EDITING is on but the policies dir is NOT writable — policy \
             editing DISABLED (mount a writable volume to enable in-place editing)",
        );
        Some(
            "the policies directory is not writable — mount a writable volume to edit \
             policies in place (a publish writes policies/*.cedar)"
                .to_string(),
        )
    };

    let admin_state = Arc::new(
        AdminState::new(
            pool.clone(),
            cedar_engine.clone(),
            audit_reader.clone(),
            // Write-side recorder for admin mutations (API-key lifecycle
            // and the broader `AdminMutation` category used across admin
            // handlers). Reuse the same SharedEvidence the MCP dispatch
            // path uses so every audit row — whatever its category —
            // lands in the same table and exporter pipeline.
            audit_sink.clone(),
            // Wire the admin `ApiKeyStore` whenever a DB pool
            // exists, NOT just when API-key auth is enabled.
            // The store is needed for admin operations (tenant
            // DELETE cleanup's `revoke_all_for_tenant`, ApiKey
            // CRUD panel) regardless of whether the runtime
            // validator is on the bearer chain: gating this on
            // `cfg.api_keys` alone would diverge from
            // `state.identity.api_key_profiles` (wired whenever
            // DB exists), letting a deployment with profiles
            // configured but API-key auth disabled skip
            // `revoke_all_for_tenant` during tenant cleanup —
            // leaving live api_keys rows that migration 0027's
            // trigger then blocks `delete_all_for_tenant` from
            // removing, so the tenant DELETE completes anyway
            // (log-and-continue) and orphans
            // api_keys/api_key_profiles rows that resurrect if
            // the tenant id is recreated and API-key auth is
            // re-enabled. The dashboard panel can still hide
            // itself when `cfg.api_keys` is absent; the wiring
            // here is for the admin substrate, not the UI.
            db_pool.clone().map(waygate_apikeys::ApiKeyStore::new),
            // OAuth session store: same gating shape — only construct when
            // the built-in AS is on AND we have a Postgres pool. The
            // dashboard panel reads from the same `oauth_refresh_tokens`
            // table the AS already writes to, so this is purely a read-side
            // handle for the admin UI.
            cfg.as_server
                .as_ref()
                .and(db_pool.clone().map(waygate_as::store::OauthStore::new)),
            // Tier-A durable session store: same gating as the per-call
            // path (AS enabled + Postgres + upstream IdP issuer), already
            // computed above for the pool builder. `None` ⇒ the admin
            // upstream_sessions endpoints 503 with a clear message.
            admin_upstream_sessions,
            // Governed-catalog read store for the /api/v1/catalog/*
            // admin endpoints. The same Arc the invocation pipeline's
            // HITL stage reads; `None` ⇒ those endpoints 503.
            catalog_store.clone(),
            cfg.public_url.clone(),
        )
        // Durable policy-bundle store for the
        // /api/v1/policy_bundles admin endpoints. Same handle the authz
        // gate loads from; `None` ⇒ those endpoints 503.
        .with_policy_store(policy_store.clone())
        // Inference-plane LLM model catalog for the read-only
        // /llm_models dashboard page. `None` ⇒ the page shows the
        // "store not configured" card.
        .with_llm_model_catalog(llm_model_catalog.clone())
        // The routing resolver for the /chat tester — present ONLY when the
        // LLM plane is mounted (`llm_deps`), so /chat uses it (not the
        // always-wired try_invocation) as its "inference configured" signal and
        // filters its picker to dispatchable models. `None` in MCP-only.
        .with_llm_resolver(llm_deps.as_ref().map(|(_, resolver)| {
            let dyn_resolver: std::sync::Arc<dyn waygate_llm_dispatch::LlmModelResolver> =
                resolver.clone();
            dyn_resolver
        }))
        // The shared credential store (same Arc the dispatcher holds)
        // for the read-only /llm_credentials health panel. `None` ⇒ no LLM
        // path ⇒ the panel shows the "not configured" card.
        .with_llm_credentials(llm_credentials.clone())
        // Durable server-manifest store for the
        // /api/v1/server_manifests admin endpoints. Same handle the boot
        // + SIGHUP resolver reads from; `None` ⇒ those endpoints 503.
        .with_manifest_store(manifest_store.clone())
        // Server-config redesign: the on-disk manifest dir is the
        // source of truth. Hand the admin write surfaces the same
        // `servers_dir` the boot/SIGHUP resolver reads, so a dashboard edit
        // mirrors onto disk (boot/SIGHUP/Reload) before recording a ledger
        // snapshot.
        .with_servers_dir(cfg.servers_dir.clone())
        // The policy analogue — a dashboard / REST policy publish or
        // rollback mirrors the chosen bundle onto `policies/*.cedar` (the
        // boot/SIGHUP source of truth) before recording the ledger transition.
        .with_policies_dir(cfg.policies_dir.clone())
        // Gate dashboard/REST policy mutation on GATEWAY_POLICY_EDITING +
        // the writable-dir probe computed above.
        .with_policy_editing_off_reason(policy_editing_off_reason)
        // The same config-health handle the SIGHUP reload task updates,
        // so the Servers page banner reflects boot/SIGHUP config health.
        .with_config_health(config_health.clone())
        // Dashboard-Reload catalog reconcile: see `import_cmd::catalog_reconcile_callback`.
        .with_catalog_reconcile(db_pool.clone().map(import_cmd::catalog_reconcile_callback))
        // The policy analogue of the config-health handle above: the
        // policy config-health handle set by build_authz_gate (boot) + the
        // reload task (SIGHUP/doorbell/poll), so the Policies page banner
        // reflects boot/reload policy health.
        .with_policy_config_health(policy_config_health.clone())
        // Break-glass store. Same handle is also
        // wrapped around the Cedar gate above (search for
        // `BreakGlassGate::new`) so admin reads / mints and
        // runtime claims see the same rows. `None` ⇒ admin
        // endpoints 503 AND the gate stays unwrapped (Deny is
        // final).
        .with_break_glass_store(db_pool.clone().map(build_break_glass_store))
        // MCP Tasks read-only admin store; `None` withholds that surface.
        // Durable Code Mode stores; `None` makes their admin surfaces unavailable.
        .with_codemode_execution_store(mcp_codemode::shared_execution_store(db_pool.clone()))
        .with_skill_distribution(skills.reviewed())
        .with_skill_catalog(skills.catalog())
        // HITL control-plane change-request store backing the
        // `mcp:propose` maker surface (propose + poll). The SAME Arc the
        // built-in `gateway-admin.*` MCP tools were wired with above, so the
        // REST and MCP surfaces share one queue. `None` ⇒
        // /api/v1/admin/change_requests/* returns 503 and the MCP tools are
        // absent.
        .with_change_request_store(change_request_store.clone())
        // HITL control-plane: the SAME out-of-band notifier the built-in
        // MCP tools were wired with above, so a REST-proposed change pushes
        // the same heads-up. `None` ⇒ no out-of-band push.
        .with_change_notifier(change_notifier.clone())
        // HITL control-plane: the secret-return keyring, enabling
        // secret-producing change actions (api_key.mint) to deliver the
        // minted secret to the maker once via encrypted burn-on-read.
        // `None` ⇒ those executors fail closed.
        .with_change_secret_crypto(change_secret_crypto)
        .with_proposal_file_reader(file_transfer::document_reader(transfer_runtime.as_ref()))
        // Per-tenant inspection-rules
        // store backing the admin CRUD surface. Same
        // DB-pool gating — `None` ⇒
        // /api/v1/admin/inspection_rules/* returns 503.
        // The runtime inspector reads
        // from this same store.
        .with_inspection_rules_store(db_pool.clone().map(|pg| {
            std::sync::Arc::new(
                waygate_dashboard_stores::inspection_rules::PgInspectionRulesStore::new(pg),
            ) as waygate_dashboard_stores::inspection_rules::SharedRulesStore
        }))
        // Per-tenant agent-config store backing the
        // "Gateway Agents" dashboard tab. Same DB-pool gating — `None` ⇒ the
        // tab shows the "store not configured" card.
        .with_agent_configs(db_pool.clone().map(|pg| {
            std::sync::Arc::new(waygate_dashboard_stores::agent_config::PgAgentConfigStore::new(pg))
                as waygate_dashboard_stores::agent_config::SharedAgentConfigStore
        }))
        // Agent-chat conversation persistence. Same
        // DB-pool gating — `None` ⇒ chat still runs a turn but stores nothing.
        .with_conversations(db_pool.clone().map(|pg| {
            std::sync::Arc::new(waygate_storage::PgConversationStore::new(pg))
                as waygate_storage::SharedConversationStore
        }))
        // Governed read-built-in reach for the chat
        // agent. The caller wraps the read-only `gateway-observe` built-in with
        // the SAME Cedar overlay (`authz_gate`) + scope-floor self-gate the MCP
        // request path uses, so an allowlisted `gateway-observe.*` agent call is
        // governed identically. Read-only namespace only — never propose/control.
        .with_assist_read(Some(
            std::sync::Arc::new(mcp_observe::GovernedObserveCaller::new(
                authz_gate.clone(),
                std::sync::Arc::new(mcp_observe::ObserveTools::new(admin_state_cell.clone())),
            )) as waygate_mcp::SharedAssistReadTools,
        ))
        // Federated gateway peer
        // registry backing the admin CRUD surface. Same
        // DB-pool gating — `None` ⇒
        // /api/v1/admin/federated_peers/* returns 503.
        // The JWKS fetcher + peer-assertion
        // validator consume this same store on the
        // dispatch path.
        .with_federated_peers_store(federated_peers_store.clone())
        // Same `Arc` the refresher
        // writes to + bearer chain's PeerJwtValidator reads
        // from, so PATCH / DELETE can immediately evict.
        .with_federated_peers_cache(
            federated_peers_store
                .as_ref()
                .map(|_| peer_jwks_cache.clone() as waygate_federation::jwks::SharedPeerJwksCache),
        )
        // Hand the admin side the same
        // hub the per-session InvocationService publishes
        // to — so the WS route at
        // /api/v1/admin/approval_grants/subscribe sees
        // every event that triggered an
        // `ApprovalRequired` denial.
        .with_hitl_hub(hitl_hub.clone())
        // Governed "Try this tool" invocation handle. Same
        // pipeline the per-session MCP path runs; `None` would disable
        // the dashboard try-it surface, but here it is always wired.
        // Cloned (it's an `Arc`) so the same governed service also backs the
        // `/v1` inference route below.
        .with_try_invocation(admin_try_invocation.clone())
        // OAuth consent grant store backing
        // /api/v1/admin/oauth_consent. Same DB-pool gating as
        // the other admin stores. The AS callback writes to
        // the same table via its own `SharedConsentStore` on
        // `AsState`; admin reads + revokes from the same
        // rows, so this handle and the AS handle must point
        // at the same Postgres pool (they do — both come
        // from `db_pool`). `None` ⇒ admin endpoints 503;
        // the AS callback is unaffected because it constructs
        // its own store when the AS itself is enabled.
        .with_consent_store(db_pool.clone().map(|pg| {
            Arc::new(waygate_as::consent::PgConsentStore::new(pg))
                as waygate_as::consent::SharedConsentStore
        }))
        // Confidential-client registry for the
        // /api/v1/admin/confidential-clients endpoints. Same Postgres pool the
        // redeem path's PgConfidentialClientStore authenticates against; `None`
        // ⇒ those admin endpoints 503.
        .with_confidential_clients(db_pool.clone().map(|pg| {
            Arc::new(waygate_as::PgConfidentialClientStore::new(pg))
                as waygate_as::SharedConfidentialClientStore
        }))
        // Per-tenant evidence routing store for the
        // /api/v1/audit/routing admin endpoints. Present whenever a
        // Postgres pool exists; `None` ⇒ those endpoints 503,
        // matching the audit/catalog/policy pattern. The recorder
        // reads the same table directly via its own pool, so no
        // separate wiring there.
        .with_routing_store(db_pool.clone().map(|pg| {
            Arc::new(waygate_storage::PgRoutingStore::new(pg))
                as Arc<dyn waygate_storage::RoutingStore>
        }))
        // Per-tenant retention policy store for the
        // /api/v1/audit/retention admin endpoints. Same gating as
        // routing — present whenever a Postgres pool exists.
        .with_retention_store(db_pool.clone().map(|pg| {
            Arc::new(waygate_storage::PgRetentionStore::new(pg))
                as Arc<dyn waygate_storage::RetentionStore>
        }))
        // Pool-bound retention sweeper for the
        // /api/v1/audit/sweep admin endpoint. Same gating as the
        // retention store; absence ⇒ the endpoint 503s. DB-level
        // authorisation is gated by migration 0018's role-based
        // SECURITY DEFINER wrapper + marker-coverage check.
        .with_sweeper(db_pool.clone().map(|pg| {
            Arc::new(waygate_storage::PgSweeper::new(pg)) as Arc<dyn waygate_storage::Sweeper>
        }))
        // Bundle signing key. `None` ⇒
        // `POST /api/v1/audit/bundle` 503s with a "key not
        // configured" message. Construction failure (invalid
        // PEM, wrong key type) is fatal at boot — the
        // operator set the env var; if it's malformed we
        // refuse to start rather than silently serving
        // unsigned-bundle 500s.
        .with_bundle_signer(cfg.evidence_bundle_signing_key_pem.as_deref().map(|pem| {
            let signer = waygate_storage::BundleSigner::from_pem(
                pem,
                cfg.evidence_bundle_signing_key_id.clone(),
            )
            .expect("GATEWAY_EVIDENCE_BUNDLE_SIGNING_KEY_PEM must be a valid PKCS8 Ed25519 PEM");
            tracing::info!(
                signing_key_id = %signer.signing_key_id,
                "evidence bundle signer configured",
            );
            Arc::new(signer)
        }))
        // SCIM 2.0 Users store backing
        // `/scim/v2/Users`. Same DB-pool gating as the
        // other Postgres-backed stores.
        .with_scim_users(db_pool.clone().map(|pg| {
            Arc::new(waygate_scim::PgScimUserStore::new(pg)) as Arc<dyn waygate_scim::ScimUserStore>
        }))
        // SCIM Groups store backing
        // /scim/v2/Groups. Same DB-pool gating.
        .with_scim_groups(db_pool.clone().map(|pg| {
            Arc::new(waygate_scim::PgScimGroupStore::new(pg))
                as Arc<dyn waygate_scim::ScimGroupStore>
        }))
        // RBAC store backing /api/v1/admin/rbac/*.
        // Same DB-pool gating as the SCIM stores. The read-side
        // `PgRbacStore::new(...)` is already wired into the
        // chained enricher above; this exposes it for the admin write
        // surface too. Absence ⇒ admin RBAC endpoints 503.
        .with_rbac_store(db_pool.clone().map(|pg| {
            Arc::new(waygate_rbac::PgRbacStore::new(pg)) as Arc<dyn waygate_rbac::RbacStore>
        }))
        // Same enricher instance
        // the bearer middleware uses, so admin mutations can
        // invalidate the resolver cache rather than waiting
        // for the 60s TTL.
        .with_rbac_enricher(rbac_enricher_concrete.clone())
        // SCIM `(tenant, sub) → ResolvedPrincipal`
        // resolver for the dashboard's "effective permissions
        // for subject" lookup. Same DB-pool gating as the SCIM
        // stores above. The dashboard uses a fresh
        // `PgScimResolver` rather than reaching into the
        // bearer middleware's cached `PgScimEnricher` — the
        // enricher's `moka` cache is keyed on the request's
        // own principal lookup, not on arbitrary admin
        // queries, so admin-driven introspection bypasses it
        // intentionally to avoid surprising cache pollution
        // from operator typing.
        .with_scim_resolver(db_pool.clone().map(|pg| {
            Arc::new(waygate_scim::PgScimResolver::new(pg)) as Arc<dyn waygate_scim::ScimResolver>
        }))
        // Per-tenant Cedar playground saved-scenarios
        // store. Same DB-pool gating as the other admin stores;
        // absence ⇒ the playground page hides the Save / Load /
        // Delete affordances and the page stays stateless. No
        // runtime path reads this table — it's
        // purely a dashboard surface.
        .with_playground_scenarios(db_pool.clone().map(|pg| {
            Arc::new(
                waygate_dashboard_stores::playground_scenarios::PgPlaygroundScenarioStore::new(pg),
            )
                as Arc<dyn waygate_dashboard_stores::playground_scenarios::PlaygroundScenarioStore>
        }))
        // SCIM provisioning-log timeline store. Same
        // DB-pool gating; absence ⇒ the SCIM REST writer hooks
        // skip the structured append (the existing audit_log
        // writes are unaffected) and the dashboard SCIM page
        // hides the Provisioning-log section.
        .with_scim_provisioning_log(db_pool.clone().map(|pg| {
            Arc::new(
                waygate_dashboard_stores::scim_provisioning_log::PgScimProvisioningLogStore::new(
                    pg,
                ),
            )
                as Arc<
                    dyn waygate_dashboard_stores::scim_provisioning_log::ScimProvisioningLogStore,
                >
        }))
        // Activity-page saved-views store. Same DB-pool
        // gating; absence ⇒ the activity page hides its
        // Saved-views sidebar section entirely (facets + filter
        // form + results unaffected). Purely dashboard-facing.
        .with_activity_saved_views(db_pool.clone().map(|pg| {
            Arc::new(
                waygate_dashboard_stores::activity_saved_views::PgActivitySavedViewStore::new(pg),
            )
                as Arc<dyn waygate_dashboard_stores::activity_saved_views::ActivitySavedViewStore>
        }))
        // Canonical tenants registry backing
        // /api/v1/admin/tenants/*. Same DB-pool gating pattern
        // as the rest of the admin stores; absence ⇒ tenant
        // endpoints 503.
        .with_tenant_store(db_pool.clone().map(|pg| {
            Arc::new(waygate_tenants::PgTenantStore::new(pg))
                as Arc<dyn waygate_tenants::TenantStore>
        }))
        .with_tenant_lifecycle_store(db_pool.clone().map(|pg| {
            Arc::new(waygate_admin::tenants::PgTenantLifecycleStore::new(pg))
                as Arc<dyn waygate_admin::tenants::TenantLifecycleStore>
        }))
        // Same `PgTenantEnricher` instance that
        // chained into the bearer middleware above. Admin tenant
        // PATCH/DELETE call `invalidate(id)` on it so a
        // suspension cuts off on the very next request, not after
        // the 60s TTL.
        .with_tenant_enricher(tenant_enricher_concrete.clone())
        .with_scim_enricher(scim_enricher_concrete.clone())
        // Same ApiKeyValidator the
        // bearer middleware uses. Tenant DELETE cleanup flushes
        // its cache after revoking the rows so a freshly revoked
        // key cannot still authenticate against the in-memory
        // cache for the remainder of its TTL.
        .with_api_key_validator(api_key_validator_arc.clone())
        // Gate the API-key admin REST surface and onboarding SCIM key
        // minting on the runtime auth flag, NOT on store presence.
        // `state.identity.api_keys` (the admin store) is always wired
        // with DB so cleanup works regardless of runtime auth state,
        // decoupled from `cfg.api_keys` (the bearer chain flag). This
        // `with_api_keys_enabled` call is the per-deployment feature
        // gate: true only when GATEWAY_API_KEYS_ENABLED=true AND the
        // bearer chain actually has the API-key validator installed.
        // The existence of `api_key_validator_arc` is exactly that
        // joint condition — it's `Some` only when both hold.
        .with_api_keys_enabled(api_key_validator_arc.is_some())
        // Per-tenant rate-limit policies CRUD
        // store backing /api/v1/admin/rate_limit_policies/*. Same
        // DB-pool gating pattern as the other admin stores.
        .with_rate_limit_policy_store(db_pool.clone().map(|pg| {
            Arc::new(waygate_quota::PgRateLimitPolicyStore::new(pg))
                as Arc<dyn waygate_quota::RateLimitPolicyStore>
        }))
        // API-key mint profiles CRUD store
        // backing /api/v1/admin/api_key_profiles/*.
        .with_api_key_profile_store(db_pool.clone().map(|pg| {
            Arc::new(waygate_apikeys::PgProfileStore::new(pg))
                as Arc<dyn waygate_apikeys::ProfileStore>
        }))
        // Scope-registry store backing the
        // read-only Scopes page (/scopes).
        .with_scope_store(db_pool.clone().map(|pg| {
            Arc::new(waygate_apikeys::PgScopeStore::new(pg)) as Arc<dyn waygate_apikeys::ScopeStore>
        }))
        // Group catalog read-view backing the
        // read-only Groups page (/groups).
        .with_group_store(db_pool.clone().map(|pg| {
            Arc::new(waygate_apikeys::PgGroupStore::new(pg)) as Arc<dyn waygate_apikeys::GroupStore>
        }))
        // Two-approver rule for catalog server promotion.
        // Opt-in via `GATEWAY_REQUIRE_TWO_APPROVALS=true`; otherwise
        // single-actor approval continues to work. Read here rather
        // than in admin code so the env surface stays in the binary's
        // config layer.
        .with_two_approver_mode(waygate_core::env::bool_default_off(
            "GATEWAY_REQUIRE_TWO_APPROVALS",
        ))
        // Configurable allowlist for the Overview "What changed" feed's
        // change-request rows (the broad `admin_mutation` category is
        // filtered to these actions). Read here so the env surface stays in
        // the binary's config layer, mirroring `GATEWAY_REQUIRE_TWO_APPROVALS`
        // above. Empty/unset → the builder keeps `AdminState`'s default set.
        .with_overview_change_feed_actions(
            std::env::var("GATEWAY_OVERVIEW_CHANGE_FEED_ACTIONS")
                .ok()
                .map(|raw| {
                    raw.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
        )
        // Read-only system info snapshot for the
        // Settings page. Built above from `cfg` + the
        // already-constructed identity keyring.
        .with_system_info(system_info.clone())
        // The gateway's OWN built-in MCP namespaces, for the read-only
        // "Built-in surfaces" operator view. Static descriptors sourced from the
        // same modules that serve the tools, so the view can't drift from the
        // wire. These are local (answered by the gateway), not proxied
        // upstreams, so they appear nowhere in the server/catalog lists.
        .with_builtin_surfaces(builtin_surfaces)
        // Grafana Explore → Tempo "View trace" link template
        // for the activity drawer. None unless GATEWAY_TRACE_URL_TEMPLATE is set.
        .with_trace_url_template(cfg.trace_url_template.clone()),
    );

    // Fill the deferred handle now that `AdminState` exists, so the
    // built-in MCP propose tool (its factory closure was defined above, before
    // this point) can capture target freshness tokens. `set` runs well before
    // the HTTP listener is bound, so every tool call observes it populated;
    // `set` returns Err only if somehow called twice, which can't happen here.
    let _ = admin_state_cell.set(admin_state.clone());
    let state = Arc::new(AppState::new(
        cfg.clone(),
        pool.clone(),
        cedar_engine.clone(),
        skills.catalog(),
        audit_reader.is_some(),
    ));
    // Wrap the rmcp `/mcp` service with a
    // response-rewriting middleware that promotes the
    // structured rmcp `insufficient_scope` / `rate_limited`
    // JSON-RPC errors to HTTP 403 + WWW-Authenticate and HTTP
    // 429 + Retry-After respectively. The JSON-RPC body is
    // preserved verbatim so existing rmcp clients still see
    // the same `data` envelope — this only ADDS the OAuth/RFC
    // surface for clients that prefer to consume the standard
    // HTTP signals.
    let mcp_resource_metadata_url = resource_metadata_url.clone();
    // axum 0.8 panics at runtime on `nest_service("/", _)` with
    // "Nesting at the root is no longer supported." Use
    // `fallback_service` to route every path under this Router
    // through `mcp_service` instead. Functionally identical for
    // the outer `nest("/mcp", ...)` below: rmcp's
    // StreamableHttpService receives the full sub-path either
    // way. The `.layer` then wraps the resulting service with
    // the JSON-RPC → HTTP 403/429 promotion middleware.
    // Pre-parse deny-only gate on the SEP-2243 routing headers. Added
    // AFTER the promote layer so it is the outer of the two: an
    // obviously-denied `tools/call` is refused from the headers alone,
    // before the body is read or the rmcp service is entered. Shares the
    // pipeline's own Cedar gate, catalog, quota service, and evidence
    // recorder, so its denials carry identical audit/metric shapes. The
    // bearer layer applied to `protected` below runs outermost, so the
    // Principal extension is present by the time the gate reads it.
    let preparse_gate_state = Arc::new(mcp_preparse_gate::GateState {
        catalog: catalog.clone(),
        authz: authz_gate.clone(),
        quota: quota_service.clone(),
        audit: audit_sink.clone(),
    });
    let mcp_service_with_promote = axum::Router::new()
        .fallback_service(mcp_service)
        .layer(axum::middleware::from_fn(move |req, next| {
            let url = mcp_resource_metadata_url.clone();
            async move { mcp_http_promote::promote_mcp_errors(req, next, url).await }
        }))
        .layer(axum::middleware::from_fn(move |req, next| {
            let state = preparse_gate_state.clone();
            async move { mcp_preparse_gate::preparse_gate(state, req, next).await }
        }));
    let mut protected: Router<()> = Router::new()
        .nest("/mcp", mcp_service_with_promote)
        .merge(waygate_admin::api_router(admin_state.clone()))
        // SCIM 2.0 lives at /scim/v2/* (NOT
        // /api/v1/*) so IdP probes for the well-known
        // /scim/v2/ServiceProviderConfig path land on the
        // right routes without operators having to override
        // the IdP SCIM base URL. Same BearerLayer below
        // gates it — SCIM clients authenticate with API
        // keys carrying the scim:read / scim:write scopes.
        .merge(waygate_admin::scim_router(admin_state.clone()));
    // Mount the OpenAI-compatible inference route ONLY when LLM models
    // are configured. With no models, `/v1` is absent entirely — the deployment
    // stays MCP-only, unchanged (so a request can't fall through to MCP
    // dispatch). Behind the same bearer layer below; dispatches through the
    // shared governed invocation service so authorize / quota / audit all apply
    // (invariant I1).
    if let Some((_, resolver)) = llm_deps.as_ref() {
        protected = protected.merge(crate::llm::router(
            admin_try_invocation,
            llm_model_catalog.clone(),
            resolver.clone(),
        ));
    }
    let protected: Router<()> = protected.layer(axum::middleware::from_fn_with_state(
        bearer_layer,
        bearer_middleware,
    ));

    let dashboard_auth = build_dashboard_auth(&cfg, oidc_http.as_ref()).await?;
    // Attach the same SCIM
    // enricher to the dashboard session middleware so SCIM
    // deactivation takes effect on /admin within one TTL window —
    // otherwise a long-lived dashboard cookie keeps working
    // after the IdP deactivates the user.
    let dashboard_auth = dashboard_auth.with_principal_enricher(principal_enricher);
    let dashboard: Router<()> =
        waygate_admin::dashboard_router(admin_state.clone(), dashboard_auth);

    let stateful = Router::new()
        .merge(health::router())
        .with_state(state.clone());

    let mut app: Router<()> = stateful
        .merge(well_known)
        .merge(protected)
        .nest("/admin", dashboard);
    if let Some(runtime) = transfer_runtime.as_ref() {
        app = runtime.mount_routes(
            app,
            cfg.public_url.clone(),
            file_transfer_admission.clone(),
            cfg.file_retention.general,
        )?;
    }
    let as_sweeper_store = if let Some((as_router, store)) = as_router {
        app = app.merge(as_router);
        Some(store)
    } else {
        None
    };
    let app = app.layer(TraceLayer::new_for_http());

    // Trim trailing slashes before routing so `/admin/` reaches the same
    // handler as `/admin`. axum 0.8's nest matches the bare prefix but not the
    // prefix-with-slash, which would 404 every "Overview" nav click otherwise.
    // Must wrap the final service — layers added via Router::layer run *after*
    // routing and can't influence path matching.
    let app = NormalizePathLayer::trim_trailing_slash().layer(app);

    let listener = tokio::net::TcpListener::bind(&cfg.listen_addr)
        .await
        .with_context(|| format!("bind {}", cfg.listen_addr))?;

    tracing::info!(addr = %cfg.listen_addr, "gateway listening");

    // NOW that the listener is bound (the serving point — the fallible
    // startup is done), record the boot activation event built earlier. A boot
    // that failed before here never persists it.
    if let Some(event) = boot_activation {
        audit_sink.record_best_effort(event).await;
    }
    // And the boot fleet heartbeat, so the replica appears in the
    // roll-up immediately rather than waiting for the first poll tick.
    if let (Some(store), Some((disk_hash, version))) = (manifest_store.as_ref(), boot_heartbeat) {
        if let Err(e) = store
            .upsert_replica_heartbeat(
                &replica_id,
                waygate_core::TenantId::DEFAULT,
                version,
                &disk_hash,
            )
            .await
        {
            tracing::warn!(error = %e, "boot fleet heartbeat upsert failed (non-fatal)");
        }
    }

    // Seed the scope registry at boot with every
    // scope the loaded policy set references (source='policy'), so the
    // catalog reflects policy-gated scopes from the first request. The
    // SIGHUP/doorbell reload re-runs this in `reload_policies_only`.
    // Best-effort; no-op when auth is disabled or the DB isn't wired.
    if let Some(engine) = cedar_engine.as_ref() {
        let policy_scopes: Vec<String> = engine.referenced_scopes().into_iter().collect();
        reconcile_policy_scopes(&db_pool, &policy_scopes).await;
    }

    #[cfg(unix)]
    let _reload_task = spawn_reload_task(
        ReloadDeps {
            policies_dir: cfg.policies_dir.clone(),
            servers_dir: cfg.servers_dir.clone(),
            cedar: cedar_engine.clone(),
            policy_store: policy_store.clone(),
            manifest_store: manifest_store.clone(),
            pool: pool.clone(),
            audit: audit_sink.clone(),
            deployment_profile: cfg.deployment_profile,
            config_health: config_health.clone(),
            policy_config_health: policy_config_health.clone(),
            replica_id: replica_id.clone(),
            db_pool: db_pool.clone(),
            // Seed with the hash boot just loaded from disk, so the first poll
            // tick no-ops instead of redundantly re-loading the same set. A
            // boot that RECOVERED off a broken disk seeds the broken disk's hash
            // (we've "processed" that disk state); a later disk FIX changes the
            // hash and triggers a real reload.
            last_policy_hash: std::sync::Mutex::new(
                waygate_policy::read_policy_dir(&cfg.policies_dir)
                    .ok()
                    .map(|c| waygate_policy::content_hash(&c.source)),
            ),
            last_tenant_policy_hash: std::sync::Mutex::new(tenant_policy_hash),
        },
        ct.clone(),
    );

    // AS-mode only: periodic sweep of expired /oauth/* rows. Indexes on
    // `expires_at` keep it cheap; a 5-minute cadence is well under the
    // shortest TTL (code rows = 60s) that actually matters — transactions
    // and refresh tokens don't mind sitting around a few extra minutes.
    let _sweeper_task = as_sweeper_store.map(|store| {
        let shutdown = ct.clone();
        tracing::info!("spawning oauth sweeper (interval = 300s)");
        tokio::spawn(async move {
            run_sweeper(
                store,
                std::time::Duration::from_secs(300),
                shutdown.cancelled_owned(),
            )
            .await
        })
    });

    let _transfer_sweeper_task = transfer_runtime
        .as_ref()
        .map(|runtime| runtime.spawn_sweeper(ct.clone()));

    // Evidence outbox drain worker. Spawned only
    // when (a) a DB pool exists, (b) the operator left the drain
    // interval non-zero, AND (c) at least one matching exporter
    // could be constructed for the configured outbox targets.
    // Each exporter (webhook, OCSF, ECS, syslog) is registered only
    // when it is BOTH named in GATEWAY_EVIDENCE_OUTBOX_TARGETS AND
    // its URL/target env var is set — naming a target without the
    // matching URL means the drain finds rows but has no exporter
    // for them. The drain handles that by dead-lettering with a
    // WARN, but we also catch it here at boot so the operator gets
    // a single clear log line instead of one per row.
    let _evidence_drain_task = match (db_pool.clone(), cfg.evidence_drain_interval) {
        (Some(pg), Some(interval)) => {
            let mut registry = waygate_storage::ExporterRegistry::new();
            // Only register `webhook` when the
            // operator explicitly listed it in
            // GATEWAY_EVIDENCE_OUTBOX_TARGETS. Without that gate
            // the drain spawns idle whenever WEBHOOK_URL is set
            // even if no record_required will ever produce a
            // `webhook` outbox row — and the README's "when
            // `webhook` is in targets" claim is wrong.
            let webhook_named = cfg
                .evidence_outbox_targets
                .iter()
                .any(|t| t == waygate_storage::WebhookExporter::TARGET);
            if let (Some(url), true) = (cfg.evidence_webhook_url.as_ref(), webhook_named) {
                match waygate_storage::WebhookExporter::new(url) {
                    Ok(webhook) => {
                        // Log only the
                        // sanitized scheme+host of the configured
                        // URL — userinfo / query tokens / signed
                        // path components MUST NOT reach the log
                        // stream.
                        tracing::info!(
                            url = %webhook.sanitized_url(),
                            "evidence webhook exporter registered",
                        );
                        registry
                            .insert(waygate_storage::WebhookExporter::TARGET, Arc::new(webhook));
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "GATEWAY_EVIDENCE_WEBHOOK_URL is set but the exporter \
                             failed to construct (e.g. malformed URL); skipping drain spawn"
                        );
                    }
                }
            } else if cfg.evidence_webhook_url.is_some() && !webhook_named {
                tracing::warn!(
                    "GATEWAY_EVIDENCE_WEBHOOK_URL is set but `webhook` is not in \
                     GATEWAY_EVIDENCE_OUTBOX_TARGETS; skipping webhook registration \
                     so no idle drain runs"
                );
            }

            // OCSF exporter. Same naming-gated
            // pattern as `webhook` — only registered when both
            // `ocsf` is in OUTBOX_TARGETS AND
            // GATEWAY_EVIDENCE_OCSF_URL is set.
            let ocsf_named = cfg
                .evidence_outbox_targets
                .iter()
                .any(|t| t == waygate_storage::OcsfExporter::TARGET);
            if let (Some(url), true) = (cfg.evidence_ocsf_url.as_ref(), ocsf_named) {
                // Pass the AOS-trace toggle through.
                // Default off; enabled by `GATEWAY_OCSF_AOS_TRACE=true`.
                match waygate_storage::OcsfExporter::with_aos_trace(
                    url,
                    cfg.evidence_ocsf_aos_trace,
                ) {
                    Ok(ocsf) => {
                        tracing::info!(
                            url = %ocsf.sanitized_url(),
                            aos_trace = cfg.evidence_ocsf_aos_trace,
                            "evidence OCSF exporter registered",
                        );
                        registry.insert(waygate_storage::OcsfExporter::TARGET, Arc::new(ocsf));
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "GATEWAY_EVIDENCE_OCSF_URL is set but the exporter \
                             failed to construct (e.g. malformed URL); skipping OCSF registration"
                        );
                    }
                }
            } else if cfg.evidence_ocsf_url.is_some() && !ocsf_named {
                tracing::warn!(
                    "GATEWAY_EVIDENCE_OCSF_URL is set but `ocsf` is not in \
                     GATEWAY_EVIDENCE_OUTBOX_TARGETS; skipping OCSF registration"
                );
            } else if ocsf_named && cfg.evidence_ocsf_url.is_none() {
                tracing::warn!(
                    "`ocsf` is in GATEWAY_EVIDENCE_OUTBOX_TARGETS but \
                     GATEWAY_EVIDENCE_OCSF_URL is unset; the outbox writes rows \
                     for `ocsf` but no exporter will ship them",
                );
            }

            // ECS exporter. Same naming-gated
            // pattern as `webhook` / `ocsf`.
            let ecs_named = cfg
                .evidence_outbox_targets
                .iter()
                .any(|t| t == waygate_storage::EcsExporter::TARGET);
            if let (Some(url), true) = (cfg.evidence_ecs_url.as_ref(), ecs_named) {
                match waygate_storage::EcsExporter::new(url) {
                    Ok(ecs) => {
                        tracing::info!(
                            url = %ecs.sanitized_url(),
                            "evidence ECS exporter registered",
                        );
                        registry.insert(waygate_storage::EcsExporter::TARGET, Arc::new(ecs));
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "GATEWAY_EVIDENCE_ECS_URL is set but the exporter \
                             failed to construct (e.g. malformed URL); skipping ECS registration"
                        );
                    }
                }
            } else if cfg.evidence_ecs_url.is_some() && !ecs_named {
                tracing::warn!(
                    "GATEWAY_EVIDENCE_ECS_URL is set but `ecs` is not in \
                     GATEWAY_EVIDENCE_OUTBOX_TARGETS; skipping ECS registration"
                );
            } else if ecs_named && cfg.evidence_ecs_url.is_none() {
                tracing::warn!(
                    "`ecs` is in GATEWAY_EVIDENCE_OUTBOX_TARGETS but \
                     GATEWAY_EVIDENCE_ECS_URL is unset; the outbox writes rows \
                     for `ecs` but no exporter will ship them",
                );
            }

            // Syslog exporter (RFC 5424 / TCP).
            // Same naming-gated pattern as the HTTP exporters.
            let syslog_named = cfg
                .evidence_outbox_targets
                .iter()
                .any(|t| t == waygate_storage::SyslogExporter::TARGET);
            if let (Some(target), true) = (cfg.evidence_syslog_target.as_ref(), syslog_named) {
                match waygate_storage::SyslogExporter::new(
                    target,
                    cfg.evidence_syslog_hostname.clone(),
                    cfg.evidence_syslog_facility,
                    cfg.evidence_syslog_pen,
                ) {
                    Ok(syslog) => {
                        tracing::info!(
                            target = %syslog.sanitized_target(),
                            hostname = %cfg.evidence_syslog_hostname,
                            facility = cfg.evidence_syslog_facility,
                            pen = cfg.evidence_syslog_pen,
                            "evidence syslog exporter registered",
                        );
                        registry.insert(waygate_storage::SyslogExporter::TARGET, Arc::new(syslog));
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "GATEWAY_EVIDENCE_SYSLOG_TARGET is set but the exporter \
                             failed to construct (likely a malformed target); skipping \
                             syslog registration"
                        );
                    }
                }
            } else if cfg.evidence_syslog_target.is_some() && !syslog_named {
                tracing::warn!(
                    "GATEWAY_EVIDENCE_SYSLOG_TARGET is set but `syslog` is not in \
                     GATEWAY_EVIDENCE_OUTBOX_TARGETS; skipping syslog registration"
                );
            } else if syslog_named && cfg.evidence_syslog_target.is_none() {
                tracing::warn!(
                    "`syslog` is in GATEWAY_EVIDENCE_OUTBOX_TARGETS but \
                     GATEWAY_EVIDENCE_SYSLOG_TARGET is unset; the outbox writes rows \
                     for `syslog` but no exporter will ship them",
                );
            }
            if registry.is_empty() {
                tracing::warn!(
                    "evidence drain interval is set but no exporters could be \
                     constructed (configure one of GATEWAY_EVIDENCE_WEBHOOK_URL + \
                     `webhook`, GATEWAY_EVIDENCE_OCSF_URL + `ocsf`, \
                     GATEWAY_EVIDENCE_ECS_URL + `ecs`, or \
                     GATEWAY_EVIDENCE_SYSLOG_TARGET + `syslog` in \
                     GATEWAY_EVIDENCE_OUTBOX_TARGETS, to register at least \
                     one exporter); not spawning the drain task"
                );
                None
            } else {
                let shutdown = ct.clone();
                let registry = Arc::new(registry);
                tracing::info!(
                    interval_secs = interval.as_secs(),
                    targets = ?registry.target_names(),
                    "spawning evidence outbox drain",
                );
                Some(tokio::spawn(async move {
                    waygate_storage::run_outbox_drain(
                        pg,
                        registry,
                        interval,
                        shutdown.cancelled_owned(),
                    )
                    .await
                }))
            }
        }
        _ => None,
    };

    // Background sweep of consumed / expired
    // `approval_grants` rows. Spawned only when (a) a DB catalog
    // store exists — DB-less deployments have no table to sweep —
    // AND (b) the operator left the sweep interval non-zero (0
    // disables). The sweep is a single DELETE statement gated by
    // the retention threshold; at idle steady state it deletes
    // zero rows. Shares the same cancellation token as the rest
    // of the background tasks so SIGTERM drains cleanly.
    let _grant_sweeper_task = match (&catalog_store, cfg.grant_sweep_interval) {
        (Some(catalog), Some(interval)) => {
            let shutdown = ct.clone();
            let retention = cfg.grant_retention;
            tracing::info!(
                interval_secs = interval.as_secs(),
                retention_secs = retention.as_secs(),
                "spawning HITL approval-grant sweeper",
            );
            Some(tokio::spawn({
                let catalog = catalog.clone();
                async move {
                    waygate_catalog::grant_sweeper::run_grant_sweeper(
                        catalog,
                        interval,
                        retention,
                        shutdown.cancelled_owned(),
                    )
                    .await
                }
            }))
        }
        _ => None,
    };

    // Retention policy storage + the
    // sweep mechanics that consume those policies. Operators
    // configure policies via /api/v1/audit/retention; the sweep
    // runs on demand via POST /api/v1/audit/sweep and (when
    // GATEWAY_RETENTION_SWEEP_INTERVAL_SECONDS is non-zero; it defaults hourly)
    // periodically via the scheduler spawned below.

    // Periodic retention sweep scheduler. Only
    // spawned when (a) the hourly default is enabled (the operator may set
    // GATEWAY_RETENTION_SWEEP_INTERVAL_SECONDS=0 to disable), AND (b)
    // AdminState has both a retention store
    // and a sweeper (both gated on a DB pool existing). Each
    // tick first owns a session-scoped fleet lock for the
    // full pass and advances a durable PostgreSQL cadence claim,
    // then lists every policy and runs the sweep per (tenant,
    // category). This keeps the ten-batch policy budget global
    // across overlapping, long-running, and phase-skewed replicas.
    // The task shares the cancellation token with the other
    // background tasks for clean SIGTERM drain.
    let _retention_scheduler_task = match (
        db_pool.as_ref(),
        admin_state.observability.retention.get(),
        admin_state.observability.sweeper.get(),
        cfg.retention_sweep_interval,
    ) {
        (Some(pool), Some(retention), Some(sweeper), Some(interval)) => {
            let shutdown = ct.clone();
            let pool = pool.clone();
            let retention = retention.clone();
            let sweeper = sweeper.clone();
            tracing::info!(
                interval_secs = interval.as_secs(),
                "spawning retention sweep scheduler",
            );
            Some(tokio::spawn(async move {
                waygate_storage::run_retention_scheduler(
                    pool,
                    sweeper,
                    retention,
                    interval,
                    shutdown.cancelled_owned(),
                )
                .await
            }))
        }
        _ => None,
    };

    // Tier-2: audit rollup maintenance worker. Spawned when a DB pool exists
    // AND the cadence is enabled (default 60s; disable with
    // GATEWAY_AUDIT_ROLLUP_INTERVAL_SECONDS=0). Folds new audit_log rows into
    // audit_rollup_hourly so wide-window dashboard aggregates stay fast as the
    // (unboundedly-retained) raw table grows. Uses the writer pool — it writes
    // the rollup — and shares the shutdown token for clean SIGTERM drain.
    let _audit_rollup_task = match (db_pool.as_ref(), cfg.audit_rollup_interval) {
        (Some(pool), Some(interval)) => {
            let shutdown = ct.clone();
            let pool = pool.clone();
            tracing::info!(
                interval_secs = interval.as_secs(),
                "spawning audit rollup maintenance",
            );
            Some(tokio::spawn(async move {
                waygate_storage::run_rollup_maintenance(pool, interval, shutdown.cancelled_owned())
                    .await
            }))
        }
        _ => None,
    };

    // Background re-encrypt sweeper. Only spawned
    // when (a) the operator left the default cadence on or
    // explicitly set a non-zero interval, AND (b) the Tier-A
    // bundle exists (no AS / no DB ⇒ no rows to sweep). The
    // sweeper is cheap at idle (an indexed `key_id <> active`
    // filter returns zero rows in steady state), so we don't
    // gate it on "rotation in progress" — leaving it running
    // makes the eventual rotation a no-op for the operator.
    let _reencrypt_task = match (cfg.reencrypt_interval, reencrypt_handles) {
        (Some(interval), Some((sessions, crypto))) => {
            let shutdown = ct.clone();
            tracing::info!(
                interval_secs = interval.as_secs(),
                "spawning Tier-A re-encrypt sweeper",
            );
            Some(tokio::spawn(async move {
                waygate_as::reencrypt_sweeper::run_reencrypt_sweeper(
                    crypto,
                    sessions,
                    interval,
                    100, // batch size
                    shutdown.cancelled_owned(),
                )
                .await
            }))
        }
        _ => None,
    };

    // Peer JWKS refresher. Walks every
    // registered federated_peers row on `peer_jwks_refresh_interval`
    // and keeps `peer_jwks_cache` warm so the bearer chain's
    // peer-assertion verifier sees valid signing keys synchronously at
    // bearer-validate time. Skipped when there's no DB
    // (no peers store to scan) — same null-sink convention
    // as the other admin-store-gated background tasks.
    let _peer_jwks_refresh_task = match federated_peers_store.clone() {
        Some(store) => {
            let shutdown = ct.clone();
            let cache = peer_jwks_cache.clone();
            let interval = cfg.peer_jwks_refresh_interval;
            tracing::info!(
                interval_secs = interval.as_secs(),
                "spawning peer JWKS refresher",
            );
            Some(tokio::spawn(async move {
                let fetcher = std::sync::Arc::new(waygate_federation::jwks::PeerJwksFetcher::new());
                let refresher = waygate_federation::jwks::PeerJwksRefresher::new(
                    store, cache, fetcher, interval,
                );
                let mut ticker = tokio::time::interval(interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = ticker.tick() => {
                            let _summary = refresher.refresh_once().await;
                        }
                    }
                }
            }))
        }
        None => {
            tracing::warn!(
                "peer JWKS refresher disabled (no federated_peers store) — \
                 peer-assertion validation will return UnknownKid \
                 for every peer-issued JWT",
            );
            None
        }
    };

    // Per-upstream reconnect scheduler: sleep until the earliest independently
    // jittered deadline, then launch every due server concurrently.
    // Without this, an upstream that was unhealthy at boot stays disconnected
    // forever (the breaker only HalfOpens on a real RPC, which never arrives
    // for a never-connected entry).
    let _reprobe_task = {
        let pool = pool.clone();
        let shutdown = ct.clone();
        tracing::info!(
            base_secs = cfg.upstream_reconnect_base.as_secs(),
            ceiling_secs = cfg.upstream_reconnect_ceiling.as_secs(),
            "spawning per-upstream reconnect scheduler"
        );
        tokio::spawn(reconnect_scheduler::run(pool, shutdown))
    };

    // Scheduled catalog refreshes: an upstream's `tools/list` ttlMs hint may
    // shorten the deadline within the floor/ceiling bounds; without a hint,
    // the freshness task uses the ceiling as its fallback interval.
    // `GATEWAY_CATALOG_FRESHNESS_FLOOR_SECONDS=0` disables it. The config
    // was parsed and validated at the top of boot with everything else.
    // Upstream push invalidation (2026-07-28 `subscriptions/listen`):
    // listeners consume eligible upstreams' tools/list_changed streams and
    // drive the same refresh path, rate-bounded by the freshness floor so
    // one operator knob bounds both the schedule and the push path.
    let listen_min_refresh = catalog_freshness_cfg
        .floor
        .unwrap_or(std::time::Duration::from_secs(60));
    let _catalog_freshness_task =
        catalog_freshness::spawn(pool.clone(), catalog_freshness_cfg, ct.clone());
    let _subscription_listen_task =
        subscription_listen::spawn(pool.clone(), listen_min_refresh, ct.clone());

    let shutdown_ct = ct.clone();
    // Bound the entire post-SIGTERM
    // cleanup sequence (axum drain + DB pool close) by
    // `GATEWAY_DRAIN_TIMEOUT_SECONDS` so a hung in-flight
    // request OR a hung pool handle can't prevent process
    // exit before the orchestrator's
    // `terminationGracePeriodSeconds` escalates to SIGKILL.
    //
    // Why bound the WHOLE sequence, not just axum drain:
    // `PgPool::close()` waits for every outstanding pool
    // handle to drop. Background tasks (recorder, retention
    // sweeper, evidence drain, …) all hold cloned pool
    // handles; if any of them are stuck after `ct.cancel()`,
    // `pool.close()` blocks forever and undoes the drain
    // bound.
    //
    // Default budget 20s leaves ~10s headroom inside the
    // typical 30s `terminationGracePeriodSeconds` for the
    // process to log + exit before SIGKILL — a 30s default
    // would match the grace period exactly, leaving no
    // margin.
    //
    // Pattern: spawn the server future as a detached task so
    // it runs concurrently with the notify wait. The shutdown
    // trigger fires `drain_started.notify_one()` from inside
    // axum's graceful-shutdown future. We then race
    // `(server task join + concurrent pool closes)` against
    // `sleep(drain_timeout)`. On the timeout branch, dropping
    // the cleanup future + returning from main aborts the
    // server task and abandons the pools — sockets close when
    // the process exits, clients see RST. The bound starts
    // from the shutdown moment, not from server boot.
    let drain_started = std::sync::Arc::new(tokio::sync::Notify::new());
    let drain_started_signal = drain_started.clone();
    let drain_timeout = cfg.drain_timeout;
    let server_fut = axum::serve(listener, Shared::new(app)).with_graceful_shutdown(async move {
        shutdown_signal().await;
        shutdown_ct.cancel();
        drain_started_signal.notify_one();
    });
    // `WithGracefulShutdown` is `IntoFuture` but not directly
    // `Future` (axum 0.8). Wrap in an async block so `tokio::spawn`
    // accepts it.
    let server_task = tokio::spawn(async move { server_fut.await });

    // Wait for SIGTERM/SIGINT to fire (the trigger inside
    // `with_graceful_shutdown` notifies us as soon as it
    // returns). The server task is running on its own; the
    // notify fires from within it.
    drain_started.notified().await;
    tracing::info!(
        timeout_secs = drain_timeout.as_secs(),
        "shutdown signal received; bounded cleanup window started (axum drain + pool close)",
    );

    let cleanup = async {
        // Wait for axum to finish draining in-flight HTTP
        // connections.
        match server_task.await {
            Ok(Ok(())) => tracing::info!("axum drained cleanly"),
            Ok(Err(e)) => tracing::warn!(error = %e, "axum returned error during drain"),
            Err(e) => tracing::warn!(error = %e, "axum task join failed"),
        }
        // Stop accepting best-effort evidence only after HTTP handlers have
        // drained, then give the fixed-capacity queues up to five seconds
        // within the process-wide cleanup budget before closing the pool they
        // write through.
        if let Some(handle) = evidence_queue_handle.take() {
            let report = handle.shutdown().await;
            if report.timed_out
                || report.worker_failures > 0
                || report.dropped_chained_best_effort > 0
                || report.dropped_best_effort > 0
            {
                tracing::warn!(
                    timed_out = report.timed_out,
                    worker_failures = report.worker_failures,
                    dropped_chained_best_effort = report.dropped_chained_best_effort,
                    dropped_best_effort = report.dropped_best_effort,
                    "bounded evidence queue shutdown was incomplete",
                );
            } else {
                tracing::info!("bounded evidence queues drained cleanly");
            }
        }
        // Then close every isolated workload pool so connections are returned
        // to Postgres before the process exits.
        if let Some(pools) = &database_pools {
            pools.close().await;
        }
    };

    match tokio::time::timeout(drain_timeout, cleanup).await {
        Ok(()) => tracing::info!("gateway shutdown complete (within drain window)"),
        Err(_) => tracing::warn!(
            timeout_secs = drain_timeout.as_secs(),
            "drain deadline reached with cleanup still pending; forcing exit \
             (in-flight HTTP and DB connections drop on process exit). \
             If this fires under normal load, raise GATEWAY_DRAIN_TIMEOUT_SECONDS \
             or investigate the stuck handler / background task.",
        ),
    }

    Ok(())
}

// Test modules split out of this file; #[path] keeps
// each mod a direct child of the crate root, so `use super::*` inside
// them still resolves exactly as before the move.
#[cfg(test)]
#[path = "main_tests/builtin_selfdoc_enforcement.rs"]
mod builtin_selfdoc_enforcement;
#[cfg(test)]
#[path = "main_tests/llm_cache_toggle_tests.rs"]
mod llm_cache_toggle_tests;
#[cfg(test)]
#[path = "main_tests/manifest_load_tests.rs"]
mod manifest_load_tests;
#[cfg(test)]
#[path = "main_tests/mcp_allowed_hosts_tests.rs"]
mod mcp_allowed_hosts_tests;
#[cfg(test)]
#[path = "main_tests/policy_load_tests.rs"]
mod policy_load_tests;
#[cfg(test)]
#[path = "main_tests/policy_oob_capture_tests.rs"]
mod policy_oob_capture_tests;
#[cfg(all(test, unix))]
#[path = "main_tests/policy_reload_doorbell_tests.rs"]
mod policy_reload_doorbell_tests;
#[cfg(test)]
#[path = "main_tests/streamable_http_config_tests.rs"]
mod streamable_http_config_tests;
