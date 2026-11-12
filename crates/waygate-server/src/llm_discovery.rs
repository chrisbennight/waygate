//! Refresh supported provider API model lists into the durable catalog.
//! OpenRouter supplies chat/embedding listings and pricing. OpenAI and Gemini
//! require explicit qualified model selections. Partial or transient-empty
//! listings preserve last-good rows; configured pins remain authoritative.
//! No consumer model listing or CLI identity tracking is implemented.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use waygate_llm_credentials::LlmCredentialStore;
use waygate_llm_discovery::{
    list_gemini, list_openai, list_openrouter, list_openrouter_embeddings, DiscoveredModel,
    DiscoverySurface,
};
use waygate_llm_dispatch::DbModelResolver;
use waygate_storage::LlmDiscoveredModelUpsert;

/// Serializes the live-PG tests that operate on the fixed
/// `(tenant = default, provider = openrouter)` discovered-row scope: the two
/// `refresh_target` reconcile tests in this module and
/// `llm::tests::boot_load_makes_a_discovered_row_routable`. `mark_discovered_absent`
/// is provider-scoped, so without serialization one test's reconcile soft-disables
/// another's discovered rows (a `present_upstream` flip mid-test). Each test holds
/// this for its whole body, cleanup included. The static only serializes tests
/// sharing a process (plain `cargo test` threads); under cargo-nextest every test
/// is its own process, so the `discovery-pg` test-group in `.config/nextest.toml`
/// provides the cross-process serialization — a new test that takes this lock
/// must also be added to that group's filter.
#[cfg(test)]
pub(crate) static DISCOVERY_PG_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// One discovery target parsed from `GATEWAY_LLM_DISCOVERY`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryTarget {
    /// Provider in the lowercase vocabulary (`openrouter`, `openai`, `google`).
    pub provider: String,
    /// API-key label (`LLM_CRED_<PROVIDER>_<LABEL>`) used for listing and calls.
    pub credential_label: String,
    /// Supported provider API base URL shared by listing and model calls.
    pub base_url: String,
    /// Exact model IDs that may be discovered through the public Responses API.
    /// Required for API-key OpenAI discovery because `/models` carries no
    /// operation metadata. Images, audio, and realtime remain explicit pins.
    pub responses_models: Vec<String>,
    /// Operator-qualified text/function models, verified against the API's
    /// supportedGenerationMethods instead of inferring modality from names.
    pub generate_content_models: Vec<String>,
}

#[derive(Deserialize)]
struct RawTarget {
    provider: String,
    credential_label: String,
    base_url: String,
    #[serde(default)]
    client_version: Option<serde_json::Value>,
    #[serde(default)]
    responses_models: Vec<String>,
    #[serde(default)]
    generate_content_models: Vec<String>,
}

/// Default discovery interval (3h) and floor (5 min) so a misconfigured interval
/// can't hammer providers. Parsed at the `main.rs` use site via
/// `waygate_core::env::duration_secs` — a sub-floor or garbage
/// `GATEWAY_LLM_DISCOVERY_INTERVAL_SECS` rejects at boot.
pub(crate) const DEFAULT_INTERVAL_SECS: u64 = 3 * 60 * 60;
pub(crate) const MIN_INTERVAL_SECS: u64 = 300;

/// Parse explicitly configured API discovery. Retired CLI-version settings
/// fail with upgrade guidance instead of selecting a consumer backend.
pub fn parse_targets(raw: &str) -> anyhow::Result<Vec<DiscoveryTarget>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let parsed: Vec<RawTarget> = serde_json::from_str(raw).map_err(|_| {
        anyhow::anyhow!("GATEWAY_LLM_DISCOVERY must be an array of provider API discovery targets")
    })?;
    anyhow::ensure!(parsed.iter().all(|target| target.client_version.is_none()),
        "GATEWAY_LLM_DISCOVERY client_version is a retired consumer setting; remove it and explicitly select supported API models");
    let mut seen_providers = std::collections::HashSet::new();
    Ok(parsed.into_iter().filter_map(|target| {
        if !DiscoverySurface::provider_has_adapter(&target.provider) {
            tracing::warn!(provider=%target.provider,"discovery has no supported API adapter; models remain operator-pinned");
            return None;
        }
        let provider=target.provider.to_ascii_lowercase();
        if !seen_providers.insert(provider.clone()) {
            tracing::warn!(provider=%provider,"duplicate discovery target; keeping the first provider-scoped target");
            return None;
        }
        Some(DiscoveryTarget {provider, credential_label:target.credential_label, base_url:target.base_url,
            responses_models:target.responses_models, generate_content_models:target.generate_content_models})
    }).collect())
}

/// Build the discovered-model alias for `(provider, upstream id)`. Namespacing by
/// provider keeps the catalog's `(tenant, alias)` key unique across providers
/// (and distinct from a bare config-pin alias), while the raw id is preserved as
/// `upstream_model` for dispatch and cost attribution.
fn discovered_alias(provider: &str, id: &str) -> String {
    format!("{provider}:{id}")
}

/// Dedup a combined discovery listing by upstream id, keeping the LAST occurrence
/// of each id. The OpenRouter refresh concatenates the chat listing then the
/// embeddings listing, so on the (practically impossible) event an id appears in
/// both, the embeddings entry — pushed last — wins, and its row is tagged
/// `upstream_api = embeddings` rather than chat. First-appearance order is
/// otherwise preserved, and the deduped aliases keep the seen-set / discovered
/// count honest for the one provider-scoped reconcile.
fn dedup_keep_last_by_id(models: Vec<DiscoveredModel>) -> Vec<DiscoveredModel> {
    use std::collections::HashMap;
    let mut by_id: HashMap<String, DiscoveredModel> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for m in models {
        if !by_id.contains_key(&m.id) {
            order.push(m.id.clone());
        }
        by_id.insert(m.id.clone(), m);
    }
    order
        .into_iter()
        .filter_map(|id| by_id.remove(&id))
        .collect()
}

/// Run one discovery cycle for one target: fetch the live model list, upsert each
/// discovered model into the catalog, then reconcile (soft-disable the ones that
/// disappeared). Returns the number of models discovered.
///
/// Fail-open: any failure returns `Err` (the caller logs and keeps the last-good
/// catalog). An empty result returns `Ok(0)` WITHOUT reconciling, so a transient
/// empty/garbled response cannot mass-soft-disable the catalog.
async fn refresh_target(
    target: &DiscoveryTarget,
    http: &reqwest::Client,
    credentials: &LlmCredentialStore,
    pool: &sqlx::PgPool,
) -> anyhow::Result<usize> {
    let provider = crate::llm::parse_provider(&target.provider)?;
    let surface = DiscoverySurface::for_provider(&target.provider);
    if surface == DiscoverySurface::Unsupported {
        tracing::warn!(
            provider = %target.provider,
            credential_label = %target.credential_label,
            "discovery target's credential maps to no wired surface; skipping"
        );
        return Ok(0);
    }
    if surface == DiscoverySurface::OpenAiApi {
        anyhow::ensure!(
            !target.responses_models.is_empty()
                && target.responses_models.iter().all(|id| !id.trim().is_empty()),
            "OpenAI API discovery requires non-empty responses_models IDs; configure the supported Responses models explicitly or use model pins"
        );
    }
    if surface == DiscoverySurface::GoogleApi {
        anyhow::ensure!(
            !target.generate_content_models.is_empty()
                && target.generate_content_models.iter().all(|id| !id.trim().is_empty()),
            "Gemini API discovery requires non-empty generate_content_models IDs; select qualified text/function models or use explicit pins"
        );
    }
    let bearer = credentials
        .api_key(provider, &target.credential_label)
        .await?;
    // Fetch the live listing(s) for this surface. OpenRouter additionally exposes a
    // dedicated embeddings catalog (`/embeddings/models`); fetch both and tag each
    // model by operation (`DiscoveredModel::is_embeddings`). Both kinds flow through
    // the SAME provider-scoped reconcile below with a unioned seen-set, so the
    // embeddings listing never soft-disables the chat rows (or vice-versa) — the
    // failure one-target-per-provider reconciliation would otherwise invite.
    // `listing_complete` is false when a best-effort sub-listing failed: we still
    // upsert what we got, but skip the reconcile below so a partial fetch never
    // soft-disables the operation whose listing failed (last-good / fail-open).
    let mut api_raw_len: Option<usize> = None;
    let mut gemini_raw_len: Option<usize> = None;
    let (models, listing_complete): (Vec<DiscoveredModel>, bool) = match surface {
        DiscoverySurface::GoogleApi => {
            let listing = list_gemini(
                http,
                &target.base_url,
                &bearer,
                &target.generate_content_models,
            )
            .await?;
            gemini_raw_len = Some(listing.raw_len);
            (dedup_keep_last_by_id(listing.models), true)
        }
        DiscoverySurface::OpenAiApi => {
            let listing =
                list_openai(http, &target.base_url, &bearer, &target.responses_models).await?;
            api_raw_len = Some(listing.raw_len);
            (dedup_keep_last_by_id(listing.models), true)
        }
        DiscoverySurface::OpenRouter => {
            let mut combined = list_openrouter(http, &target.base_url, &bearer).await?;
            // An empty chat listing is the transient/garble case the empty-result
            // fail-open guards (OpenRouter always returns chat models), so it makes
            // the picture INCOMPLETE: reconcile is skipped below rather than
            // soft-disabling every chat alias when only the embeddings listing
            // returned rows.
            let chat_empty = combined.is_empty();
            // The dedicated embeddings listing is best-effort: a provider or proxy
            // that does not expose `/embeddings/models` (e.g. a self-hosted
            // OpenAI-compat endpoint configured as `openrouter`) must not break chat
            // discovery. On any error, log, keep the chat models, and mark the
            // picture INCOMPLETE so reconcile is skipped — otherwise the
            // provider-scoped `mark_discovered_absent` would soft-disable every
            // previously-discovered embeddings row (none are in the chat-only
            // `seen`), breaking last-good for a transient embeddings outage.
            // Embeddings wins on an id collision (the dedicated listing is the
            // authoritative embeddings source): chat is pushed first, embeddings
            // last, and the dedup keeps the last write per id.
            let embeddings_ok =
                match list_openrouter_embeddings(http, &target.base_url, &bearer).await {
                    Ok(embeddings) => {
                        combined.extend(embeddings);
                        true
                    }
                    Err(e) => {
                        tracing::warn!(
                            provider = %target.provider,
                            error = %e,
                            "embeddings model listing failed; upserting chat models but \
                             skipping reconcile this cycle (preserves last-good)"
                        );
                        false
                    }
                };
            // Reconcile only with a complete, non-degenerate picture: the embeddings
            // listing succeeded AND the chat listing was non-empty. (A *successful
            // empty* embeddings listing is not degenerate — it means the provider
            // genuinely has no embeddings models now — so it still reconciles.)
            (
                dedup_keep_last_by_id(combined),
                embeddings_ok && !chat_empty,
            )
        }

        // Unreachable: Unsupported returned above.
        DiscoverySurface::Unsupported => return Ok(0),
    };
    if models.is_empty() {
        if api_raw_len.is_some_and(|raw| raw > 0) || gemini_raw_len.is_some_and(|raw| raw > 0) {
            tracing::warn!(provider=%target.provider,listing_complete,
                "provider listing has no selected API models; only a complete listing may reconcile discovered rows");
        } else {
            tracing::warn!(provider=%target.provider,
                "discovery returned no models; preserving last-good catalog against a transient empty response");
            return Ok(0);
        }
    }

    // One transaction per target so the cycle is all-or-nothing: if any upsert
    // or the reconcile fails, the whole target's writes roll back and the catalog
    // is genuinely unchanged (last-good) — no partially-committed rows that would
    // become routable on the resolver reload.
    let tenant = waygate_core::TenantId::default();
    let mut tx = pool.begin().await?;
    let mut seen = Vec::with_capacity(models.len());
    for m in &models {
        let alias = discovered_alias(&target.provider, &m.id);
        // Per-model routing: an embeddings row speaks the embeddings surface
        // (`upstream_api = embeddings`, path `embeddings` → the resolver's
        // `LlmOperation::Embeddings`, dispatched to `/v1/embeddings`); every other
        // discovered row keeps its surface's chat routing.
        let (path, upstream_api, openai_chatgpt) = if m.is_embeddings {
            ("embeddings", "embeddings", false)
        } else {
            match surface {
                DiscoverySurface::OpenRouter => ("chat/completions", "chat_completions", false),
                DiscoverySurface::OpenAiApi => ("responses", "responses", false),
                DiscoverySurface::GoogleApi => ("v1beta", "generate_content", false),

                DiscoverySurface::Unsupported => unreachable!("Unsupported returned above"),
            }
        };
        let pricing = m.pricing.as_ref();
        let upsert = LlmDiscoveredModelUpsert {
            tenant_id: tenant.as_str().to_owned(),
            alias: alias.clone(),
            provider: target.provider.clone(),
            credential_label: target.credential_label.clone(),
            upstream_model: m.id.clone(),
            base_url: target.base_url.clone(),
            path: path.to_string(),
            upstream_api: upstream_api.to_string(),
            openai_chatgpt,
            input_cost_per_mtok: pricing.and_then(|p| p.input_per_mtok),
            output_cost_per_mtok: pricing.and_then(|p| p.output_per_mtok),
            cached_read_cost_per_mtok: pricing.and_then(|p| p.cached_read_per_mtok),
            cache_write_cost_per_mtok: pricing.and_then(|p| p.cache_write_per_mtok),
            currency: pricing.map(|p| p.currency.clone()),
        };
        waygate_storage::upsert_discovered_llm_model(&mut *tx, &upsert).await?;
        seen.push(alias);
    }
    // Skip reconcile when the listing was incomplete (a best-effort sub-listing
    // failed): soft-disabling here would clear the operation whose listing failed.
    // Same fail-open guarantee as the empty-result early return above.
    let soft_disabled = if listing_complete {
        waygate_storage::mark_discovered_absent(&mut *tx, tenant.as_str(), &target.provider, &seen)
            .await?
    } else {
        0
    };
    tx.commit().await?;
    tracing::info!(
        provider = %target.provider,
        discovered = models.len(),
        soft_disabled,
        "discovery cycle complete"
    );
    Ok(models.len())
}

/// Run one cycle across all targets (each fail-open), then reload the resolver's
/// discovered layer once from the catalog so the cycle's changes take effect on
/// routing.
async fn run_cycle(
    targets: &[DiscoveryTarget],
    http: &reqwest::Client,
    credentials: &LlmCredentialStore,
    pool: &sqlx::PgPool,
    resolver: &DbModelResolver,
) {
    for target in targets {
        if let Err(e) = refresh_target(target, http, credentials, pool).await {
            tracing::warn!(
                provider = %target.provider,
                error = %e,
                "discovery cycle failed for target; keeping last-good catalog"
            );
        }
    }
    match crate::llm::load_discovered_models(pool).await {
        Ok(map) => {
            let n = map.len();
            resolver.reload(map);
            tracing::info!(discovered = n, "discovery: resolver reloaded");
        }
        Err(e) => tracing::warn!(
            error = %e,
            "discovery: resolver reload failed; keeping last-good resolver"
        ),
    }
}

/// The discovery refresher loop: runs a cycle immediately (boot fetch), then once
/// per `interval_period`, until `shutdown` fires. Spawned as a background task so
/// it never blocks the listener.
pub async fn run_discovery_scheduler(
    targets: Vec<DiscoveryTarget>,
    http: reqwest::Client,
    credentials: Arc<LlmCredentialStore>,
    pool: sqlx::PgPool,
    resolver: Arc<DbModelResolver>,
    interval_period: Duration,
    shutdown: impl std::future::Future<Output = ()>,
) {
    use tokio::pin;
    use tokio::time::interval;

    pin!(shutdown);
    let mut ticker = interval(interval_period);
    // The first tick fires immediately → a boot-time fetch (the boot loader only
    // loaded already-persisted rows; this pulls fresh from the provider).
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tracing::info!(
        interval_secs = interval_period.as_secs(),
        targets = targets.len(),
        "discovery refresher started"
    );
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("discovery refresher shutting down");
                return;
            }
            _ = ticker.tick() => {
                run_cycle(
                    &targets,
                    &http,
                    &credentials,
                    &pool,
                    &resolver,
                )
                .await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    fn raw_test_http_client() -> reqwest::Client {
        reqwest::Client::new() // A raw test client isolates discovery reconciliation from gateway policy.
    }

    #[test]
    fn parse_targets_preserves_gemini_api_generation_selection() {
        let targets = parse_targets(
            r#"[{"provider":"google","credential_label":"API","base_url":"https://generativelanguage.googleapis.com","generate_content_models":["qualified-model"]}]"#,
        ).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].generate_content_models, vec!["qualified-model"]);
        assert!(targets[0].responses_models.is_empty());
    }

    #[tokio::test]
    async fn gemini_api_discovery_requires_qualified_models_before_io() {
        let target = DiscoveryTarget {
            provider: "google".into(),
            credential_label: "API".into(),
            base_url: "http://127.0.0.1:1".into(),
            responses_models: vec![],
            generate_content_models: vec![],
        };
        let credentials = LlmCredentialStore::from_vars([(
            "LLM_CRED_GOOGLE_API".into(),
            r#"{"api_key":"synthetic-api-key"}"#.into(),
        )]);
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .unwrap();
        let error = refresh_target(&target, &raw_test_http_client(), &credentials, &pool)
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("requires non-empty generate_content_models"));
    }

    #[test]
    fn parse_targets_preserves_public_api_responses_selection() {
        let targets = parse_targets(
            r#"[{"provider":"openai","credential_label":"API","base_url":"https://api.openai.com/v1","responses_models":["qualified-model"]}]"#,
        ).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].responses_models, vec!["qualified-model"]);
    }

    #[tokio::test]
    async fn public_api_discovery_requires_explicit_operation_selection_before_io() {
        let target = DiscoveryTarget {
            provider: "openai".into(),
            credential_label: "API".into(),
            base_url: "http://127.0.0.1:1".into(),
            responses_models: vec![],
            generate_content_models: vec![],
        };
        let credentials = LlmCredentialStore::from_vars([(
            "LLM_CRED_OPENAI_API".into(),
            r#"{"api_key":"synthetic-api-key"}"#.into(),
        )]);
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .unwrap();
        let error = refresh_target(&target, &raw_test_http_client(), &credentials, &pool)
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("requires non-empty responses_models"));
    }

    #[test]
    fn parse_targets_keeps_api_adapter_providers_and_rejects_malformed_config() {
        let targets = parse_targets(r#"[
            {"provider":"openrouter","credential_label":"MAIN","base_url":"https://openrouter.ai/api/v1"},
            {"provider":"anthropic","credential_label":"API","base_url":"https://api.anthropic.com/v1"},
            {"provider":"openai","credential_label":"API","base_url":"https://api.openai.com/v1","responses_models":["qualified-model"]}
        ]"#).unwrap();
        assert_eq!(
            targets
                .iter()
                .map(|t| t.provider.as_str())
                .collect::<Vec<_>>(),
            vec!["openrouter", "openai"]
        );
        assert_eq!(targets[1].credential_label, "API");
        assert!(parse_targets("").unwrap().is_empty());
        assert!(parse_targets("  ").unwrap().is_empty());
        assert!(parse_targets("[]").unwrap().is_empty());
        assert!(parse_targets("not json").is_err());
    }

    #[test]
    fn parse_targets_rejects_retired_consumer_version_settings() {
        let error = parse_targets(r#"[{"provider":"openai","credential_label":"API","base_url":"https://api.openai.com/v1","client_version":"0.144.0"}]"#).unwrap_err();
        assert!(error.to_string().contains("retired consumer setting"));
    }

    #[test]
    fn parse_targets_dedupes_by_provider() {
        let targets = parse_targets(
            r#"[
            {"provider":"openrouter","credential_label":"FIRST","base_url":"https://a"},
            {"provider":"OpenRouter","credential_label":"SECOND","base_url":"https://b"}
        ]"#,
        )
        .unwrap();
        assert_eq!(
            targets.len(),
            1,
            "provider-scoped reconciliation keeps the first target"
        );
        assert_eq!(targets[0].credential_label, "FIRST");
    }

    #[test]
    fn discovered_alias_is_provider_namespaced() {
        assert_eq!(
            discovered_alias("openrouter", "openai/gpt-4o"),
            "openrouter:openai/gpt-4o"
        );
    }

    // --- Integration: refresh_target against a loopback OpenRouter + live PG ----

    use std::net::SocketAddr;
    use std::sync::Mutex;

    use axum::extract::State;
    use axum::routing::get;
    use axum::Router;

    /// A loopback OpenRouter fake whose model-list body can be swapped between
    /// cycles, so a test can drive "model disappears" reconciliation.
    async fn serve_openrouter(body: Arc<Mutex<String>>) -> String {
        let app = Router::new()
            .route(
                "/api/v1/models",
                get(|State(b): State<Arc<Mutex<String>>>| async move {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        b.lock().unwrap().clone(),
                    )
                }),
            )
            .route(
                // Best-effort embeddings catalog; this fake has no embeddings
                // models, so the chat-discovery test sees a present-but-empty
                // listing rather than a 404 (which the refresher tolerates anyway).
                "/api/v1/embeddings/models",
                get(|| async {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        r#"{"data":[]}"#,
                    )
                }),
            )
            .with_state(body);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/api/v1")
    }

    fn body_with(ids: &[&str]) -> String {
        let data: Vec<String> = ids
            .iter()
            .map(|id| {
                format!(
                    r#"{{"id":"{id}","pricing":{{"prompt":"0.0000030","completion":"0.0000060"}}}}"#
                )
            })
            .collect();
        format!(r#"{{"data":[{}]}}"#, data.join(","))
    }

    async fn present_upstream(pool: &sqlx::PgPool, tenant: &str, alias: &str) -> bool {
        sqlx::query_scalar::<_, bool>(
            "SELECT present_upstream FROM llm_models WHERE tenant_id = $1 AND alias = $2",
        )
        .bind(tenant)
        .bind(alias)
        .fetch_one(pool)
        .await
        .expect("row")
    }

    #[tokio::test]
    async fn refresh_target_public_openai_reconciles_only_explicit_responses_models() {
        let Ok(url) = std::env::var("AUDIT_DATABASE_URL") else {
            eprintln!("skipping OpenAI API discovery pg test: AUDIT_DATABASE_URL not set");
            return;
        };
        let _serial = super::DISCOVERY_PG_LOCK.lock().await;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        waygate_storage::PgAuditSink::migrate(&pool).await.unwrap();
        let tenant = waygate_core::TenantId::default().as_str().to_owned();
        let id = format!("api-{}", uuid::Uuid::now_v7().simple());
        let alias = discovered_alias("openai", &id);
        let body = Arc::new(Mutex::new(body_with(&[&id, "gpt-image-2"])));
        let base_url = serve_openrouter(body.clone()).await;
        let credentials = LlmCredentialStore::from_vars([(
            "LLM_CRED_OPENAI_API".into(),
            r#"{"api_key":"synthetic-api-key"}"#.into(),
        )]);
        let target = DiscoveryTarget {
            provider: "openai".into(),
            credential_label: "API".into(),
            base_url,
            responses_models: vec![id.clone()],
            generate_content_models: vec![],
        };
        let http = raw_test_http_client();
        assert_eq!(
            refresh_target(&target, &http, &credentials, &pool)
                .await
                .unwrap(),
            1
        );
        let row = waygate_storage::get_llm_model(&pool, &tenant, &alias)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.upstream_api, "responses");
        assert_eq!(row.path, "responses");
        assert!(!row.openai_chatgpt);
        assert!(row.input_cost_per_mtok.is_none());
        assert_eq!(row.credential_label, "API");
        *body.lock().unwrap() = r#"{"data":[]}"#.into();
        refresh_target(&target, &http, &credentials, &pool)
            .await
            .unwrap();
        assert!(present_upstream(&pool, &tenant, &alias).await);
        *body.lock().unwrap() = body_with(&["gpt-image-2"]);
        refresh_target(&target, &http, &credentials, &pool)
            .await
            .unwrap();
        assert!(!present_upstream(&pool, &tenant, &alias).await);
        sqlx::query("DELETE FROM llm_models WHERE tenant_id=$1 AND alias=$2")
            .bind(&tenant)
            .bind(&alias)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn refresh_target_gemini_api_reconciles_selected_generation_models() {
        let Ok(url) = std::env::var("AUDIT_DATABASE_URL") else {
            eprintln!("skipping Gemini API discovery pg test: AUDIT_DATABASE_URL not set");
            return;
        };
        let _serial = super::DISCOVERY_PG_LOCK.lock().await;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        waygate_storage::PgAuditSink::migrate(&pool).await.unwrap();
        let tenant = waygate_core::TenantId::default().as_str().to_owned();
        let id = format!("qualified-{}", uuid::Uuid::now_v7().simple());
        let alias = discovered_alias("google", &id);
        let body = Arc::new(Mutex::new(
            serde_json::json!({"models":[
                {"name":format!("models/{id}"),"supportedGenerationMethods":["generateContent"]},
                {"name":"models/unselected-image","supportedGenerationMethods":["generateContent"]}
            ]})
            .to_string(),
        ));
        let app=axum::Router::new().route("/v1beta/models",axum::routing::get(
            |axum::extract::State(body):axum::extract::State<Arc<Mutex<String>>>| async move {
                ([(axum::http::header::CONTENT_TYPE,"application/json")],body.lock().unwrap().clone())
            }
        )).with_state(body.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let credentials = LlmCredentialStore::from_vars([(
            "LLM_CRED_GOOGLE_API".into(),
            r#"{"api_key":"synthetic-api-key"}"#.into(),
        )]);
        let target = DiscoveryTarget {
            provider: "google".into(),
            credential_label: "API".into(),
            base_url,
            generate_content_models: vec![id.clone()],
            responses_models: vec![],
        };
        let http = raw_test_http_client();
        assert_eq!(
            refresh_target(&target, &http, &credentials, &pool)
                .await
                .unwrap(),
            1
        );
        let row = waygate_storage::get_llm_model(&pool, &tenant, &alias)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.upstream_api, "generate_content");
        assert_eq!(row.path, "v1beta");
        assert!(!row.openai_chatgpt);
        assert!(row.input_cost_per_mtok.is_none());
        let models = crate::llm::load_discovered_models(&pool).await.unwrap();
        let resolved = models
            .get(&(crate::llm::LLM_SERVER.into(), alias.clone()))
            .unwrap();
        assert_eq!(
            resolved.route.protocol,
            waygate_llm_translate::UpstreamProtocol::Gemini
        );
        *body.lock().unwrap() =
            serde_json::json!({"models":[{"name":format!("models/{id}")}]}).to_string();
        assert!(refresh_target(&target, &http, &credentials, &pool)
            .await
            .is_err());
        assert!(present_upstream(&pool, &tenant, &alias).await);
        *body.lock().unwrap()=serde_json::json!({"models":[{"name":format!("models/{id}"),"supportedGenerationMethods":["embedContent"]}]}).to_string();
        refresh_target(&target, &http, &credentials, &pool)
            .await
            .unwrap();
        assert!(!present_upstream(&pool, &tenant, &alias).await);
        sqlx::query("DELETE FROM llm_models WHERE tenant_id=$1 AND alias=$2")
            .bind(&tenant)
            .bind(&alias)
            .execute(&pool)
            .await
            .unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn refresh_target_upserts_prices_and_reconciles() {
        let Ok(url) = std::env::var("AUDIT_DATABASE_URL") else {
            eprintln!("skipping refresh_target pg test: AUDIT_DATABASE_URL not set");
            return;
        };
        let _serial = super::DISCOVERY_PG_LOCK.lock().await;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect");
        waygate_storage::PgAuditSink::migrate(&pool)
            .await
            .expect("migrate");
        let tenant = waygate_core::TenantId::default().as_str().to_owned();

        // Two unique model ids so this run never collides with another.
        let run = uuid::Uuid::now_v7().simple().to_string();
        let m1 = format!("vendor/{run}-a");
        let m2 = format!("vendor/{run}-b");

        let body = Arc::new(Mutex::new(body_with(&[&m1, &m2])));
        let base_url = serve_openrouter(body.clone()).await;
        let credentials = LlmCredentialStore::from_vars([(
            "LLM_CRED_OPENROUTER_MAIN".to_string(),
            "sk-test".to_string(),
        )]);
        let http = raw_test_http_client();
        let target = DiscoveryTarget {
            provider: "openrouter".into(),
            credential_label: "MAIN".into(),
            base_url,
            responses_models: vec![],
            generate_content_models: vec![],
        };

        // Cycle 1: both models discovered, priced, present.
        let n = refresh_target(&target, &http, &credentials, &pool)
            .await
            .expect("cycle 1");
        assert_eq!(n, 2);
        let alias1 = discovered_alias("openrouter", &m1);
        let alias2 = discovered_alias("openrouter", &m2);
        let row1 = waygate_storage::get_llm_model(&pool, &tenant, &alias1)
            .await
            .unwrap()
            .expect("m1 upserted");
        assert_eq!(
            row1.upstream_model, m1,
            "raw id preserved as upstream_model"
        );
        // 0.000003 USD/token → 3 per-Mtok (normalize strips the scale's trailing
        // zeros; compared as a string to avoid a rust_decimal dev-dep).
        assert_eq!(
            row1.input_cost_per_mtok
                .as_ref()
                .map(|d| d.normalize().to_string()),
            Some("3".to_string()),
        );
        assert!(present_upstream(&pool, &tenant, &alias2).await);

        // Cycle 2: m2 disappears from the listing → soft-disabled, m1 stays.
        *body.lock().unwrap() = body_with(&[&m1]);
        refresh_target(&target, &http, &credentials, &pool)
            .await
            .expect("cycle 2");
        assert!(
            present_upstream(&pool, &tenant, &alias1).await,
            "m1 still present"
        );
        assert!(
            !present_upstream(&pool, &tenant, &alias2).await,
            "the disappeared m2 is soft-disabled, not deleted"
        );

        // Cycle 3: an empty listing must NOT reconcile (fail-open) — m1 stays present.
        *body.lock().unwrap() = r#"{"data":[]}"#.to_string();
        let n3 = refresh_target(&target, &http, &credentials, &pool)
            .await
            .expect("cycle 3");
        assert_eq!(n3, 0);
        assert!(
            present_upstream(&pool, &tenant, &alias1).await,
            "an empty response does not mass-soft-disable the catalog"
        );

        sqlx::query("DELETE FROM llm_models WHERE tenant_id = $1 AND alias = ANY($2)")
            .bind(&tenant)
            .bind(vec![alias1, alias2])
            .execute(&pool)
            .await
            .expect("cleanup");
    }

    /// A loopback OpenRouter fake serving BOTH the chat `/models` and the
    /// embeddings `/embeddings/models` listings, each with an independently
    /// swappable body, so a test can drive the dual-listing refresh and its
    /// reconcile across operations.
    async fn serve_openrouter_dual(
        chat_body: Arc<Mutex<String>>,
        emb_body: Arc<Mutex<String>>,
    ) -> String {
        type Bodies = (Arc<Mutex<String>>, Arc<Mutex<String>>);
        let app = Router::new()
            .route(
                "/api/v1/models",
                get(|State((chat, _)): State<Bodies>| async move {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        chat.lock().unwrap().clone(),
                    )
                }),
            )
            .route(
                "/api/v1/embeddings/models",
                get(|State((_, emb)): State<Bodies>| async move {
                    use axum::response::IntoResponse;
                    let body = emb.lock().unwrap().clone();
                    // The `__FAIL__` sentinel drives the best-effort failure path
                    // (a transient `/embeddings/models` outage).
                    if body == "__FAIL__" {
                        return (
                            axum::http::StatusCode::SERVICE_UNAVAILABLE,
                            "embeddings down",
                        )
                            .into_response();
                    }
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        body,
                    )
                        .into_response()
                }),
            )
            .with_state((chat_body, emb_body));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/api/v1")
    }

    #[tokio::test]
    async fn refresh_target_discovers_embeddings_distinctly_and_reconcile_keeps_both() {
        let Ok(url) = std::env::var("AUDIT_DATABASE_URL") else {
            eprintln!("skipping embeddings discovery pg test: AUDIT_DATABASE_URL not set");
            return;
        };
        let _serial = super::DISCOVERY_PG_LOCK.lock().await;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect");
        waygate_storage::PgAuditSink::migrate(&pool)
            .await
            .expect("migrate");
        let tenant = waygate_core::TenantId::default().as_str().to_owned();

        let run = uuid::Uuid::now_v7().simple().to_string();
        let chat_id = format!("vendor/{run}-chat");
        let emb_id = format!("vendor/{run}-embed");
        let chat_body = Arc::new(Mutex::new(body_with(&[&chat_id])));
        let emb_body = Arc::new(Mutex::new(body_with(&[&emb_id])));
        let base_url = serve_openrouter_dual(chat_body.clone(), emb_body.clone()).await;

        let credentials = LlmCredentialStore::from_vars([(
            "LLM_CRED_OPENROUTER_MAIN".to_string(),
            "sk-test".to_string(),
        )]);
        let http = raw_test_http_client();
        let target = DiscoveryTarget {
            provider: "openrouter".into(),
            credential_label: "MAIN".into(),
            base_url,
            responses_models: vec![],
            generate_content_models: vec![],
        };
        let chat_alias = discovered_alias("openrouter", &chat_id);
        let emb_alias = discovered_alias("openrouter", &emb_id);

        // Cycle 1: a chat model and an embeddings model discovered in one cycle.
        let n = refresh_target(&target, &http, &credentials, &pool)
            .await
            .expect("cycle 1");
        assert_eq!(n, 2, "both the chat and embeddings models are discovered");

        // The embeddings row is tagged distinctly — this is what makes it a
        // first-class embeddings model in the catalog (vs the chat row).
        let emb_row = waygate_storage::get_llm_model(&pool, &tenant, &emb_alias)
            .await
            .unwrap()
            .expect("embeddings row upserted");
        assert_eq!(emb_row.upstream_api, "embeddings");
        assert_eq!(emb_row.path, "embeddings");
        assert!(!emb_row.openai_chatgpt);
        let chat_row = waygate_storage::get_llm_model(&pool, &tenant, &chat_alias)
            .await
            .unwrap()
            .expect("chat row upserted");
        assert_eq!(chat_row.upstream_api, "chat_completions");
        assert_eq!(chat_row.path, "chat/completions");

        // The UNION guard: both are present after the mixed cycle. Without the
        // unioned seen-set, the single provider-scoped reconcile would have
        // soft-disabled whichever operation's models weren't in the (chat-only)
        // seen — here, the embeddings model.
        assert!(
            present_upstream(&pool, &tenant, &chat_alias).await,
            "chat present"
        );
        assert!(
            present_upstream(&pool, &tenant, &emb_alias).await,
            "embeddings present (not cross-soft-disabled by the chat reconcile)"
        );

        // The resolver routes the embeddings row as a DISTINCT operation and the
        // chat row as chat — so `/v1/embeddings` vs `/v1/chat/completions` dispatch
        // correctly after the cycle reloads the resolver.
        let resolved = crate::llm::load_discovered_models(&pool)
            .await
            .expect("resolve discovered");
        let key = |alias: &str| (crate::llm::LLM_SERVER.to_string(), alias.to_string());
        assert_eq!(
            resolved
                .get(&key(&emb_alias))
                .expect("embeddings resolves")
                .operation,
            waygate_llm_dispatch::LlmOperation::Embeddings,
        );
        assert_eq!(
            resolved
                .get(&key(&chat_alias))
                .expect("chat resolves")
                .operation,
            waygate_llm_dispatch::LlmOperation::Chat,
        );

        // Cycle 2 (fail-open): the embeddings listing FAILS (a transient outage)
        // while chat is unchanged. The cycle must upsert chat but SKIP reconcile,
        // so the previously-discovered embeddings row stays present — a partial
        // embeddings failure must never soft-disable last-good embeddings models.
        *emb_body.lock().unwrap() = "__FAIL__".to_string();
        refresh_target(&target, &http, &credentials, &pool)
            .await
            .expect("cycle 2 (embeddings listing fails)");
        assert!(
            present_upstream(&pool, &tenant, &chat_alias).await,
            "chat still present after embeddings listing failure"
        );
        assert!(
            present_upstream(&pool, &tenant, &emb_alias).await,
            "a transient embeddings listing failure preserves last-good embeddings rows (no reconcile)"
        );

        // Cycle 2b (fail-open, symmetric): the CHAT listing returns a successful
        // EMPTY list (the transient/garble case) while embeddings has models again.
        // Reconcile must be skipped — an empty chat listing must not soft-disable
        // the existing chat alias. Restore the embeddings listing to a present model
        // so this cycle isolates the chat-empty condition.
        *chat_body.lock().unwrap() = r#"{"data":[]}"#.to_string();
        *emb_body.lock().unwrap() = body_with(&[&emb_id]);
        refresh_target(&target, &http, &credentials, &pool)
            .await
            .expect("cycle 2b (chat listing empty)");
        assert!(
            present_upstream(&pool, &tenant, &chat_alias).await,
            "an empty chat listing preserves the existing chat alias (no reconcile)"
        );
        // Restore the chat listing for the genuine-removal cycle below.
        *chat_body.lock().unwrap() = body_with(&[&chat_id]);

        // Cycle 3: the embeddings model genuinely disappears from a SUCCESSFUL
        // embeddings listing (chat unchanged) → it is soft-disabled, the chat model
        // stays. Proves reconcile acts on embeddings rows too, scoped to the
        // provider, without disturbing chat.
        *emb_body.lock().unwrap() = r#"{"data":[]}"#.to_string();
        refresh_target(&target, &http, &credentials, &pool)
            .await
            .expect("cycle 3");
        assert!(
            present_upstream(&pool, &tenant, &chat_alias).await,
            "chat still present"
        );
        assert!(
            !present_upstream(&pool, &tenant, &emb_alias).await,
            "the disappeared embeddings model is soft-disabled"
        );

        sqlx::query("DELETE FROM llm_models WHERE tenant_id = $1 AND alias = ANY($2)")
            .bind(&tenant)
            .bind(vec![chat_alias, emb_alias])
            .execute(&pool)
            .await
            .expect("cleanup");
    }
}
