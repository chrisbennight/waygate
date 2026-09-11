//! Discovery refresher: periodically enumerate each configured provider's live
//! model list and upsert the results into the `llm_models` catalog, so an
//! operator no longer hand-lists every model in `GATEWAY_LLM_MODELS`. The
//! DB-backed resolver (`waygate_llm_dispatch::DbModelResolver`) then makes the
//! discovered models routable after each cycle reloads it.
//!
//! Scope today: **OpenRouter** (api-key listing, with pricing — chat models from
//! `/models` AND embeddings models from the dedicated `/embeddings/models`, each
//! tagged by operation) and **OpenAI Codex** (subscription OAuth — the
//! ChatGPT-backend `/models` listing, no pricing). Each provider shares one base
//! URL between discovery and chat: OpenRouter's `/models` + `/embeddings/models`
//! (discovery) and `/chat/completions` + `/embeddings` (dispatch); Codex's
//! `/models` + `/responses` (the Responses shape against the ChatGPT backend,
//! which dispatch authenticates with the Codex request fingerprint via the
//! discovered row's `openai_chatgpt` flag). Anthropic and Gemini stay deferred — Anthropic's
//! first-party `x-api-key` `/v1/models` adapter is unwired, Gemini's is
//! unverified — so their models remain operator-pinned.
//! [`waygate_llm_discovery::DiscoverySurface`]
//! maps each `(provider, auth-kind)` to its adapter; an `Unsupported` mapping is
//! a normal outcome the refresher skips.
//!
//! ## The Codex listing's `client_version`
//!
//! The ChatGPT backend scopes its `/models` response to what the named CLI
//! release may see (an old version gets an old subset; an ancient one an empty
//! list), so the version sent must track CLI releases. Resolution order per
//! Codex cycle: the target's optional `client_version` pin (operator override,
//! bypasses tracking) → [`waygate_llm_discovery::CodexVersionTracker`] (the
//! live release trackers, cached on a TTL, falling back through last-good to
//! the compiled default). The tracker never fails, so a registry outage
//! degrades to a possibly-stale version — never a skipped cycle.
//!
//! ## Safety
//!
//! - **Fail-open.** A target whose discovery fails (transport, auth, decode) logs
//!   a `WARN` and leaves the catalog untouched — the last-good rows keep serving.
//!   An *empty* result skips reconciliation entirely, so a transient empty/garbled
//!   response can never mass-soft-disable a provider's catalog. For Codex,
//!   "empty" means the **raw** listing was empty: a non-empty listing whose every
//!   model was filtered as non-picker-visible is a complete answer and DOES
//!   reconcile (empty seen-set ⇒ soft-disable all) — otherwise a previously
//!   discovered, now-hidden model would stay routable.
//! - **Reconcile only after a successful, non-empty fetch.** `mark_discovered_absent`
//!   runs per `(tenant, provider)` only with the just-seen alias set, so a dropped
//!   model is soft-disabled (retained, hidden) — never deleted, and a pin is never
//!   touched (the storage layer scopes reconciliation to `source = 'discovered'`).
//!   For OpenRouter the seen set is the **union** of the chat and embeddings
//!   listings, so the single provider-scoped reconcile never soft-disables one
//!   operation's models because the other operation's listing changed. The picture
//!   is treated as **incomplete** — and reconcile **skipped** that cycle (last-good
//!   preserved) — if the best-effort embeddings listing *fails* OR the primary chat
//!   listing returns *empty* (the transient/garble case), so a partial or
//!   degenerate listing never soft-disables previously-discovered rows. (A
//!   *successful empty* embeddings listing is not degenerate — the provider has no
//!   embeddings models — so it still reconciles them away.)
//! - **Bounded.** The interval is floored so a misconfiguration can't hammer
//!   providers; the HTTP client carries a request timeout.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use waygate_llm_credentials::LlmCredentialStore;
use waygate_llm_discovery::{
    is_valid_codex_client_version, list_codex, list_openrouter, list_openrouter_embeddings,
    CodexVersionTracker, DiscoveredModel, DiscoverySurface,
};
use waygate_llm_dispatch::DbModelResolver;
use waygate_llm_providers::SharedCodexUaVersion;
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
    /// Provider in the lowercase vocabulary (`openrouter`, `openai`).
    pub provider: String,
    /// The injected credential label (`LLM_CRED_<PROVIDER>_<LABEL>`) whose bearer
    /// authenticates both the listing and the discovered models' chat calls. Its
    /// kind (api-key vs OAuth) also selects the discovery surface for `openai`
    /// (OAuth ⇒ Codex; an api key ⇒ skipped).
    pub credential_label: String,
    /// Provider base URL shared by the model listing (`/models`) and the chat
    /// route the discovered models point at. OpenRouter:
    /// `https://openrouter.ai/api/v1` (listing `/models`, chat `/chat/completions`).
    /// Codex: `https://chatgpt.com/backend-api/codex` (listing `/models`, chat
    /// `/responses`).
    pub base_url: String,
    /// Operator pin for the Codex listing's `client_version` (the backend
    /// scopes the returned models to what that CLI release may see). `None` —
    /// the normal case — lets the refresher resolve a current version via the
    /// release tracker; a pin bypasses the tracker entirely for this target.
    /// Ignored by non-Codex surfaces.
    pub client_version: Option<String>,
}

#[derive(Deserialize)]
struct RawTarget {
    provider: String,
    credential_label: String,
    base_url: String,
    #[serde(default)]
    client_version: Option<String>,
}

/// Default discovery interval (3h) and floor (5 min) so a misconfigured interval
/// can't hammer providers. Parsed at the `main.rs` use site via
/// `waygate_core::env::duration_secs` — a sub-floor or garbage
/// `GATEWAY_LLM_DISCOVERY_INTERVAL_SECS` rejects at boot.
pub(crate) const DEFAULT_INTERVAL_SECS: u64 = 3 * 60 * 60;
pub(crate) const MIN_INTERVAL_SECS: u64 = 300;

/// Parse `GATEWAY_LLM_DISCOVERY` (a JSON array of targets). Targets whose
/// provider has no wired discovery adapter (`openrouter` or `openai`/Codex today)
/// are dropped with a `WARN`. The concrete surface for a kept target is resolved
/// later, in [`refresh_target`], from the credential's actual auth-kind — parse
/// time has no credential store, so it can only gate on whether the provider has
/// an adapter under *some* auth-kind (see
/// [`DiscoverySurface::provider_has_adapter`]). An `openai` target backed by an
/// api key (not Codex OAuth) is kept here but skipped at refresh.
///
/// **At most one target per provider** is kept: reconciliation
/// (`mark_discovered_absent`) is provider-scoped, so two targets sharing a
/// provider would each soft-disable the other's discovered models, leaving only
/// the last one effective-live. The first target for a provider wins; a later
/// duplicate is dropped with a `WARN`. A blank value, invalid JSON, or an empty
/// array yields no targets, so the refresher does not spawn (discovery is off by
/// default).
pub fn parse_targets(raw: &str) -> Vec<DiscoveryTarget> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Vec::new();
    }
    let parsed: Vec<RawTarget> = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "GATEWAY_LLM_DISCOVERY is not a valid JSON array; discovery disabled");
            return Vec::new();
        }
    };
    let mut seen_providers = std::collections::HashSet::new();
    parsed
        .into_iter()
        .filter_map(|t| {
            // Keep any provider with a wired adapter under SOME auth-kind; the
            // refresher resolves the concrete surface per credential. parse_targets
            // has no credential store, so it cannot know the auth-kind here.
            if !DiscoverySurface::provider_has_adapter(&t.provider) {
                tracing::warn!(
                    provider = %t.provider,
                    "discovery target has no wired adapter (supported: openrouter, openai/codex); skipping"
                );
                return None;
            }
            let provider = t.provider.to_ascii_lowercase();
            if !seen_providers.insert(provider.clone()) {
                tracing::warn!(
                    provider = %provider,
                    "duplicate discovery target for provider; keeping the first and skipping \
                     this one (reconciliation is provider-scoped)"
                );
                return None;
            }
            // A malformed client_version pin would be rejected by the Codex
            // backend with a 400 on every cycle. Dropping the PIN (not the
            // target) fails toward the release tracker, so discovery still
            // runs — with a loud WARN so the operator fixes the pin.
            let client_version = t.client_version.filter(|v| {
                let ok = is_valid_codex_client_version(v);
                if !ok {
                    tracing::warn!(
                        provider = %provider,
                        client_version = %v,
                        "discovery target's client_version pin is not MAJOR.MINOR.PATCH; \
                         ignoring the pin (the release tracker will resolve the version)"
                    );
                }
                ok
            });
            Some(DiscoveryTarget {
                provider,
                credential_label: t.credential_label,
                base_url: t.base_url,
                client_version,
            })
        })
        .collect()
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
    codex_version: &CodexVersionTracker,
    codex_ua: Option<&SharedCodexUaVersion>,
) -> anyhow::Result<usize> {
    let provider = crate::llm::parse_provider(&target.provider)?;
    // The credential's KIND picks the surface (api-key OpenRouter vs OAuth Codex).
    // parse_targets kept this target on provider alone (no credential store), so
    // resolve the kind here and skip if it maps to no wired surface.
    let is_oauth = credentials
        .credential_is_oauth(provider, &target.credential_label)
        .await
        .ok_or_else(|| {
            anyhow::anyhow!(
                "discovery credential {}/{} is not configured",
                target.provider,
                target.credential_label
            )
        })?;
    let surface = DiscoverySurface::for_provider(&target.provider, is_oauth);
    if surface == DiscoverySurface::Unsupported {
        tracing::warn!(
            provider = %target.provider,
            credential_label = %target.credential_label,
            "discovery target's credential maps to no wired surface \
             (e.g. openai api-key, not Codex OAuth); skipping"
        );
        return Ok(0);
    }
    let bearer = credentials
        .bearer(provider, &target.credential_label)
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
    // The client_version the Codex arm sent, kept for the empty-listing WARN
    // below: an empty Codex listing usually means the version was too old for
    // the backend (it returns an empty — not error — response for a version
    // below what it supports), and naming the version makes that diagnosable.
    let mut codex_client_version: Option<String> = None;
    // How many models the raw Codex response carried BEFORE the visibility
    // filter. Distinguishes "the backend returned nothing" (fail-open below)
    // from "the backend returned models but none are picker-visible" — the
    // latter is a complete answer that must reconcile, or a previously
    // discovered now-hidden model would stay routable.
    let mut codex_raw_len: Option<usize> = None;
    let (models, listing_complete): (Vec<DiscoveredModel>, bool) = match surface {
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
        DiscoverySurface::Codex => {
            // The ChatGPT workspace id (`chatgpt-account-id`) when the OAuth blob
            // carried one; the backend gates the listing on it for multi-workspace
            // accounts. `None` is fine for a single-workspace token.
            let account_id = credentials
                .oauth_account_id(provider, &target.credential_label)
                .await;
            // Version resolution: the operator pin bypasses the tracker; the
            // tracker itself never fails (last-good / compiled-default chain).
            let client_version = match &target.client_version {
                Some(pinned) => pinned.clone(),
                None => codex_version.current(http).await,
            };
            // Publish the version this cycle lists models as into the shared
            // dispatch handle, so the /responses User-Agent fingerprint
            // presents the same client identity as the listing fetch.
            if let Some(handle) = codex_ua {
                *handle.write().expect("codex ua version lock") = client_version.clone();
            }
            let listing = list_codex(
                http,
                &target.base_url,
                &bearer,
                account_id.as_deref(),
                &client_version,
            )
            .await?;
            codex_client_version = Some(client_version);
            codex_raw_len = Some(listing.raw_len);
            // A malformed entry (missing/empty slug) means the payload cannot
            // be trusted as the complete model universe: upsert what parsed
            // cleanly but mark the picture INCOMPLETE so reconcile is skipped
            // this cycle — a garbled response never soft-disables last-good
            // rows (the same incomplete-picture rule as OpenRouter).
            let complete = listing.malformed_len == 0;
            if !complete {
                tracing::warn!(
                    provider = %target.provider,
                    malformed = listing.malformed_len,
                    raw_models = listing.raw_len,
                    "codex listing carries malformed (slugless) entries; \
                     treating it as incomplete and skipping reconcile this cycle"
                );
            }
            (listing.models, complete)
        }
        // Unreachable: Unsupported returned above.
        DiscoverySurface::Unsupported => return Ok(0),
    };
    if models.is_empty() {
        // A Codex listing that was non-empty upstream, WELL-FORMED throughout,
        // and filtered to zero picker-visible models is a COMPLETE answer, not
        // a transient failure: fall through so the reconcile below runs with
        // an empty seen-set and soft-disables every previously discovered row
        // (none are picker-visible anymore). A raw-empty listing stays
        // fail-open, and a listing with malformed entries is incomplete
        // (listing_complete = false) — its reconcile is skipped below anyway,
        // so it exits early here with the incompleteness already logged.
        let codex_all_filtered = codex_raw_len.is_some_and(|raw| raw > 0) && listing_complete;
        if codex_all_filtered {
            tracing::warn!(
                provider = %target.provider,
                raw_models = codex_raw_len.unwrap_or(0),
                "codex listing carries no picker-visible models; reconciling \
                 previously discovered rows away (soft-disable)"
            );
        } else {
            match &codex_client_version {
                // The malformed-entry case already logged its own WARN at the
                // fetch site; this diagnostic is for the RAW-EMPTY listing,
                // which is what a too-old client_version looks like (the
                // backend scopes the listing to the version and returns empty
                // — not an error — below its supported range), so name the
                // version sent.
                Some(sent) if codex_raw_len == Some(0) => tracing::warn!(
                    provider = %target.provider,
                    client_version = %sent,
                    "codex discovery returned no models — likely a too-old \
                     client_version (the backend returns an empty listing below \
                     its supported range); skipping reconcile (fail-open)"
                ),
                Some(_) => {}
                None => tracing::warn!(
                    provider = %target.provider,
                    "discovery returned no models; skipping reconcile (fail-open against a transient empty response)"
                ),
            }
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
                DiscoverySurface::Codex => ("responses", "responses", true),
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
    codex_version: &CodexVersionTracker,
    codex_ua: Option<&SharedCodexUaVersion>,
) {
    for target in targets {
        if let Err(e) =
            refresh_target(target, http, credentials, pool, codex_version, codex_ua).await
        {
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
// Each parameter is an independent runtime dependency (client, credentials,
// pool, resolver, the shared Codex UA handle) rather than a data-clump worth a
// struct, and the generic `shutdown` future can't live in a plain params
// struct — so the arg count is inherent, not accidental.
#[allow(clippy::too_many_arguments)]
pub async fn run_discovery_scheduler(
    targets: Vec<DiscoveryTarget>,
    http: reqwest::Client,
    credentials: Arc<LlmCredentialStore>,
    pool: sqlx::PgPool,
    resolver: Arc<DbModelResolver>,
    interval_period: Duration,
    codex_ua: Option<SharedCodexUaVersion>,
    shutdown: impl std::future::Future<Output = ()>,
) {
    use tokio::pin;
    use tokio::time::interval;

    pin!(shutdown);
    let mut ticker = interval(interval_period);
    // The first tick fires immediately → a boot-time fetch (the boot loader only
    // loaded already-persisted rows; this pulls fresh from the provider).
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // One tracker for the scheduler's lifetime so its TTL cache and last-good
    // fallback span cycles (a per-cycle tracker would re-fetch every cycle and
    // forget last-good across an outage).
    let codex_version = CodexVersionTracker::default();
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
                    &codex_version,
                    codex_ua.as_ref(),
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
    fn parse_targets_keeps_adapter_providers_drops_unsupported() {
        let raw = r#"[
            {"provider":"openrouter","credential_label":"MAIN","base_url":"https://openrouter.ai/api/v1"},
            {"provider":"anthropic","credential_label":"X","base_url":"https://api.anthropic.com/v1"},
            {"provider":"openai","credential_label":"CODEX","base_url":"https://chatgpt.com/backend-api/codex"}
        ]"#;
        let targets = parse_targets(raw);
        // openrouter and openai both have a wired adapter under SOME auth-kind, so
        // both survive the parse-time gate (openai's concrete surface — Codex vs
        // skipped — is resolved later from its credential). anthropic has no
        // adapter at all and is dropped here.
        let providers: Vec<&str> = targets.iter().map(|t| t.provider.as_str()).collect();
        assert_eq!(providers, vec!["openrouter", "openai"]);

        let openrouter = targets.iter().find(|t| t.provider == "openrouter").unwrap();
        assert_eq!(openrouter.credential_label, "MAIN");
        assert_eq!(openrouter.base_url, "https://openrouter.ai/api/v1");
        let openai = targets.iter().find(|t| t.provider == "openai").unwrap();
        assert_eq!(openai.credential_label, "CODEX");
        assert_eq!(openai.base_url, "https://chatgpt.com/backend-api/codex");
        assert_eq!(
            openai.client_version, None,
            "no pin ⇒ the release tracker resolves the version"
        );

        // Blank / invalid / empty array ⇒ no targets (refresher won't spawn).
        assert!(parse_targets("").is_empty());
        assert!(parse_targets("   ").is_empty());
        assert!(parse_targets("not json").is_empty());
        assert!(parse_targets("[]").is_empty());
    }

    #[test]
    fn parse_targets_validates_the_client_version_pin() {
        // A well-formed pin is kept; a malformed one (the backend would 400 on
        // it every cycle) is dropped while the TARGET survives, failing toward
        // the release tracker rather than disabling discovery.
        let raw = r#"[
            {"provider":"openai","credential_label":"CODEX","base_url":"https://chatgpt.com/backend-api/codex","client_version":"0.144.0"},
            {"provider":"openrouter","credential_label":"MAIN","base_url":"https://a","client_version":"not-a-version"}
        ]"#;
        let targets = parse_targets(raw);
        assert_eq!(targets.len(), 2, "both targets survive");
        let openai = targets.iter().find(|t| t.provider == "openai").unwrap();
        assert_eq!(openai.client_version.as_deref(), Some("0.144.0"));
        let openrouter = targets.iter().find(|t| t.provider == "openrouter").unwrap();
        assert_eq!(
            openrouter.client_version, None,
            "the malformed pin is dropped, not the target"
        );
    }

    #[test]
    fn parse_targets_dedupes_by_provider() {
        // Two openrouter targets ⇒ only the FIRST is kept: reconciliation is
        // provider-scoped, so a second would soft-disable the first's models.
        let raw = r#"[
            {"provider":"openrouter","credential_label":"FIRST","base_url":"https://a"},
            {"provider":"OpenRouter","credential_label":"SECOND","base_url":"https://b"}
        ]"#;
        let targets = parse_targets(raw);
        assert_eq!(
            targets.len(),
            1,
            "the duplicate openrouter provider is dropped"
        );
        assert_eq!(
            targets[0].credential_label, "FIRST",
            "the first target wins"
        );
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

    /// A loopback OpenAI Codex backend serving `/models` (the
    /// `{"models":[{"slug":…}]}` shape), so the refresher's Codex arm can be
    /// exercised without the real ChatGPT backend or a subscription token. The
    /// Codex CLI fingerprint headers are asserted in `waygate-llm-discovery`'s own
    /// `codex_sends_cli_fingerprint_and_parses_slugs`; this fake echoes a
    /// swappable body (so a test can drive an empty-listing cycle) and records
    /// the `client_version` query it was asked with (the refresher's
    /// version-resolution contract).
    async fn serve_codex(
        body: Arc<Mutex<String>>,
        seen_version: Arc<Mutex<Option<String>>>,
    ) -> String {
        type CodexState = (Arc<Mutex<String>>, Arc<Mutex<Option<String>>>);
        let app = Router::new()
            .route(
                "/models",
                get(
                    |State((body, seen)): State<CodexState>,
                     axum::extract::Query(q): axum::extract::Query<
                        std::collections::HashMap<String, String>,
                    >| async move {
                        *seen.lock().unwrap() = q.get("client_version").cloned();
                        (
                            [(axum::http::header::CONTENT_TYPE, "application/json")],
                            body.lock().unwrap().clone(),
                        )
                    },
                ),
            )
            .with_state((body, seen_version));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn codex_body_with(slugs: &[&str]) -> String {
        let models: Vec<String> = slugs
            .iter()
            .map(|s| format!(r#"{{"slug":"{s}"}}"#))
            .collect();
        format!(r#"{{"models":[{}]}}"#, models.join(","))
    }

    /// A tracker whose source URLs are unroutable, so a test that should never
    /// consult it (OpenRouter surface, or a pinned Codex target) fails fast to
    /// the compiled default instead of reaching the real registries if a bug
    /// ever routes through it.
    fn test_tracker() -> CodexVersionTracker {
        CodexVersionTracker::new(
            "http://127.0.0.1:1/npm",
            "http://127.0.0.1:1/github",
            Duration::ZERO,
        )
    }

    /// Shared buffer a scoped `tracing` subscriber writes into, so a test can
    /// assert the operator-facing WARN text a refresh emits.
    #[derive(Clone, Default)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLogs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
        type Writer = CapturedLogs;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    impl CapturedLogs {
        fn contents(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
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
            client_version: None,
        };
        let tracker = test_tracker();

        // Cycle 1: both models discovered, priced, present.
        let n = refresh_target(&target, &http, &credentials, &pool, &tracker, None)
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
        refresh_target(&target, &http, &credentials, &pool, &tracker, None)
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
        let n3 = refresh_target(&target, &http, &credentials, &pool, &tracker, None)
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

    #[tokio::test]
    async fn refresh_target_codex_writes_responses_routing_with_chatgpt_flag() {
        let Ok(url) = std::env::var("AUDIT_DATABASE_URL") else {
            eprintln!("skipping codex refresh_target pg test: AUDIT_DATABASE_URL not set");
            return;
        };
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
        let slug = format!("gpt-{run}-codex");
        let seen_version: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let codex_body = Arc::new(Mutex::new(codex_body_with(&[&slug])));
        let base_url = serve_codex(codex_body.clone(), seen_version.clone()).await;

        // An OAuth credential for provider `openai` — parsed as an OAuth blob
        // because `OpenAi.is_oauth()` — with a future expiry so `bearer()` returns
        // the token without a network refresh, and an `account_id` for the
        // `chatgpt-account-id` header. This is what makes the surface resolve to
        // Codex (`for_provider("openai", is_oauth=true)`).
        let blob = r#"{"tokens":{"access_token":"oauth-token","refresh_token":"rt","account_id":"acct-codex"},"expires_at":"2100-01-01T00:00:00Z"}"#;
        let credentials = LlmCredentialStore::from_vars([(
            "LLM_CRED_OPENAI_CODEX".to_string(),
            blob.to_string(),
        )]);
        let http = raw_test_http_client();
        // The operator pin: it must bypass the release tracker and reach the
        // listing request verbatim (the test tracker is unroutable, so a
        // consult would fall back to the compiled default and fail the
        // pinned-version assertion below).
        let target = DiscoveryTarget {
            provider: "openai".into(),
            credential_label: "CODEX".into(),
            base_url: base_url.clone(),
            client_version: Some("0.133.0".into()),
        };

        let tracker = test_tracker();
        // The shared dispatch UA handle: the cycle must publish the version it
        // lists models as, so the /responses fingerprint matches the listing.
        let ua_handle: SharedCodexUaVersion = Arc::new(std::sync::RwLock::new("0.0.0".to_string()));
        let n = refresh_target(
            &target,
            &http,
            &credentials,
            &pool,
            &tracker,
            Some(&ua_handle),
        )
        .await
        .expect("codex cycle");
        assert_eq!(n, 1);
        assert_eq!(
            seen_version.lock().unwrap().as_deref(),
            Some("0.133.0"),
            "the pinned client_version reaches the listing request"
        );
        assert_eq!(
            ua_handle.read().unwrap().as_str(),
            "0.133.0",
            "the cycle publishes its client_version into the shared dispatch UA handle"
        );

        let alias = discovered_alias("openai", &slug);
        let row = waygate_storage::get_llm_model(&pool, &tenant, &alias)
            .await
            .unwrap()
            .expect("codex model upserted");
        // The contract this PR adds: a discovered Codex model routes chat via the
        // OpenAI Responses shape against the ChatGPT backend, flagged so dispatch
        // uses the Codex request fingerprint rather than a plain Bearer.
        assert_eq!(
            row.upstream_model, slug,
            "raw slug preserved as upstream_model"
        );
        assert_eq!(row.provider, "openai");
        assert_eq!(row.path, "responses");
        assert_eq!(row.upstream_api, "responses");
        assert!(
            row.openai_chatgpt,
            "Codex rows set the ChatGPT-backend auth flag"
        );
        assert_eq!(
            row.base_url, base_url,
            "the chat base is the Codex backend base"
        );
        assert!(
            row.input_cost_per_mtok.is_none(),
            "the Codex listing carries no pricing"
        );
        assert!(present_upstream(&pool, &tenant, &alias).await);

        // A RAW-EMPTY Codex listing — what a too-old client_version produces
        // (the backend returns empty, not an error, below its supported
        // range) — must not reconcile: the previously-discovered row stays
        // present (fail-open), and the WARN names the client_version actually
        // sent so the cause is diagnosable from the log line alone.
        *codex_body.lock().unwrap() = r#"{"models":[]}"#.to_string();
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(logs.clone())
            .finish();
        let n_empty = {
            use tracing::instrument::WithSubscriber;
            refresh_target(&target, &http, &credentials, &pool, &tracker, None)
                .with_subscriber(subscriber)
                .await
                .expect("codex empty cycle")
        };
        assert_eq!(n_empty, 0);
        assert!(
            present_upstream(&pool, &tenant, &alias).await,
            "a raw-empty codex listing (e.g. a too-old client_version) never soft-disables last-good rows"
        );
        let warn = logs.contents();
        assert!(
            warn.contains("0.133.0") && warn.contains("client_version"),
            "the empty-listing WARN names the exact client_version sent; got: {warn}"
        );

        // A payload that PARSES but carries only slugless entries
        // (`{"models":[{}]}`) is a garbled response, not an authoritative
        // "no visible models" answer: the listing is incomplete, reconcile is
        // skipped, and the previously discovered row keeps serving
        // (last-good) — a malformed listing must never mass-soft-disable.
        *codex_body.lock().unwrap() = r#"{"models":[{}]}"#.to_string();
        let n_malformed = refresh_target(&target, &http, &credentials, &pool, &tracker, None)
            .await
            .expect("codex malformed cycle");
        assert_eq!(n_malformed, 0);
        assert!(
            present_upstream(&pool, &tenant, &alias).await,
            "a parsed-but-malformed listing (slugless entries) is incomplete and never soft-disables last-good rows"
        );

        // A listing that is NON-empty upstream, well-formed, but has zero
        // picker-visible models is a complete answer, not a transient failure:
        // it must reconcile, soft-disabling the previously discovered row
        // (otherwise a model that turned hidden would stay routable forever).
        *codex_body.lock().unwrap() =
            format!(r#"{{"models":[{{"slug":"{slug}","visibility":"hide"}}]}}"#);
        let n_hidden = refresh_target(&target, &http, &credentials, &pool, &tracker, None)
            .await
            .expect("codex all-hidden cycle");
        assert_eq!(n_hidden, 0, "no picker-visible models discovered");
        assert!(
            !present_upstream(&pool, &tenant, &alias).await,
            "an all-hidden listing reconciles: the now-hidden model is soft-disabled, not left routable"
        );

        sqlx::query("DELETE FROM llm_models WHERE tenant_id = $1 AND alias = $2")
            .bind(&tenant)
            .bind(&alias)
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
            client_version: None,
        };
        let tracker = test_tracker();
        let chat_alias = discovered_alias("openrouter", &chat_id);
        let emb_alias = discovered_alias("openrouter", &emb_id);

        // Cycle 1: a chat model and an embeddings model discovered in one cycle.
        let n = refresh_target(&target, &http, &credentials, &pool, &tracker, None)
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
        refresh_target(&target, &http, &credentials, &pool, &tracker, None)
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
        refresh_target(&target, &http, &credentials, &pool, &tracker, None)
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
        refresh_target(&target, &http, &credentials, &pool, &tracker, None)
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
