//! Read/write access for the inference-plane model
//! catalog (`migrations/0047_llm_models.sql`).
//!
//! This is the storage layer only — the *access* counterpart to the
//! migration, mirroring [`crate::routing`]. It is consumed by:
//!
//! - the boot-time seeder that upserts the env-configured
//!   models ([`upsert_llm_model`]) and the `searchTools` surface that
//!   lists them ([`list_llm_models`]);
//! - the Cedar `Model` resource, which reads [`LlmModelRow::risk`];
//! - token/cost budgets, which read the (optional) costing
//!   columns on the projected row.
//!
//! Functions are generic over `sqlx::Executor` so a caller can run
//! them on a pool or inside a transaction (the boot seeder upserts a
//! batch in one transaction).

use rust_decimal::Decimal;
use time::OffsetDateTime;

/// One catalog row, projected with the discovery + routing columns plus the
/// optional per-million-token costing (usage-cost computation reads it to
/// weight usage costs). A cost rate is `None` when the operator has not configured
/// pricing for the model; cost-based budgets then skip while token budgets
/// still apply (design §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmModelRow {
    pub tenant_id: String,
    pub alias: String,
    pub provider: String,
    pub credential_label: String,
    pub upstream_model: String,
    pub base_url: String,
    pub path: String,
    pub upstream_api: String,
    /// `true` selects the Codex (ChatGPT-backend) auth fingerprint at dispatch —
    /// see `migrations/0055_llm_models_codex_auth.sql`. Maps to
    /// `ResolvedRoute.openai_chatgpt`.
    pub openai_chatgpt: bool,
    pub risk: String,
    pub requires_approval: bool,
    pub description: Option<String>,
    /// Per-MILLION-token rates in `currency`; `None` = no pricing configured.
    pub input_cost_per_mtok: Option<Decimal>,
    pub output_cost_per_mtok: Option<Decimal>,
    pub cached_read_cost_per_mtok: Option<Decimal>,
    pub cache_write_cost_per_mtok: Option<Decimal>,
    pub currency: String,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for LlmModelRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;
        Ok(Self {
            tenant_id: row.try_get("tenant_id")?,
            alias: row.try_get("alias")?,
            provider: row.try_get("provider")?,
            credential_label: row.try_get("credential_label")?,
            upstream_model: row.try_get("upstream_model")?,
            base_url: row.try_get("base_url")?,
            path: row.try_get("path")?,
            upstream_api: row.try_get("upstream_api")?,
            openai_chatgpt: row.try_get("openai_chatgpt")?,
            risk: row.try_get("risk")?,
            requires_approval: row.try_get("requires_approval")?,
            description: row.try_get("description")?,
            input_cost_per_mtok: row.try_get("input_cost_per_mtok")?,
            output_cost_per_mtok: row.try_get("output_cost_per_mtok")?,
            cached_read_cost_per_mtok: row.try_get("cached_read_cost_per_mtok")?,
            cache_write_cost_per_mtok: row.try_get("cache_write_cost_per_mtok")?,
            currency: row.try_get("currency")?,
            enabled: row.try_get("enabled")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

/// Upsert payload for one model. The boot seeder builds one of these
/// per configured `ModelDef`; costing is not part of the env config,
/// so it is intentionally absent here and is preserved on conflict
/// (an operator-set cost is not clobbered by a redeploy).
#[derive(Debug, Clone)]
pub struct LlmModelUpsert {
    pub tenant_id: String,
    pub alias: String,
    pub provider: String,
    pub credential_label: String,
    pub upstream_model: String,
    pub base_url: String,
    pub path: String,
    pub upstream_api: String,
    /// `true` ⇒ Codex (ChatGPT-backend) auth (a `surface: codex` pin).
    pub openai_chatgpt: bool,
    pub risk: String,
    pub requires_approval: bool,
    pub description: Option<String>,
    pub enabled: bool,
}

/// List a tenant's **effective-live** models, ordered by alias for
/// stable discovery output. A model is effective-live when it is
/// `enabled` AND either operator-pinned (`source = 'config'`) or still
/// present upstream (`present_upstream`). This hides a discovered model
/// the provider has dropped (the refresher soft-disables it by clearing
/// `present_upstream`) while never hiding a pin, whose `present_upstream`
/// is irrelevant. See `migrations/0054_llm_models_discovery.sql`.
pub async fn list_llm_models<'e, E>(
    executor: E,
    tenant_id: &str,
) -> Result<Vec<LlmModelRow>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query_as::<_, LlmModelRow>(
        r#"
        SELECT tenant_id, alias, provider, credential_label, upstream_model,
               base_url, path, upstream_api, openai_chatgpt, risk, requires_approval,
               description, input_cost_per_mtok, output_cost_per_mtok,
               cached_read_cost_per_mtok, cache_write_cost_per_mtok, currency,
               enabled, created_at, updated_at
          FROM llm_models
         WHERE tenant_id = $1 AND enabled AND (source = 'config' OR present_upstream)
         ORDER BY alias
        "#,
    )
    .bind(tenant_id)
    .fetch_all(executor)
    .await
}

/// List a tenant's **effective-live discovered** models — `source =
/// 'discovered'`, `enabled`, and still `present_upstream`. This is the layer the
/// DB-backed resolver overlays on the env pins: models the discovery refresher
/// found upstream and wrote to the catalog, excluding ones it has soft-disabled
/// (dropped upstream) and excluding config pins (those route from env with full
/// failover fidelity, so the resolver sources them from the env layer, not here).
/// Ordered by alias for a stable rebuild.
pub async fn list_discovered_llm_models<'e, E>(
    executor: E,
    tenant_id: &str,
) -> Result<Vec<LlmModelRow>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query_as::<_, LlmModelRow>(
        r#"
        SELECT tenant_id, alias, provider, credential_label, upstream_model,
               base_url, path, upstream_api, openai_chatgpt, risk, requires_approval,
               description, input_cost_per_mtok, output_cost_per_mtok,
               cached_read_cost_per_mtok, cache_write_cost_per_mtok, currency,
               enabled, created_at, updated_at
          FROM llm_models
         WHERE tenant_id = $1 AND enabled AND present_upstream AND source = 'discovered'
         ORDER BY alias
        "#,
    )
    .bind(tenant_id)
    .fetch_all(executor)
    .await
}

/// Fetch one model by `(tenant, alias)`. Returns `None` when there is
/// no such row (regardless of `enabled` — callers that only want
/// live models filter on [`LlmModelRow::enabled`]).
pub async fn get_llm_model<'e, E>(
    executor: E,
    tenant_id: &str,
    alias: &str,
) -> Result<Option<LlmModelRow>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query_as::<_, LlmModelRow>(
        r#"
        SELECT tenant_id, alias, provider, credential_label, upstream_model,
               base_url, path, upstream_api, openai_chatgpt, risk, requires_approval,
               description, input_cost_per_mtok, output_cost_per_mtok,
               cached_read_cost_per_mtok, cache_write_cost_per_mtok, currency,
               enabled, created_at, updated_at
          FROM llm_models
         WHERE tenant_id = $1 AND alias = $2
        "#,
    )
    .bind(tenant_id)
    .bind(alias)
    .fetch_optional(executor)
    .await
}

/// Fetch the catalog row that prices `served` for `provider` — the model the
/// provider actually ran. Cost attributes to `model_served`, not the requested
/// alias (design §4.2): with OpenRouter auto-routing / failover the billed
/// model can differ from the alias, so the catalog row representing the served
/// model carries the authoritative rates.
///
/// Scoped by **`(tenant, provider, upstream_model)`**: the same `upstream_model`
/// string can exist under two providers with different rates (e.g. a model
/// name served by both OpenAI directly and via OpenRouter), so the served
/// lookup must match the call's resolved provider to avoid borrowing another
/// provider's pricing. Returns `None` when no configured model routes to
/// `served` on that provider (then cost is `Unknown`). `ORDER BY alias LIMIT 1`
/// is a deterministic tiebreak if several aliases share one
/// `(provider, upstream_model)` — their costing prices the same model and
/// should agree.
pub async fn get_llm_model_by_served<'e, E>(
    executor: E,
    tenant_id: &str,
    provider: &str,
    served: &str,
) -> Result<Option<LlmModelRow>, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query_as::<_, LlmModelRow>(
        r#"
        SELECT tenant_id, alias, provider, credential_label, upstream_model,
               base_url, path, upstream_api, openai_chatgpt, risk, requires_approval,
               description, input_cost_per_mtok, output_cost_per_mtok,
               cached_read_cost_per_mtok, cache_write_cost_per_mtok, currency,
               enabled, created_at, updated_at
          FROM llm_models
         WHERE tenant_id = $1 AND provider = $2 AND upstream_model = $3
         ORDER BY alias
         LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(provider)
    .bind(served)
    .fetch_optional(executor)
    .await
}

/// Admin-side read trait over the model catalog. Kept as a trait so the
/// dashboard's `/llm_models` page can be unit-tested against an in-memory
/// fake without a Postgres pool, mirroring [`crate::RoutingStore`]. The
/// Postgres impl is [`PgLlmModelCatalog`].
#[async_trait::async_trait]
pub trait LlmModelCatalog: Send + Sync {
    /// List a tenant's enabled models, ordered by alias (matches
    /// [`list_llm_models`]).
    async fn list_models(&self, tenant_id: &str) -> Result<Vec<LlmModelRow>, sqlx::Error>;
}

/// Postgres-backed [`LlmModelCatalog`]. Thin wrapper around
/// [`list_llm_models`] so production code and tests share the same SQL.
pub struct PgLlmModelCatalog {
    pool: sqlx::PgPool,
}

impl PgLlmModelCatalog {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl LlmModelCatalog for PgLlmModelCatalog {
    async fn list_models(&self, tenant_id: &str) -> Result<Vec<LlmModelRow>, sqlx::Error> {
        list_llm_models(&self.pool, tenant_id).await
    }
}

/// Shared handle to the model catalog, mirroring `SharedCatalogStore`.
pub type SharedLlmModelCatalog = std::sync::Arc<dyn LlmModelCatalog>;

/// Insert or update one **operator-pinned** model (`source = 'config'`),
/// keyed on `(tenant_id, alias)`.
///
/// A pin is authoritative over discovery: the conflict path stamps
/// `source = 'config'` and `present_upstream = TRUE`, so if an alias was
/// previously minted by the discovery refresher (`source = 'discovered'`)
/// and the operator later pins it, the row is reclaimed as a pin —
/// reconciliation's soft-disable can never again touch it. This is the
/// counterpart to [`upsert_discovered_llm_model`]'s provenance gate,
/// which refuses to overwrite a `config` row.
///
/// Costing is preserved across a redeploy — an operator-configured cost
/// is never clobbered — with ONE exception: when this pin *reclaims* a
/// previously-`discovered` row AND re-points it to a different
/// `(provider, upstream_model)`, the discovery-filled rates priced a
/// *different* model and would mis-cost usage on the new route, so they
/// (and the currency label) are dropped. The operator can then price the
/// pinned route; the discovery refresher cannot (its provenance gate
/// skips a `config` row). A same-route reclaim, and any redeploy of an
/// already-`config` pin, keep the existing costing untouched.
pub async fn upsert_llm_model<'e, E>(executor: E, model: &LlmModelUpsert) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query(
        r#"
        INSERT INTO llm_models
            (tenant_id, alias, provider, credential_label, upstream_model,
             base_url, path, upstream_api, risk, requires_approval,
             description, enabled, openai_chatgpt, source, present_upstream, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                'config', TRUE, now())
        ON CONFLICT (tenant_id, alias) DO UPDATE SET
            provider          = EXCLUDED.provider,
            credential_label  = EXCLUDED.credential_label,
            upstream_model    = EXCLUDED.upstream_model,
            base_url          = EXCLUDED.base_url,
            path              = EXCLUDED.path,
            upstream_api    = EXCLUDED.upstream_api,
            openai_chatgpt    = EXCLUDED.openai_chatgpt,
            risk              = EXCLUDED.risk,
            requires_approval = EXCLUDED.requires_approval,
            description       = EXCLUDED.description,
            enabled           = EXCLUDED.enabled,
            -- Drop discovery-filled costing ONLY when reclaiming a discovered
            -- row that this pin re-points to a different provider/upstream (the
            -- rates priced a different model). All `llm_models.*` here are the
            -- pre-update values, so `source` is the row's OLD provenance. A
            -- same-route reclaim, and any redeploy of an already-config pin
            -- (source <> 'discovered'), keep the operator's costing untouched.
            input_cost_per_mtok = CASE
                WHEN llm_models.source = 'discovered'
                 AND (llm_models.provider       IS DISTINCT FROM EXCLUDED.provider
                   OR llm_models.upstream_model IS DISTINCT FROM EXCLUDED.upstream_model)
                THEN NULL ELSE llm_models.input_cost_per_mtok END,
            output_cost_per_mtok = CASE
                WHEN llm_models.source = 'discovered'
                 AND (llm_models.provider       IS DISTINCT FROM EXCLUDED.provider
                   OR llm_models.upstream_model IS DISTINCT FROM EXCLUDED.upstream_model)
                THEN NULL ELSE llm_models.output_cost_per_mtok END,
            cached_read_cost_per_mtok = CASE
                WHEN llm_models.source = 'discovered'
                 AND (llm_models.provider       IS DISTINCT FROM EXCLUDED.provider
                   OR llm_models.upstream_model IS DISTINCT FROM EXCLUDED.upstream_model)
                THEN NULL ELSE llm_models.cached_read_cost_per_mtok END,
            cache_write_cost_per_mtok = CASE
                WHEN llm_models.source = 'discovered'
                 AND (llm_models.provider       IS DISTINCT FROM EXCLUDED.provider
                   OR llm_models.upstream_model IS DISTINCT FROM EXCLUDED.upstream_model)
                THEN NULL ELSE llm_models.cache_write_cost_per_mtok END,
            currency = CASE
                WHEN llm_models.source = 'discovered'
                 AND (llm_models.provider       IS DISTINCT FROM EXCLUDED.provider
                   OR llm_models.upstream_model IS DISTINCT FROM EXCLUDED.upstream_model)
                THEN 'USD' ELSE llm_models.currency END,
            source            = 'config',
            present_upstream  = TRUE,
            updated_at        = now()
        "#,
    )
    .bind(&model.tenant_id)
    .bind(&model.alias)
    .bind(&model.provider)
    .bind(&model.credential_label)
    .bind(&model.upstream_model)
    .bind(&model.base_url)
    .bind(&model.path)
    .bind(&model.upstream_api)
    .bind(&model.risk)
    .bind(model.requires_approval)
    .bind(&model.description)
    .bind(model.enabled)
    .bind(model.openai_chatgpt)
    .execute(executor)
    .await
    .map(|_| ())
}

/// A discovered-model upsert payload (the discovery refresher's write
/// shape). Routing fields mirror [`LlmModelUpsert`]; costing is optional
/// and, when present, only *fills* a NULL catalog rate — it never
/// clobbers an operator-set price (see [`upsert_discovered_llm_model`]).
/// `risk`/`requires_approval`/`description`/`enabled` are intentionally
/// absent: a discovered row takes the schema defaults on first insert
/// (risk `low` — the catalog default) and the refresher never overwrites
/// those operator-governed fields on a later cycle.
#[derive(Debug, Clone)]
pub struct LlmDiscoveredModelUpsert {
    pub tenant_id: String,
    pub alias: String,
    pub provider: String,
    pub credential_label: String,
    pub upstream_model: String,
    pub base_url: String,
    pub path: String,
    pub upstream_api: String,
    /// Codex (ChatGPT-backend) auth variant. `true` only for OpenAI Codex
    /// discovery (the OpenAI *Responses* shape spoken against the ChatGPT
    /// backend); `false` for every other discovered model. Routes to
    /// [`crate::llm_catalog::LlmModelRow::openai_chatgpt`] and on into
    /// `ResolvedRoute.openai_chatgpt`, so dispatch selects the Codex request
    /// fingerprint (`ProviderAuth::OpenAiChatGpt`) instead of a plain Bearer.
    /// It is a routing fact of the adapter, not an operator-governed field, so
    /// (unlike `risk`/`enabled`) the refresher *does* keep it current on every
    /// cycle.
    pub openai_chatgpt: bool,
    /// Per-MILLION-token rates from the provider's model listing (only
    /// OpenRouter publishes these today). `None` ⇒ unknown; filled into a
    /// NULL catalog rate, never over an operator value. `Some` currency
    /// defaults to USD when omitted.
    pub input_cost_per_mtok: Option<Decimal>,
    pub output_cost_per_mtok: Option<Decimal>,
    pub cached_read_cost_per_mtok: Option<Decimal>,
    pub cache_write_cost_per_mtok: Option<Decimal>,
    pub currency: Option<String>,
}

/// Insert or update one **discovered** model (`source = 'discovered'`),
/// keyed on `(tenant_id, alias)`, marking it present upstream. This is
/// the discovery refresher's write path.
///
/// Two invariants protect operator intent:
///
///   - **Provenance gate.** The conflict UPDATE is guarded by
///     `WHERE llm_models.source = 'discovered'`, so an existing
///     operator-pinned (`config`) row of the same alias is left
///     untouched — discovery can never clobber a pin (the row simply
///     stays a pin, which already serves the model). A brand-new alias
///     still inserts as `discovered`.
///   - **Costing fill, never clobber, never mislabel.** A NULL cost
///     column is filled from the provider listing (`COALESCE`), but an
///     operator-set rate is preserved (design decision 3). Fills are
///     currency-consistent: a discovered payload's rates are adopted only
///     when the row has no pricing yet (it then takes the payload's
///     currency) or the payload's currency matches the row's; a
///     cross-currency payload at an already-priced row is skipped, so a
///     rate is never stored under the wrong unit. `risk`, `enabled`,
///     `requires_approval`, and `description` are not in the SET list at
///     all — the refresher never moves them after first insert.
pub async fn upsert_discovered_llm_model<'e, E>(
    executor: E,
    model: &LlmDiscoveredModelUpsert,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query(
        r#"
        INSERT INTO llm_models
            (tenant_id, alias, provider, credential_label, upstream_model,
             base_url, path, upstream_api, openai_chatgpt,
             input_cost_per_mtok, output_cost_per_mtok,
             cached_read_cost_per_mtok, cache_write_cost_per_mtok, currency,
             source, present_upstream, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                COALESCE($14, 'USD'), 'discovered', TRUE, now())
        ON CONFLICT (tenant_id, alias) DO UPDATE SET
            provider          = EXCLUDED.provider,
            credential_label  = EXCLUDED.credential_label,
            upstream_model    = EXCLUDED.upstream_model,
            base_url          = EXCLUDED.base_url,
            path              = EXCLUDED.path,
            upstream_api    = EXCLUDED.upstream_api,
            openai_chatgpt    = EXCLUDED.openai_chatgpt,
            -- Costing fills are currency-consistent. A discovered payload is in
            -- ONE currency, so a NULL rate is filled only when the fill cannot
            -- mislabel it: either the row has NO pricing yet (it then adopts the
            -- payload's currency, below) OR the payload's currency already
            -- matches the row's. A cross-currency payload arriving at an
            -- already-priced row is skipped wholesale — never COALESCE'd in,
            -- which would store the new rate under the row's old unit. COALESCE
            -- still preserves an existing (operator- or earlier-discovery-set)
            -- rate when a fill does apply. `cost_compatible` (repeated per
            -- column because SQL has no SET-local binding) is:
            --   all rates NULL  OR  EXCLUDED.currency = llm_models.currency
            input_cost_per_mtok = CASE
                WHEN (llm_models.input_cost_per_mtok       IS NULL
                  AND llm_models.output_cost_per_mtok      IS NULL
                  AND llm_models.cached_read_cost_per_mtok IS NULL
                  AND llm_models.cache_write_cost_per_mtok IS NULL)
                   OR EXCLUDED.currency = llm_models.currency
                THEN COALESCE(llm_models.input_cost_per_mtok, EXCLUDED.input_cost_per_mtok)
                ELSE llm_models.input_cost_per_mtok
            END,
            output_cost_per_mtok = CASE
                WHEN (llm_models.input_cost_per_mtok       IS NULL
                  AND llm_models.output_cost_per_mtok      IS NULL
                  AND llm_models.cached_read_cost_per_mtok IS NULL
                  AND llm_models.cache_write_cost_per_mtok IS NULL)
                   OR EXCLUDED.currency = llm_models.currency
                THEN COALESCE(llm_models.output_cost_per_mtok, EXCLUDED.output_cost_per_mtok)
                ELSE llm_models.output_cost_per_mtok
            END,
            cached_read_cost_per_mtok = CASE
                WHEN (llm_models.input_cost_per_mtok       IS NULL
                  AND llm_models.output_cost_per_mtok      IS NULL
                  AND llm_models.cached_read_cost_per_mtok IS NULL
                  AND llm_models.cache_write_cost_per_mtok IS NULL)
                   OR EXCLUDED.currency = llm_models.currency
                THEN COALESCE(llm_models.cached_read_cost_per_mtok, EXCLUDED.cached_read_cost_per_mtok)
                ELSE llm_models.cached_read_cost_per_mtok
            END,
            cache_write_cost_per_mtok = CASE
                WHEN (llm_models.input_cost_per_mtok       IS NULL
                  AND llm_models.output_cost_per_mtok      IS NULL
                  AND llm_models.cached_read_cost_per_mtok IS NULL
                  AND llm_models.cache_write_cost_per_mtok IS NULL)
                   OR EXCLUDED.currency = llm_models.currency
                THEN COALESCE(llm_models.cache_write_cost_per_mtok, EXCLUDED.cache_write_cost_per_mtok)
                ELSE llm_models.cache_write_cost_per_mtok
            END,
            -- Currency travels with the rates. `currency` is NOT NULL (defaults
            -- 'USD'), so a plain COALESCE can't detect "unset": adopt the
            -- payload's currency only on the cycle the row first acquires pricing
            -- (all rates NULL). Once any rate exists it is locked, and the gate
            -- above guarantees later fills are same-currency, so the row's rates
            -- are always denominated in this one unit.
            currency = CASE
                WHEN llm_models.input_cost_per_mtok       IS NULL
                 AND llm_models.output_cost_per_mtok      IS NULL
                 AND llm_models.cached_read_cost_per_mtok IS NULL
                 AND llm_models.cache_write_cost_per_mtok IS NULL
                THEN EXCLUDED.currency
                ELSE llm_models.currency
            END,
            present_upstream  = TRUE,
            updated_at        = now()
          WHERE llm_models.source = 'discovered'
        "#,
    )
    .bind(&model.tenant_id)
    .bind(&model.alias)
    .bind(&model.provider)
    .bind(&model.credential_label)
    .bind(&model.upstream_model)
    .bind(&model.base_url)
    .bind(&model.path)
    .bind(&model.upstream_api)
    .bind(model.openai_chatgpt)
    .bind(model.input_cost_per_mtok)
    .bind(model.output_cost_per_mtok)
    .bind(model.cached_read_cost_per_mtok)
    .bind(model.cache_write_cost_per_mtok)
    .bind(&model.currency)
    .execute(executor)
    .await
    .map(|_| ())
}

/// Soft-disable the `discovered` models for `(tenant, provider)` that a
/// fresh discovery cycle did **not** return: set `present_upstream =
/// FALSE` on every currently-present discovered row whose alias is not in
/// `seen_aliases`. This is the reconciliation half of discovery's
/// soft-disable (design decision 2): a dropped model is hidden from the
/// effective-live listing but retained (costing/history, re-enable) — it
/// is never deleted, and `enabled` (operator intent) is never touched.
///
/// Scoped to one `provider` so reconciling one provider's listing never
/// disables another's, and only ever to `source = 'discovered'` rows so a
/// pin is never affected. The caller MUST invoke this only after a
/// *successful* discovery for `provider` (fail-open: a failed or empty-by-
/// error cycle must not mass-disable a provider's catalog).
pub async fn mark_discovered_absent<'e, E>(
    executor: E,
    tenant_id: &str,
    provider: &str,
    seen_aliases: &[String],
) -> Result<u64, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let result = sqlx::query(
        r#"
        UPDATE llm_models
           SET present_upstream = FALSE, updated_at = now()
         WHERE tenant_id = $1
           AND provider = $2
           AND source = 'discovered'
           AND present_upstream
           AND alias <> ALL($3)
        "#,
    )
    .bind(tenant_id)
    .bind(provider)
    .bind(seen_aliases)
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}
