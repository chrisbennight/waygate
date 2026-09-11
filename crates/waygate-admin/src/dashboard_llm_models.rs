//! LLM models page — `/llm_models`.
//!
//! Read-only operator view of the inference-plane model catalog
//! (`waygate_storage::llm_catalog`). Lists the models
//! configured for the principal's tenant — alias, provider, the upstream
//! model the gateway dispatches to, the credential label that authenticates
//! the call, the native request surface, the Cedar risk tier, whether the
//! model is enabled and whether an invocation requires approval, plus the
//! per-million-token input / output pricing (when the operator configured
//! it) and the free-text description.
//!
//! ## Tenant scoping
//!
//! Reads use `principal.tenant`. The store's `list_models` is the same
//! `list_llm_models` query the `searchTools` discovery surface and the boot
//! seeder use — enabled rows only, ordered by alias.
//!
//! ## Admin gate
//!
//! Mirrors the catalog page's `principal_has_dashboard_admin`. A dashboard
//! session without `mcp:admin` (or a peer-asserted principal) sees the
//! insufficient-scope card; the store fetch is skipped entirely so no model
//! data — including the per-tenant aliases, credential labels, and pricing —
//! enters the rendered HTML.

use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use waygate_oidc::{AuthMethod, Principal, Scope};
use waygate_storage::{LlmModelRow, SharedLlmModelCatalog};

use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;

#[derive(Template)]
#[template(path = "llm_models.html")]
struct LlmModelsPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when the model catalog store is unwired (dev mode /
    /// no DB). Template renders the "feature disabled" card.
    store_configured: bool,
    /// `true` when the dashboard principal lacks `mcp:admin`
    /// (or is a peer assertion). Template renders the
    /// insufficient-scope card and SKIPS the store fetch.
    insufficient_scope: bool,
    /// Models visible to the principal's tenant. Ordered server-side
    /// by alias; no client-side sort.
    models: Vec<ModelRow>,
    /// `true` when the models fetch failed. Template renders a
    /// section error card instead of the empty "no models" state.
    models_load_error: bool,
}

/// One model row for the read-only table. A display projection of
/// [`LlmModelRow`] — only the operator-facing columns, with the optional
/// per-million-token costs pre-formatted to strings (em-dash for an unset
/// rate is handled in the template).
struct ModelRow {
    alias: String,
    provider: String,
    upstream_model: String,
    credential_label: String,
    upstream_api: String,
    /// `true` when this is an embeddings model (`upstream_api = embeddings`).
    /// Drives the "Kind" badge so embeddings rows are visually distinct from
    /// chat-family rows; derived from `upstream_api` (the operation source of truth).
    is_embeddings: bool,
    /// Images use a distinct operation badge, independent of chat discovery.
    is_images: bool,
    risk: String,
    enabled: bool,
    requires_approval: bool,
    /// Per-MILLION-token input rate, pre-formatted; `None` ⇒ no pricing.
    input_cost: Option<String>,
    /// Per-MILLION-token output rate, pre-formatted; `None` ⇒ no pricing.
    output_cost: Option<String>,
    description: Option<String>,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new().route("/llm_models", get(llm_models_page))
}

async fn llm_models_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);

    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    let insufficient_scope = !principal_has_dashboard_admin(user_principal);
    let store_configured = state.llm.llm_models.enabled();

    let load = if insufficient_scope {
        // Skip the store read entirely — no model data leaks into the
        // rendered HTML.
        LoadResult::default()
    } else {
        match state.llm.llm_models.get() {
            Some(store) => load_llm_models(store, &read_tenant).await,
            None => LoadResult::default(),
        }
    };

    let page = LlmModelsPage {
        chrome: PageChrome::build(
            &state,
            "LLM Models",
            "/llm_models",
            &headers,
            user_display_str,
            tenant_ctx,
            String::new(),
        ),
        store_configured,
        insufficient_scope,
        models: load.models,
        models_load_error: load.models_load_error,
    };
    render(&page)
}

/// Authorization gate for the LLM models dashboard page. Same shape as
/// `dashboard_catalog::principal_has_dashboard_admin`.
fn principal_has_dashboard_admin(p: Option<&Principal>) -> bool {
    match p {
        None => false,
        Some(p) if p.auth_method == AuthMethod::PeerAssertion => false,
        Some(p) => p.has_scope(Scope::McpAdmin.as_str()),
    }
}

#[derive(Default)]
struct LoadResult {
    models: Vec<ModelRow>,
    /// `true` when the store fetch failed — distinguish "store failed"
    /// from "genuinely empty" so the template renders an error card
    /// rather than the empty state (the catalog page's per-section
    /// load-error pattern).
    models_load_error: bool,
}

async fn load_llm_models(store: &SharedLlmModelCatalog, tenant: &str) -> LoadResult {
    match store.list_models(tenant).await {
        Ok(rows) => LoadResult {
            models: rows.into_iter().map(model_row).collect(),
            models_load_error: false,
        },
        Err(e) => {
            tracing::error!(
                error = %e,
                tenant = %tenant,
                "llm models page: list_models failed",
            );
            LoadResult {
                models: Vec::new(),
                models_load_error: true,
            }
        }
    }
}

fn model_row(m: LlmModelRow) -> ModelRow {
    let is_embeddings = m.upstream_api.eq_ignore_ascii_case("embeddings");
    let is_images = m.upstream_api.eq_ignore_ascii_case("images");
    ModelRow {
        alias: m.alias,
        provider: m.provider,
        upstream_model: m.upstream_model,
        credential_label: m.credential_label,
        upstream_api: m.upstream_api,
        is_embeddings,
        is_images,
        risk: m.risk,
        enabled: m.enabled,
        requires_approval: m.requires_approval,
        input_cost: m.input_cost_per_mtok.map(|c| c.to_string()),
        output_cost: m.output_cost_per_mtok.map(|c| c.to_string()),
        description: m.description,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal_with(scopes: Vec<&str>, method: AuthMethod) -> Principal {
        Principal {
            sub: "tester".into(),
            email: None,
            groups: vec![],
            issuer: "local-test".into(),
            scopes: scopes.into_iter().map(String::from).collect(),
            tenant: waygate_core::TenantId::default(),
            auth_method: method,
            raw_token: None,
            roles: vec![],
            scim: None,
            enrichment_blocked: None,
            api_key_profile_restrictions: None,
        }
    }

    #[test]
    fn llm_models_admin_gate_allows_oauth_admin() {
        let p = principal_with(vec!["mcp:read", "mcp:admin"], AuthMethod::Oauth);
        assert!(principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn llm_models_admin_gate_blocks_oauth_without_admin_scope() {
        let p = principal_with(
            vec!["openid", "profile", "email", "groups", "mcp:read"],
            AuthMethod::Oauth,
        );
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn llm_models_admin_gate_blocks_peer_assertion_even_with_admin_scope() {
        let p = principal_with(vec!["mcp:admin"], AuthMethod::PeerAssertion);
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn llm_models_admin_gate_blocks_missing_principal() {
        assert!(!principal_has_dashboard_admin(None));
    }

    /// Fake model catalog returning a seeded row, so `load_llm_models`
    /// can be exercised without a Postgres pool.
    struct ModelFake {
        models: Vec<LlmModelRow>,
    }

    #[async_trait::async_trait]
    impl waygate_storage::LlmModelCatalog for ModelFake {
        async fn list_models(&self, _tenant_id: &str) -> Result<Vec<LlmModelRow>, sqlx::Error> {
            Ok(self.models.clone())
        }
    }

    fn seeded_row() -> LlmModelRow {
        use time::OffsetDateTime;
        LlmModelRow {
            tenant_id: "default".into(),
            alias: "claude-fast".into(),
            provider: "anthropic".into(),
            credential_label: "anthropic-prod".into(),
            upstream_model: "claude-3-5-haiku".into(),
            base_url: "https://api.anthropic.com".into(),
            path: "/v1/messages".into(),
            upstream_api: "messages".into(),
            openai_chatgpt: false,
            risk: "low".into(),
            requires_approval: false,
            description: Some("fast tier".into()),
            input_cost_per_mtok: None,
            output_cost_per_mtok: None,
            cached_read_cost_per_mtok: None,
            cache_write_cost_per_mtok: None,
            currency: "USD".into(),
            enabled: true,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[tokio::test]
    async fn load_llm_models_maps_seeded_row() {
        let store: SharedLlmModelCatalog = Arc::new(ModelFake {
            models: vec![seeded_row()],
        });

        let load = load_llm_models(&store, "default").await;

        assert!(!load.models_load_error, "fake never errors");
        assert_eq!(load.models.len(), 1);
        let row = &load.models[0];
        assert_eq!(row.alias, "claude-fast");
        assert_eq!(row.provider, "anthropic");
        assert!(row.enabled, "the enabled flag must survive into the row");
        assert!(
            !row.is_embeddings,
            "a `messages` (chat-family) row is not embeddings"
        );
    }

    #[test]
    fn model_row_flags_embeddings_by_upstream_api() {
        assert!(!model_row(seeded_row()).is_embeddings);
        let mut emb = seeded_row();
        emb.upstream_api = "embeddings".into();
        assert!(
            model_row(emb).is_embeddings,
            "an embeddings upstream_api flags the Kind badge"
        );
    }
}
