//! LLM credentials page — `/llm_credentials`.
//!
//! Read-only operator view of the inference-plane credential pool
//! (`waygate_llm_credentials::LlmCredentialStore`). Lists every
//! configured credential — one row per `(provider, label)` — with its current
//! pool [`Health`](waygate_llm_credentials::Health).
//!
//! ## Not tenant-scoped
//!
//! Unlike the `/llm_models` page, this panel is **NOT** tenant-scoped.
//! Credentials are a process-global, env-injected deployment resource (the
//! `LLM_CRED_<PROVIDER>_<LABEL>` variables Infisical injects at boot — one pool
//! serves every tenant), so the store has no tenant dimension. The panel shows
//! the deployment's credential pool, gated by the same `mcp:admin` dashboard
//! gate as the other admin pages. It exposes only the provider, the
//! operator-chosen pool label, and the cached health — NO secret material (no
//! access tokens, no refresh tokens, no API keys).
//!
//! ## Admin gate
//!
//! Mirrors the LLM-models page's `principal_has_dashboard_admin`. A dashboard
//! session without `mcp:admin` (or a peer-asserted principal) sees the
//! insufficient-scope card; the snapshot is skipped entirely so no credential
//! data — not even the provider / label pairs — enters the rendered HTML. The
//! snapshot is also skipped when the store is unwired (no LLM path /
//! dispatcher), rendering the "not configured" card instead.

use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use waygate_llm_credentials::{Health, LlmCredentialStore};
use waygate_oidc::{AuthMethod, Principal, Scope};

use crate::chrome::PageChrome;
use crate::dashboard::{render, user_display};
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;

#[derive(Template)]
#[template(path = "llm_credentials.html")]
struct LlmCredentialsPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// `true` when the credential store is unwired (dev mode / no LLM path /
    /// dispatcher). Template renders the "feature disabled" card.
    store_configured: bool,
    /// `true` when the dashboard principal lacks `mcp:admin`
    /// (or is a peer assertion). Template renders the
    /// insufficient-scope card and SKIPS the snapshot.
    insufficient_scope: bool,
    /// One row per configured `(provider, label)`. Ordered server-side by
    /// `(provider, label)` (the store sorts the snapshot); no client-side sort.
    credentials: Vec<CredRow>,
}

/// One credential row for the read-only table. A display projection of
/// [`CredentialStatus`](waygate_llm_credentials::CredentialStatus) — the
/// provider as its canonical identifier, the operator-chosen pool label, and
/// the health pre-mapped to its display string. No secret material.
struct CredRow {
    provider: String,
    label: String,
    health: &'static str,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new().route("/llm_credentials", get(llm_credentials_page))
}

async fn llm_credentials_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    headers: HeaderMap,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);

    let insufficient_scope = !principal_has_dashboard_admin(user_principal);
    let store_configured = state.llm.llm_credentials.enabled();

    // Not tenant-scoped: the credential pool is process-global, so there is no
    // tenant filter on the snapshot. Skip the read when the gate fails or the
    // store is unwired so no credential data leaks into the rendered HTML.
    let credentials = if insufficient_scope {
        Vec::new()
    } else {
        match state.llm.llm_credentials.get() {
            Some(store) => load_credentials(store).await,
            None => Vec::new(),
        }
    };

    let page = LlmCredentialsPage {
        chrome: PageChrome::build(
            &state,
            "LLM Credentials",
            "/llm_credentials",
            &headers,
            user_display_str,
            tenant_ctx,
            String::new(),
        ),
        store_configured,
        insufficient_scope,
        credentials,
    };
    render(&page)
}

/// Authorization gate for the LLM credentials dashboard page. Same shape as
/// `dashboard_llm_models::principal_has_dashboard_admin`.
fn principal_has_dashboard_admin(p: Option<&Principal>) -> bool {
    match p {
        None => false,
        Some(p) if p.auth_method == AuthMethod::PeerAssertion => false,
        Some(p) => p.has_scope(Scope::McpAdmin.as_str()),
    }
}

/// Map the store's snapshot into display rows. `status_snapshot` is infallible
/// (returns a `Vec`, not a `Result`) and already sorted by `(provider, label)`,
/// so there is no fetch-error path to handle — an empty `Vec` is rendered as
/// the "no credentials configured" empty state.
async fn load_credentials(store: &LlmCredentialStore) -> Vec<CredRow> {
    store
        .status_snapshot()
        .await
        .into_iter()
        .map(|s| CredRow {
            provider: s.provider.as_str().to_owned(),
            label: s.label,
            health: health_str(s.health),
        })
        .collect()
}

/// Display string for [`Health`]. Mirrors `dashboard_catalog`'s
/// `catalog_server_status_str` — a stable operator-facing label per variant,
/// matching the `serde(rename_all = "snake_case")` wire form the credential
/// store already emits.
fn health_str(h: Health) -> &'static str {
    match h {
        Health::Healthy => "healthy",
        Health::Unknown => "unknown",
        Health::Failing => "failing",
        Health::Stale => "stale",
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
    fn llm_credentials_admin_gate_allows_oauth_admin() {
        let p = principal_with(vec!["mcp:read", "mcp:admin"], AuthMethod::Oauth);
        assert!(principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn llm_credentials_admin_gate_blocks_oauth_without_admin_scope() {
        let p = principal_with(
            vec!["openid", "profile", "email", "groups", "mcp:read"],
            AuthMethod::Oauth,
        );
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn llm_credentials_admin_gate_blocks_peer_assertion_even_with_admin_scope() {
        let p = principal_with(vec!["mcp:admin"], AuthMethod::PeerAssertion);
        assert!(!principal_has_dashboard_admin(Some(&p)));
    }

    #[test]
    fn llm_credentials_admin_gate_blocks_missing_principal() {
        assert!(!principal_has_dashboard_admin(None));
    }

    #[test]
    fn health_strings_match_serde_wire_form() {
        // The display labels must match the `serde(rename_all = "snake_case")`
        // form the store emits for metrics / the Grafana view, so the panel and
        // the JSON snapshot never disagree about what a credential's health is.
        assert_eq!(health_str(Health::Healthy), "healthy");
        assert_eq!(health_str(Health::Unknown), "unknown");
        assert_eq!(health_str(Health::Failing), "failing");
        assert_eq!(health_str(Health::Stale), "stale");
    }

    #[tokio::test]
    async fn load_credentials_maps_snapshot_row() {
        // A real store built from one injected OpenRouter API-key credential.
        // OpenRouter takes a bare key (no OAuth blob), so it loads Healthy with
        // no network, and the snapshot must surface exactly one row carrying
        // the canonical provider id + operator-chosen label.
        let store = Arc::new(LlmCredentialStore::from_vars([(
            "LLM_CRED_OPENROUTER_MAIN".to_string(),
            "sk-test".to_string(),
        )]));

        let rows = load_credentials(&store).await;

        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.provider, "openrouter");
        assert_eq!(row.label, "MAIN");
        assert_eq!(
            row.health, "healthy",
            "a bare-key credential loads Healthy without a network round-trip",
        );
    }
}
