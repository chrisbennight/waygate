//! Contextual Assistant — the context-plane HTTP surface.
//!
//! `GET /assist/context?page=<nav-suffix>` returns the per-page
//! [`crate::page_context::PresentationContext`] — the suggested-action chips and
//! affordances the docked panel renders. Session-gated; **grounding is never
//! returned** (it's the server-authored prompt text, injected at chat time —
//! see `page_context.rs` and `dashboard_agent_chat::agent_chat_stream`).
//!
//! `page` is client-supplied and untrusted; `resolve_page_context` sanitizes it
//! (registered pages use the trusted `DESTINATIONS` labels; unknown ones are
//! slug-sanitized), so the response is safe to build from any value.
//!
//! One-shot **review** chips (`OneShotReview`) call the `mcp:admin`-gated review
//! drivers (`agent_review.rs`), so they are gated here too: a chip is
//! emitted only when the caller is a dashboard admin **and** an enabled agent of
//! that kind exists — with that agent's id attached so the panel can run it.
//! Otherwise the chip is dropped (the generic chips + chat remain).

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde::Deserialize;

use waygate_dashboard_stores::agent_config::AgentKind;
use waygate_oidc::{AuthMethod, Principal, Scope};

use crate::page_context::{resolve_page_context, ActionKind, PresentationContext, SuggestedAction};
use crate::state::AdminState;

pub fn router() -> Router<Arc<AdminState>> {
    Router::new().route("/assist/context", get(assist_context))
}

#[derive(Deserialize)]
struct ContextQuery {
    /// The dashboard page (nav suffix, e.g. `/policies`) the panel is open on.
    #[serde(default)]
    page: String,
}

/// Dashboard-admin check: `mcp:admin` scope and NOT a peer assertion. Mirrors
/// the per-module helper used across the dashboard's admin-gated surfaces.
fn principal_has_dashboard_admin(p: Option<&Principal>) -> bool {
    match p {
        None => false,
        Some(p) if p.auth_method == AuthMethod::PeerAssertion => false,
        Some(p) => p.has_scope(Scope::McpAdmin.as_str()),
    }
}

/// Gate the one-shot **review** chips: keep a `OneShotReview` chip only when the
/// caller is admin AND an enabled agent of its kind exists (attaching that
/// agent's id); drop it otherwise. Every other chip kind passes through
/// unchanged. Pure so the admin/availability matrix is unit-testable.
fn gate_review_actions(
    actions: Vec<SuggestedAction>,
    is_admin: bool,
    review_agents: &HashMap<String, String>,
) -> Vec<SuggestedAction> {
    let mut out = Vec::with_capacity(actions.len());
    for a in actions {
        match a.kind {
            ActionKind::OneShotReview { agent_kind, .. } => {
                // Review drivers are mcp:admin-gated; never offer the chip to a
                // non-admin or when no enabled agent of that kind is configured.
                if !is_admin {
                    continue;
                }
                if let Some(id) = review_agents.get(&agent_kind) {
                    out.push(SuggestedAction {
                        id: a.id,
                        label: a.label,
                        kind: ActionKind::OneShotReview {
                            agent_kind,
                            agent_id: Some(id.clone()),
                        },
                    });
                }
            }
            other => out.push(SuggestedAction {
                id: a.id,
                label: a.label,
                kind: other,
            }),
        }
    }
    out
}

/// Map each review `AgentKind` to the id of the first **enabled** agent of that
/// kind in the tenant (the one a review chip will run). Empty when no agent
/// store is wired or the query fails.
async fn resolve_review_agents(state: &AdminState, tenant: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Some(store) = state.agent.agent_configs.get() else {
        return map;
    };
    // Page through ALL configs: the first enabled agent of a review kind may
    // sort past any single page, so don't cap at one list() call.
    // PAGE <= MAX_LIST_LIMIT, so a short page reliably means "no more rows".
    const PAGE: u32 = 200;
    let mut offset = 0u32;
    loop {
        let rows = match store.list(tenant, PAGE, offset).await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!(error = %e, tenant, "assist context: list agents failed");
                break;
            }
        };
        let fetched = rows.len() as u32;
        for a in rows {
            if !a.enabled {
                continue;
            }
            let key = match a.kind {
                AgentKind::PolicyReview => AgentKind::PolicyReview.as_str(),
                AgentKind::Classification => AgentKind::Classification.as_str(),
                AgentKind::Chat => continue,
            };
            map.entry(key.to_owned())
                .or_insert_with(|| a.id.to_string());
        }
        // Done once both review kinds are resolved, or the store is exhausted.
        let found_both = map.contains_key(AgentKind::PolicyReview.as_str())
            && map.contains_key(AgentKind::Classification.as_str());
        if found_both || fetched < PAGE {
            break;
        }
        offset += PAGE;
    }
    map
}

/// `GET /assist/context?page=<suffix>` — the per-page presentation context
/// (chips + affordances) for the docked panel. Session-gated; review chips are
/// admin-gated + agent-resolved.
async fn assist_context(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    Query(q): Query<ContextQuery>,
) -> Response {
    let Some(Extension(principal)) = user else {
        return (StatusCode::UNAUTHORIZED, "no authenticated session").into_response();
    };
    let page = if q.page.trim().is_empty() {
        "/"
    } else {
        q.page.as_str()
    };
    let is_admin = principal_has_dashboard_admin(Some(&principal));
    let review_agents = if is_admin {
        resolve_review_agents(&state, principal.tenant.as_str()).await
    } else {
        HashMap::new()
    };

    // `.presentation()` drops the server-authored grounding — only chips +
    // affordances cross to the client.
    let ctx = resolve_page_context(page, None).presentation();
    let actions = gate_review_actions(ctx.actions, is_admin, &review_agents);
    Json(PresentationContext { actions, ..ctx }).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page_context::ActionKind;

    fn review(id: &str, kind: &str) -> SuggestedAction {
        SuggestedAction {
            id: id.to_owned(),
            label: "Review".to_owned(),
            kind: ActionKind::OneShotReview {
                agent_kind: kind.to_owned(),
                agent_id: None,
            },
        }
    }

    fn generic(id: &str) -> SuggestedAction {
        SuggestedAction {
            id: id.to_owned(),
            label: "Explain".to_owned(),
            kind: ActionKind::SeedPrompt {
                text: "explain".to_owned(),
            },
        }
    }

    fn agent_id_of(a: &SuggestedAction) -> Option<&str> {
        match &a.kind {
            ActionKind::OneShotReview { agent_id, .. } => agent_id.as_deref(),
            _ => None,
        }
    }

    #[test]
    fn non_admin_loses_review_chips_keeps_generic() {
        let actions = vec![
            review("review_policy_set", "policy_review"),
            generic("explain_page"),
        ];
        let out = gate_review_actions(actions, false, &HashMap::new());
        let ids: Vec<&str> = out.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["explain_page"],
            "non-admin must not get review chips"
        );
    }

    #[test]
    fn admin_with_agent_gets_review_chip_with_id() {
        let mut agents = HashMap::new();
        agents.insert("policy_review".to_owned(), "agent-123".to_owned());
        let actions = vec![
            review("review_policy_set", "policy_review"),
            generic("explain_page"),
        ];
        let out = gate_review_actions(actions, true, &agents);
        let ids: Vec<&str> = out.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, vec!["review_policy_set", "explain_page"]);
        assert_eq!(
            agent_id_of(&out[0]),
            Some("agent-123"),
            "review chip must carry the agent id"
        );
    }

    #[test]
    fn admin_without_a_matching_agent_drops_the_review_chip() {
        // Admin, but no enabled agent of that kind → the chip can't run, so drop.
        let actions = vec![
            review("audit_classifications", "classification"),
            generic("recent_activity"),
        ];
        let out = gate_review_actions(actions, true, &HashMap::new());
        let ids: Vec<&str> = out.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, vec!["recent_activity"]);
    }
}
