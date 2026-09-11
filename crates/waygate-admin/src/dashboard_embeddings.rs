//! LLM embeddings tester — `GET /embeddings` (page) + `POST /embeddings/run`
//! (htmx result fragment).
//!
//! A minimal surface to *exercise* a configured **embeddings** model from the
//! dashboard, authorized AS the logged-in session principal through the SAME
//! `SharedInvocation` the `/v1/embeddings` route uses (`AdminState::try_invocation`).
//! Embeddings are unary, so — unlike the streaming `/chat` tester — this posts a
//! form and swaps in a server-rendered result fragment: dimensions, a vector
//! preview, token usage, latency, and a pairwise **cosine-similarity matrix**,
//! the only human-meaningful way to *test* an embedding (semantically close
//! inputs score high, e.g. `cat`≈`kitten` ≫ `cat`·`airplane`).
//!
//! Like `/chat`, this is NOT gated on `mcp:admin` — testing a model is a model
//! invocation; the per-call Cedar gate is the real control, and a denial /
//! step-up renders inline in the result fragment. The picker is filtered to
//! models the resolver dispatches as `LlmOperation::Embeddings`, so a chat model
//! never appears here. Inputs are held only for the request — this page never
//! stores them; the call's data-retention is identical to a `/v1/embeddings`
//! call (usage/audit rows, and the per-principal cache for a cache-enabled model).

use std::sync::Arc;
use std::time::Instant;

use askama::Template;
use axum::extract::{Form, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use waygate_invocation::{InvocationError, InvocationRequest, InvocationResponse};
use waygate_llm_dispatch::LlmOperation;
use waygate_oidc::Principal;

use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::dashboard::{csrf_matches, render, user_display};
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;

/// Reserved invocation server namespace for LLM models (mirrors
/// `waygate_server::llm::LLM_SERVER`; see `dashboard_chat`).
const LLM_SERVER: &str = "llm";

/// Cap on inputs accepted from the textarea (one per line) — a tester, not a
/// batch job; also bounds the NxN similarity matrix.
const MAX_INPUTS: usize = 16;
/// How many leading vector components to show in the per-input preview.
const PREVIEW_DIMS: usize = 8;

#[derive(Template)]
#[template(path = "embeddings.html")]
struct EmbeddingsPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// Embeddings-only model aliases (tenant-scoped, enabled, resolver-dispatchable).
    /// Empty ⇒ the template shows a free-text model input instead.
    models: Vec<String>,
    /// `false` when the LLM plane is not mounted (no resolver) — the template
    /// shows a "not configured" note instead of the form.
    invocation_ready: bool,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/embeddings", get(embeddings_page))
        .route("/embeddings/run", post(run_embeddings))
}

async fn embeddings_page(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    tenant_ctx: Option<Extension<TenantContext>>,
    csrf: Option<Extension<CsrfToken>>,
    headers: HeaderMap,
) -> Response {
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let user_principal = user.as_ref().map(|Extension(p)| p);
    let user_display_str = user_principal.map(user_display);
    let read_tenant = user_principal
        .map(|p| p.tenant.as_str().to_owned())
        .unwrap_or_else(|| waygate_core::TenantId::DEFAULT.to_owned());

    // Picker = catalog models the resolver dispatches as EMBEDDINGS (so a chat
    // model never shows here). Same catalog+resolver gate as the chat picker,
    // with the operation discriminator added.
    let models = match (state.llm.llm_models.get(), state.llm.llm_resolver.as_ref()) {
        (Some(store), Some(resolver)) => match store.list_models(&read_tenant).await {
            Ok(rows) => rows
                .into_iter()
                .map(|r| r.alias)
                .filter(|alias| {
                    resolver
                        .resolve(LLM_SERVER, alias)
                        .is_some_and(|m| m.operation == LlmOperation::Embeddings)
                })
                .collect(),
            Err(e) => {
                tracing::error!(error = %e, tenant = %read_tenant, "embeddings page: list_models failed");
                Vec::new()
            }
        },
        _ => Vec::new(),
    };

    let page = EmbeddingsPage {
        chrome: PageChrome::build(
            &state,
            "Embeddings",
            "/embeddings",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        models,
        invocation_ready: state.llm.llm_resolver.is_some(),
    };
    render(&page)
}

#[derive(Deserialize)]
struct EmbedReq {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    model: String,
    /// One input per non-empty line.
    #[serde(default)]
    inputs: String,
    /// Optional Matryoshka output dimensionality (blank ⇒ model default).
    #[serde(default)]
    dimensions: String,
    /// Optional retrieval task hint (`search_query` / `search_document` / …);
    /// blank ⇒ not sent. A provider that doesn't support it surfaces an error.
    #[serde(default)]
    input_type: String,
}

#[derive(Template)]
#[template(path = "embeddings_result.html")]
struct EmbeddingsResult {
    /// Set on any failure (CSRF, not-configured, pipeline denial, bad response).
    error: Option<String>,
    /// Step-up scope to re-authorize with, when the failure was a Cedar step-up.
    step_up_scope: Option<String>,
    model: String,
    dimensions: usize,
    input_count: usize,
    prompt_tokens: Option<u64>,
    latency_ms: u128,
    items: Vec<EmbedItem>,
    /// Pairwise cosine-similarity matrix (row-major), present only for >= 2 inputs.
    sim_rows: Vec<SimRow>,
}

// (Embeddings bill input tokens only — `usage.total_tokens` equals
// `prompt_tokens`, so the view surfaces just the one count.)

struct EmbedItem {
    index: usize,
    text: String,
    /// First-N-component preview, shown collapsed.
    preview: String,
    /// The complete vector as a copy-pasteable JSON array (full f64 precision),
    /// revealed when the preview is expanded.
    full: String,
}

struct SimRow {
    index: usize,
    cells: Vec<String>,
}

/// An error/empty result view (no vectors), rendered into the same fragment.
fn err_result(message: impl Into<String>, step_up_scope: Option<String>) -> EmbeddingsResult {
    EmbeddingsResult {
        error: Some(message.into()),
        step_up_scope,
        model: String::new(),
        dimensions: 0,
        input_count: 0,
        prompt_tokens: None,
        latency_ms: 0,
        items: Vec::new(),
        sim_rows: Vec::new(),
    }
}

/// `POST /embeddings/run` — embed the submitted inputs for the session principal
/// and render the result fragment. CSRF is validated **before** the (billable)
/// invoke. Failures (denied / step-up / budget / upstream) render inline.
async fn run_embeddings(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    Form(req): Form<EmbedReq>,
) -> Response {
    if !csrf_ok(csrf.as_ref(), &req.csrf) {
        return render(&err_result("invalid or missing CSRF token", None));
    }
    let model = req.model.trim().to_string();
    if model.is_empty() {
        return render(&err_result("pick a model", None));
    }
    // One input per non-empty line, capped.
    let inputs: Vec<String> = req
        .inputs
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .take(MAX_INPUTS)
        .map(str::to_owned)
        .collect();
    if inputs.is_empty() {
        return render(&err_result(
            "enter at least one line of text to embed",
            None,
        ));
    }
    // The LLM plane must be mounted (resolver present); `try_invocation` alone is
    // always wired for the MCP try-it path, so check the resolver too.
    if state.llm.llm_resolver.is_none() {
        return render(&err_result(
            "inference is not configured on this gateway",
            None,
        ));
    }
    let Some(invocation) = state.dashboard.try_invocation.as_ref() else {
        return render(&err_result(
            "inference is not configured on this gateway",
            None,
        ));
    };
    let principal = user.as_ref().map(|Extension(p)| p);

    // OpenAI-shaped embeddings body. `encoding_format: float` so vectors come back
    // (needed for the similarity matrix); `dimensions` only when the operator gave
    // one (a Matryoshka-capable model; others ignore or reject it — surfaced as an
    // inline error). `input_type` (retrieval task hint) only when chosen — a
    // provider that doesn't support it surfaces the error inline.
    let mut args = serde_json::Map::new();
    args.insert("model".to_string(), json!(model));
    args.insert("input".to_string(), json!(inputs));
    args.insert("encoding_format".to_string(), json!("float"));
    if let Some(d) = req.dimensions.trim().parse::<u64>().ok().filter(|d| *d > 0) {
        args.insert("dimensions".to_string(), json!(d));
    }
    let input_type = req.input_type.trim();
    if !input_type.is_empty() {
        args.insert("input_type".to_string(), json!(input_type));
    }
    let request = InvocationRequest::new(LLM_SERVER, model.clone())
        .with_arguments(Some(args))
        .with_embeddings_surface(true);

    let started = Instant::now();
    let result = invocation.invoke(principal, request).await;
    let latency_ms = started.elapsed().as_millis();

    match result {
        Ok(InvocationResponse::UnaryValue(body)) => {
            render(&parse_embeddings_result(&model, &inputs, &body, latency_ms))
        }
        Ok(_) => render(&err_result(
            "unexpected non-embeddings result on the inference route",
            None,
        )),
        Err(e) => {
            let scope = match &e {
                InvocationError::StepUpRequired { required_scope, .. } => {
                    Some(required_scope.clone())
                }
                _ => None,
            };
            render(&err_result(e.to_string(), scope))
        }
    }
}

/// Parse the OpenAI embeddings response body into the result view: per-input
/// vector previews, token usage, and a pairwise cosine-similarity matrix.
fn parse_embeddings_result(
    model: &str,
    inputs: &[String],
    body: &Value,
    latency_ms: u128,
) -> EmbeddingsResult {
    let Some(data) = body.get("data").and_then(Value::as_array) else {
        return err_result("the provider returned no embeddings data", None);
    };
    // Place each row's vector at its authoritative `index` (providers return them
    // in order, but the field is the contract).
    let mut vectors: Vec<Vec<f64>> = vec![Vec::new(); data.len()];
    for row in data {
        let idx = row.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
        let v: Vec<f64> = row
            .get("embedding")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_f64).collect())
            .unwrap_or_default();
        if idx < vectors.len() {
            vectors[idx] = v;
        }
    }
    let dimensions = vectors.first().map(Vec::len).unwrap_or(0);
    let usage = body.get("usage");
    let prompt_tokens = usage
        .and_then(|u| u.get("prompt_tokens"))
        .and_then(Value::as_u64);

    let items: Vec<EmbedItem> = vectors
        .iter()
        .enumerate()
        .map(|(i, v)| EmbedItem {
            index: i,
            text: truncate(inputs.get(i).map(String::as_str).unwrap_or(""), 80),
            preview: preview_vec(v, PREVIEW_DIMS),
            full: full_vec(v),
        })
        .collect();

    // Pairwise cosine similarity is only meaningful with >= 2 inputs.
    let sim_rows = if vectors.len() >= 2 {
        vectors
            .iter()
            .enumerate()
            .map(|(i, vi)| SimRow {
                index: i,
                cells: vectors
                    .iter()
                    .map(|vj| format!("{:.3}", cosine(vi, vj)))
                    .collect(),
            })
            .collect()
    } else {
        Vec::new()
    };

    EmbeddingsResult {
        error: None,
        step_up_scope: None,
        model: model.to_string(),
        dimensions,
        input_count: inputs.len(),
        prompt_tokens,
        latency_ms,
        items,
        sim_rows,
    }
}

/// Cosine similarity of two equal-length vectors; `0.0` for a length mismatch or
/// a zero-norm vector (degenerate — no direction to compare).
fn cosine(a: &[f64], b: &[f64]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0;
    let mut na = 0.0;
    let mut nb = 0.0;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    if na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    dot / (na.sqrt() * nb.sqrt())
}

/// `[0.0123, -0.0456, …]` — the first `n` components at 4 decimals.
fn preview_vec(v: &[f64], n: usize) -> String {
    let head: Vec<String> = v.iter().take(n).map(|x| format!("{x:.4}")).collect();
    if v.len() > n {
        format!("[{}, …]", head.join(", "))
    } else {
        format!("[{}]", head.join(", "))
    }
}

/// The complete vector as a copy-pasteable JSON array at full f64 precision
/// (shortest round-trippable form via `{}`), revealed when the preview expands.
fn full_vec(v: &[f64]) -> String {
    let all: Vec<String> = v.iter().map(|x| x.to_string()).collect();
    format!("[{}]", all.join(", "))
}

/// Truncate to at most `max` characters (on a char boundary), with an ellipsis.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        let head: String = s.chars().take(max).collect();
        format!("{head}…")
    } else {
        s.to_string()
    }
}

/// Validate the submitted CSRF token against the per-session token; absent
/// injection (no auth layer) ⇒ reject.
fn csrf_ok(injected: Option<&Extension<CsrfToken>>, submitted: &str) -> bool {
    match injected {
        Some(Extension(CsrfToken(expected))) => {
            !submitted.is_empty() && csrf_matches(expected, submitted)
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_page_loads_htmx_and_uses_form_layout() {
        // Regression guard: the embeddings form posts + swaps its result via htmx,
        // which the dashboard loads PER-PAGE (not globally in layout.html). A page
        // that omits the htmx script falls back to a native submit and never
        // embeds; a page that ignores the `.form*` layout classes renders fields
        // crammed inline. The empty-state render test can't catch either — it
        // renders no form — so assert the CONFIGURED page directly here.
        let page = EmbeddingsPage {
            chrome: crate::chrome::PageChrome {
                title: "Embeddings",
                env: "dev",
                user: None,
                theme: None,
                nav: Vec::new(),
                tenant_ctx: None,
                csrf_token: "tok".into(),
            },
            models: vec!["openrouter:openai/text-embedding-3-small".into()],
            invocation_ready: true,
        };
        let html = page.render().expect("renders");
        assert!(
            html.contains("htmx.min.js"),
            "htmx must be loaded so the form actually posts"
        );
        assert!(html.contains("hx-post"), "the form posts via htmx");
        assert!(
            html.contains(r#"class="form""#),
            "uses the dashboard's stacked form layout, not an unstyled form"
        );
        assert!(
            html.contains("form-field"),
            "fields use the form-field layout"
        );
        assert!(
            html.contains("form-select"),
            "the model picker is a styled select"
        );
        assert!(
            html.contains("openrouter:openai/text-embedding-3-small"),
            "the chosen model renders as an option"
        );
    }

    #[test]
    fn csrf_ok_requires_matching_nonempty_token() {
        let tok = Extension(CsrfToken("expected".into()));
        assert!(csrf_ok(Some(&tok), "expected"));
        assert!(!csrf_ok(Some(&tok), "wrong"));
        assert!(!csrf_ok(Some(&tok), ""));
        assert!(!csrf_ok(None, "expected"));
    }

    #[test]
    fn cosine_identical_orthogonal_opposite_and_degenerate() {
        let a = [1.0, 2.0, 3.0];
        // Identical ⇒ 1.0
        assert!((cosine(&a, &a) - 1.0).abs() < 1e-9);
        // Orthogonal ⇒ 0.0
        assert!(cosine(&[1.0, 0.0], &[0.0, 1.0]).abs() < 1e-9);
        // Opposite ⇒ -1.0
        assert!((cosine(&[1.0, 1.0], &[-1.0, -1.0]) + 1.0).abs() < 1e-9);
        // Length mismatch / zero norm ⇒ 0.0 (no panic, no NaN)
        assert_eq!(cosine(&[1.0], &[1.0, 2.0]), 0.0);
        assert_eq!(cosine(&[0.0, 0.0], &[1.0, 2.0]), 0.0);
    }

    #[test]
    fn preview_vec_caps_and_marks_truncation() {
        assert_eq!(preview_vec(&[0.5, -0.25], 8), "[0.5000, -0.2500]");
        assert_eq!(preview_vec(&[1.0, 2.0, 3.0], 2), "[1.0000, 2.0000, …]");
        assert_eq!(preview_vec(&[], 8), "[]");
    }

    #[test]
    fn parse_builds_previews_usage_and_similarity() {
        // Two inputs; second vector equals the first ⇒ off-diagonal similarity 1.0.
        let body = json!({
            "object": "list",
            "data": [
                {"object": "embedding", "index": 0, "embedding": [1.0, 0.0, 0.0]},
                {"object": "embedding", "index": 1, "embedding": [1.0, 0.0, 0.0]}
            ],
            "model": "text-embedding-3-small",
            "usage": {"prompt_tokens": 7, "total_tokens": 7}
        });
        let inputs = vec!["alpha".to_string(), "beta".to_string()];
        let r = parse_embeddings_result("m", &inputs, &body, 42);
        assert!(r.error.is_none());
        assert_eq!(r.dimensions, 3);
        assert_eq!(r.input_count, 2);
        assert_eq!(r.prompt_tokens, Some(7));
        assert_eq!(r.latency_ms, 42);
        assert_eq!(r.items.len(), 2);
        assert_eq!(r.items[0].text, "alpha");
        // The preview is the first-8 (here all 3) at 4 decimals; `full` is the
        // complete copy-pasteable array at full precision.
        assert_eq!(r.items[0].preview, "[1.0000, 0.0000, 0.0000]");
        assert_eq!(r.items[0].full, "[1, 0, 0]");
        // 2 inputs ⇒ a 2x2 similarity matrix; identical vectors ⇒ all cells 1.000.
        assert_eq!(r.sim_rows.len(), 2);
        assert_eq!(r.sim_rows[0].cells, vec!["1.000", "1.000"]);
    }

    #[test]
    fn parse_single_input_has_no_similarity_matrix() {
        let body = json!({
            "data": [{"index": 0, "embedding": [0.1, 0.2]}],
            "usage": {"prompt_tokens": 2, "total_tokens": 2}
        });
        let r = parse_embeddings_result("m", &["solo".to_string()], &body, 1);
        assert_eq!(r.items.len(), 1);
        assert!(r.sim_rows.is_empty(), "no matrix for a single input");
    }

    #[test]
    fn parse_missing_data_is_an_error_result() {
        let r = parse_embeddings_result("m", &["x".to_string()], &json!({"object": "list"}), 1);
        assert!(r.error.is_some());
    }
}
