//! LLM chat tester — `GET /chat` (page) + `POST /chat/stream` (SSE).
//!
//! A minimal **streaming** chatbot to *exercise* a configured model from the
//! dashboard, authorized AS the logged-in session principal (Cedar authorizes
//! the model resource, budget, audit) via the SAME `SharedInvocation` the
//! `/v1/chat/completions` route uses (`AdminState::try_invocation`). It is a
//! test surface, not a chat product: the **conversation transcript is held
//! client-side** and this page never stores it server-side.
//!
//! Persistence note: because the call flows through the shared pipeline, it has
//! the SAME data-retention surface as a `/v1` call — usage/audit rows, and (for
//! a model with caching enabled) the assistant completion in the per-principal
//! `llm_cache`. That cache is opt-in (`GATEWAY_LLM_CACHE_ENABLED` + a per-model
//! `cache_ttl_ms`) and disabled by default; this page deliberately does **not**
//! bypass it, so a test sees the model's real cached behavior.
//!
//! Unlike the read-only `/llm_models` + `/llm_credentials` pages, this is NOT
//! gated on `mcp:admin` — testing a model is a model invocation, not an admin action, so any
//! authenticated dashboard session may open it. The per-call Cedar gate is the
//! real control; a denial / step-up surfaces inline as an `event: error` SSE
//! frame carrying the scope to re-authorize with.

use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::json;

use waygate_invocation::{InvocationError, InvocationRequest, InvocationResponse};
use waygate_llm_dispatch::LlmOperation;
use waygate_oidc::Principal;

use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::dashboard::{csrf_matches, render, user_display};
use crate::state::AdminState;
use crate::tenant_ctx::TenantContext;

/// The reserved invocation server namespace for LLM models. Mirrors
/// `waygate_server::llm::LLM_SERVER` (defined in the binary crate, so it can't
/// be imported here) — the dispatch path keys models under `("llm", <alias>)`.
const LLM_SERVER: &str = "llm";

#[derive(Template)]
#[template(path = "chat.html")]
struct ChatPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// Configured model aliases for the picker (tenant-scoped, enabled only).
    /// Empty ⇒ the template shows a free-text model input instead.
    models: Vec<String>,
    /// `false` when no invocation service is wired (no DB / dev) — the template
    /// disables the composer and shows a "not configured" note.
    invocation_ready: bool,
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/chat", get(chat_page))
        .route("/chat/stream", post(chat_stream))
}

async fn chat_page(
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

    // Populate the model picker from the catalog, then filter to CHAT models the
    // resolver can dispatch. An embeddings model resolves too, but it can't be
    // chatted with (the pipeline rejects a chat call on an embeddings model), so
    // it must NOT appear in this picker — the `/embeddings` tester has the inverse
    // filter (`LlmOperation::Embeddings`). No resolver (MCP-only) or no catalog ⇒
    // empty, and the template falls back to a free-text model field.
    let models = match (state.llm.llm_models.get(), state.llm.llm_resolver.as_ref()) {
        (Some(store), Some(resolver)) => match store.list_models(&read_tenant).await {
            Ok(rows) => rows
                .into_iter()
                .map(|r| r.alias)
                .filter(|alias| {
                    resolver
                        .resolve(LLM_SERVER, alias)
                        .is_some_and(|m| m.operation == LlmOperation::Chat)
                })
                .collect(),
            Err(e) => {
                tracing::error!(error = %e, tenant = %read_tenant, "chat page: list_models failed");
                Vec::new()
            }
        },
        _ => Vec::new(),
    };

    let page = ChatPage {
        chrome: PageChrome::build(
            &state,
            "Chat",
            "/chat",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        models,
        // The LLM plane is mounted iff the resolver is present — `try_invocation`
        // is ALWAYS wired (for the MCP try-it path) so it can't signal this.
        invocation_ready: state.llm.llm_resolver.is_some(),
    };
    render(&page)
}

#[derive(Deserialize)]
struct ChatReq {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    messages: Vec<ChatMsg>,
    #[serde(default)]
    temperature: Option<f64>,
}

#[derive(Deserialize, Serialize)]
struct ChatMsg {
    role: String,
    content: String,
}

/// `POST /chat/stream` — dispatch one chat turn for the session principal and
/// stream the assistant reply back as SSE. CSRF is validated **before** the
/// (side-effecting, possibly billable) invoke. The streamed frames are the
/// provider's OpenAI `chat.completion.chunk` JSON (relayed verbatim, mirroring
/// `waygate_server::llm::chat_completions`'s `InvocationResponse::Stream` arm),
/// terminated by `[DONE]`; failures arrive as an `event: error` frame so the
/// browser's single read-path handles both.
async fn chat_stream(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    Json(req): Json<ChatReq>,
) -> Response {
    if !csrf_ok(csrf.as_ref(), &req.csrf) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": { "message": "invalid or missing CSRF token" } })),
        )
            .into_response();
    }
    if req.model.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "message": "missing required field `model`" } })),
        )
            .into_response();
    }
    // The LLM plane must actually be mounted (resolver present) — `try_invocation`
    // alone is always wired for MCP try-it, so a model call on an MCP-only
    // deployment would otherwise enter the non-LLM path and fail confusingly.
    if state.llm.llm_resolver.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": { "message": "inference is not configured on this gateway" } })),
        )
            .into_response();
    }
    let Some(invocation) = state.dashboard.try_invocation.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": { "message": "inference is not configured on this gateway" } })),
        )
            .into_response();
    };
    let principal = user.as_ref().map(|Extension(p)| p);

    // The OpenAI-shaped chat body the invocation pipeline expects for an LLM
    // call (same shape the /v1 route forwards), with streaming forced on.
    let mut args = serde_json::Map::new();
    args.insert("model".to_string(), json!(req.model));
    args.insert(
        "messages".to_string(),
        serde_json::to_value(&req.messages).unwrap_or_else(|_| json!([])),
    );
    args.insert("stream".to_string(), json!(true));
    if let Some(t) = req.temperature {
        args.insert("temperature".to_string(), json!(t));
    }
    let request = InvocationRequest::new(LLM_SERVER, req.model.clone()).with_arguments(Some(args));

    match invocation.invoke(principal, request).await {
        // Forward each canonical chunk as an OpenAI-shaped SSE frame — verbatim,
        // matching the /v1 streaming arm (waygate-server/src/llm.rs).
        Ok(InvocationResponse::Stream(stream)) => {
            let sse = stream.map(|item| {
                let event = match item {
                    Ok(chunk) if chunk.terminal => Event::default().data("[DONE]"),
                    Ok(chunk) => Event::default().data(chunk.event.to_string()),
                    Err(e) => Event::default().event("error").data(
                        json!({ "error": { "message": e.to_string(), "type": "api_error" } })
                            .to_string(),
                    ),
                };
                Ok::<Event, std::convert::Infallible>(event)
            });
            Sse::new(sse).into_response()
        }
        // `stream:true` should yield a Stream; tolerate a unary body defensively
        // (e.g. a cache replay served as a single value) by framing it as one
        // SSE data event + the terminal sentinel.
        Ok(InvocationResponse::UnaryValue(body)) => {
            sse_once(Event::default().data(body.to_string()))
        }
        Ok(InvocationResponse::Unary(_)) => {
            sse_error("unexpected tool result on the inference route", None)
        }
        // The chat surface declares no input capabilities, so the pipeline
        // fails an MRTR pause closed before it can surface here.
        Ok(InvocationResponse::InputRequired(_)) => sse_error(
            "unexpected input_required pause on the inference route",
            None,
        ),
        // A pre-stream pipeline error (denied / step-up / budget / upstream).
        // Surface it as an error frame so the browser shows it inline; a
        // step-up carries the scope to re-authorize with.
        Err(e) => {
            let scope = match &e {
                InvocationError::StepUpRequired { required_scope, .. } => {
                    Some(required_scope.clone())
                }
                _ => None,
            };
            sse_error(&e.to_string(), scope)
        }
    }
}

/// Validate the submitted CSRF token against the per-session token injected by
/// the auth layer. Absent injection (no auth layer) ⇒ reject.
fn csrf_ok(injected: Option<&Extension<CsrfToken>>, submitted: &str) -> bool {
    match injected {
        // Constant-time compare via the dashboard's shared helper (avoids a
        // byte-timing oracle); still require a non-empty submission.
        Some(Extension(CsrfToken(expected))) => {
            !submitted.is_empty() && csrf_matches(expected, submitted)
        }
        None => false,
    }
}

/// A single-frame SSE response: the event, then the `[DONE]` sentinel.
fn sse_once(event: Event) -> Response {
    let frames = futures_util::stream::iter(vec![
        Ok::<Event, std::convert::Infallible>(event),
        Ok(Event::default().data("[DONE]")),
    ]);
    Sse::new(frames).into_response()
}

/// A one-frame SSE error response (`event: error`), optionally carrying the
/// `step_up_scope` the client should re-authorize with.
fn sse_error(message: &str, step_up_scope: Option<String>) -> Response {
    let mut err = json!({ "error": { "message": message, "type": "api_error" } });
    if let Some(scope) = step_up_scope {
        err["error"]["step_up_scope"] = json!(scope);
    }
    let frames = futures_util::stream::iter(vec![Ok::<Event, std::convert::Infallible>(
        Event::default().event("error").data(err.to_string()),
    )]);
    Sse::new(frames).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_ok_requires_matching_nonempty_token() {
        let tok = Extension(CsrfToken("expected".into()));
        assert!(csrf_ok(Some(&tok), "expected"));
        assert!(!csrf_ok(Some(&tok), "wrong"));
        assert!(!csrf_ok(Some(&tok), ""), "empty submission rejected");
        assert!(!csrf_ok(None, "expected"), "no injected token ⇒ reject");
    }

    /// Collect an SSE response body to a string for assertions.
    async fn sse_body(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("collect sse body");
        String::from_utf8_lossy(&bytes).to_string()
    }

    #[tokio::test]
    async fn sse_error_frames_message_and_step_up_scope() {
        let body = sse_body(sse_error("nope", Some("mcp:invoke:high".into()))).await;
        assert!(body.contains("event:error") || body.contains("event: error"));
        assert!(body.contains("nope"));
        assert!(body.contains("mcp:invoke:high"));
    }

    #[tokio::test]
    async fn sse_once_appends_done_sentinel() {
        let body = sse_body(sse_once(Event::default().data("{\"hi\":1}"))).await;
        assert!(body.contains("hi"));
        assert!(body.contains("[DONE]"), "terminal sentinel present");
    }
}
