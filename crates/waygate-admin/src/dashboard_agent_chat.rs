//! Interactive **agent chat** — `GET /agent_chat`
//! (page) + `POST /agent_chat/stream` (SSE).
//!
//! Unlike the `/chat` model-tester (which streams one raw model completion), this
//! runs a **configured agent**: the bounded [`waygate_agent::run_agent`] loop over
//! the agent's allowlisted upstream tools, executed AS the logged-in session
//! principal (so every model call + tool call inherits the same Cedar authz /
//! budget / audit as a `/v1` or MCP call), with each model/tool invocation
//! stamped `acting_agent = agent:<name>` for audit attribution, and the turn
//! transcript persisted (owner-scoped) when a conversation store is wired.
//!
//! Safety posture:
//! - **Allowlist** — only the agent's `allowed_tools` are offered/dispatchable
//!   (hard-enforced in [`waygate_agent_runtime::agent_runtime::UpstreamAgentDispatch`]); an empty
//!   allowlist ⇒ a read/answer-only agent.
//! - **Side-effects gate** — a side-effecting tool is parked by
//!   [`waygate_agent_runtime::agent_runtime::ChatApprovalGate`] and runs only after the operator
//!   approves it in-chat (`POST /agent_chat/approve`); a reject (or a timeout) is
//!   fed back to the model, honoring "no side effects without confirmation".
//! - **Effective principal** — the session principal narrowed to the allowlist
//!   (+ the agent's own model), never broadened
//!   ([`waygate_agent_runtime::agent_runtime::effective_principal`]).

use std::convert::Infallible;
use std::sync::Arc;

use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use waygate_agent::{
    build_system_prompt, run_agent, AgentEvent, AgentEventSink, AgentOutcome, AgentRunConfig,
    AgentToolDispatch, SystemPromptContext,
};
use waygate_llm_translate::{CanonicalMessage, ContentPart, Role};
use waygate_oidc::Principal;
use waygate_storage::{NewConversation, SharedConversationStore};

use crate::auth::CsrfToken;
use crate::chrome::PageChrome;
use crate::dashboard::{csrf_matches, render, user_display};
use crate::state::AdminState;
use crate::tenant_ctx::{self, TenantContext};
use waygate_agent_runtime::agent_runtime::{
    effective_principal, ChatApprovalGate, OpenAiAgentModel, UpstreamAgentDispatch,
};

/// Cap on how many prior messages of a conversation are replayed into the model
/// context (keeps the prompt bounded; older turns are dropped oldest-first by
/// the store's `ORDER BY seq` + this limit on the tail).
const HISTORY_LIMIT: u32 = 100;

/// Human label for the gateway in the agent's system prompt.
const GATEWAY_LABEL: &str = "MCP";

/// How many recent conversations the resume list shows.
const CONVERSATION_LIST_LIMIT: u32 = 50;

#[derive(Template)]
#[template(path = "agent_chat.html")]
struct AgentChatPage {
    /// Shared topbar / nav / tenant chrome — see [`crate::chrome::PageChrome`].
    chrome: PageChrome,
    /// Enabled chat agents for the picker (id, display name, model alias).
    agents: Vec<AgentOption>,
    /// `false` ⇒ no agent-config store wired (no DB): the page shows a "not
    /// configured" card.
    configured: bool,
    /// `false` ⇒ no inference plane (resolver) wired: chat can't run.
    inference_ready: bool,
    /// `true` when a conversation store is wired — the page shows the recent
    /// conversations list (resume).
    history_enabled: bool,
}

/// One agent in the picker. `model` drives the egress indicator chip; an LLM
/// call to it leaves the gateway for that model's provider. Serializable so the
/// docked panel can hydrate its picker client-side from `/agent_chat/bootstrap`.
#[derive(Serialize)]
struct AgentOption {
    id: String,
    name: String,
    model: String,
}

/// List the tenant's enabled **chat** agents for the picker, plus whether an
/// agent-config store is wired at all. Shared by the immersive page and the
/// docked panel's bootstrap so both surface the identical agent set.
async fn list_chat_agents(state: &AdminState, tenant: &str) -> (Vec<AgentOption>, bool) {
    match state.agent.agent_configs.get() {
        Some(store) => match store.list(tenant, 200, 0).await {
            Ok(rows) => (
                rows.into_iter()
                    .filter(|a| {
                        a.enabled
                            && a.kind == waygate_dashboard_stores::agent_config::AgentKind::Chat
                    })
                    .map(|a| AgentOption {
                        id: a.id.to_string(),
                        name: a.name,
                        model: a.model_alias,
                    })
                    .collect(),
                true,
            ),
            Err(e) => {
                tracing::error!(error = %e, tenant = %tenant, "agent chat: list agents failed");
                (Vec::new(), true)
            }
        },
        None => (Vec::new(), false),
    }
}

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/agent_chat", get(agent_chat_page))
        .route("/agent_chat/bootstrap", get(agent_chat_bootstrap))
        .route("/agent_chat/stream", post(agent_chat_stream))
        .route("/agent_chat/approve", post(agent_chat_approve))
        .route("/agent_chat/conversations", get(agent_chat_conversations))
        .route(
            "/agent_chat/conversations/{id}",
            get(agent_chat_conversation),
        )
}

async fn agent_chat_page(
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

    // List enabled CHAT agents for the picker. No store ⇒ empty + "not
    // configured" card.
    let (agents, configured) = list_chat_agents(&state, &read_tenant).await;

    let page = AgentChatPage {
        chrome: PageChrome::build(
            &state,
            "Agent Chat",
            "/agent_chat",
            &headers,
            user_display_str,
            tenant_ctx,
            csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        ),
        agents,
        configured,
        inference_ready: state.llm.llm_resolver.is_some()
            && state.dashboard.try_invocation.is_some(),
        history_enabled: state.agent.conversations.enabled(),
    };
    render(&page)
}

/// `GET /agent_chat/bootstrap` — the data the docked assistant panel needs to
/// hydrate its chat client on *any* page: the session CSRF token, the
/// tenant-correct stream URL, the enabled chat agents, and the inference/store
/// readiness flags. Session-gated (the dashboard middleware injects the
/// principal + CSRF), returned same-origin to the authenticated session only —
/// the CSRF token lives in the encrypted session cookie, so the client can't
/// read it directly and needs this echo to POST to `/agent_chat/stream`.
async fn agent_chat_bootstrap(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    tenant_ctx: Option<Extension<TenantContext>>,
) -> Response {
    let Some(Extension(human)) = user else {
        return bad(StatusCode::UNAUTHORIZED, "no authenticated session");
    };
    let tenant_ctx = tenant_ctx.map(|Extension(c)| c);
    let (agents, configured) = list_chat_agents(&state, human.tenant.as_str()).await;
    Json(json!({
        "csrf": csrf.map(|Extension(c)| c.0).unwrap_or_default(),
        "stream_url": tenant_ctx::nav_url(tenant_ctx.as_ref(), "/agent_chat/stream"),
        "agents": agents,
        "configured": configured,
        "inference_ready": state.llm.llm_resolver.is_some() && state.dashboard.try_invocation.is_some(),
        "history_enabled": state.agent.conversations.enabled(),
    }))
    .into_response()
}

#[derive(Deserialize)]
struct ChatReq {
    #[serde(default)]
    csrf: String,
    /// Agent config id (UUID string).
    #[serde(default)]
    agent_id: String,
    /// The new user message.
    #[serde(default)]
    message: String,
    /// Continue an existing conversation; absent ⇒ start a new one.
    #[serde(default)]
    conversation_id: Option<String>,
    /// The dashboard page the docked panel is open on (nav suffix, e.g.
    /// `/policies`). Grounds the agent in the operator's current page
    /// (Contextual Assistant). Untrusted — resolved + sanitized server-side.
    #[serde(default)]
    page: Option<String>,
}

/// `POST /agent_chat/stream` — run one agent turn and stream its step events as
/// SSE. CSRF is validated before any (governed, possibly billable) model call.
async fn agent_chat_stream(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    Json(req): Json<ChatReq>,
) -> Response {
    if !csrf_ok(csrf.as_ref(), &req.csrf) {
        return bad(StatusCode::FORBIDDEN, "invalid or missing CSRF token");
    }
    if req.message.trim().is_empty() {
        return bad(StatusCode::BAD_REQUEST, "missing required field `message`");
    }
    let Some(Extension(human)) = user else {
        return bad(StatusCode::UNAUTHORIZED, "no authenticated session");
    };
    // The inference plane must be mounted (resolver + invocation).
    if state.llm.llm_resolver.is_none() {
        return bad(
            StatusCode::SERVICE_UNAVAILABLE,
            "inference is not configured on this gateway",
        );
    }
    let Some(invocation) = state.dashboard.try_invocation.clone() else {
        return bad(
            StatusCode::SERVICE_UNAVAILABLE,
            "inference is not configured on this gateway",
        );
    };
    let Some(agent_store) = state.agent.agent_configs.get() else {
        return bad(
            StatusCode::SERVICE_UNAVAILABLE,
            "agent configuration is not available",
        );
    };

    let tenant = human.tenant.as_str().to_owned();
    let Ok(agent_id) = Uuid::parse_str(req.agent_id.trim()) else {
        return bad(StatusCode::BAD_REQUEST, "invalid `agent_id`");
    };
    let agent = match agent_store.get(&tenant, agent_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return bad(StatusCode::NOT_FOUND, "no such agent"),
        Err(e) => {
            tracing::error!(error = %e, "agent chat: load agent failed");
            return bad(StatusCode::INTERNAL_SERVER_ERROR, "failed to load agent");
        }
    };
    if !agent.enabled {
        return bad(StatusCode::FORBIDDEN, "this agent is disabled");
    }
    if agent.kind != waygate_dashboard_stores::agent_config::AgentKind::Chat {
        return bad(StatusCode::BAD_REQUEST, "this agent is not a chat agent");
    }

    // Build the agent's effective principal + its three runtime seams.
    let acting_agent = format!("agent:{}", agent.name);
    let eff = effective_principal(&human, &agent.allowed_tools, &agent.model_alias);
    let model = OpenAiAgentModel::new(
        invocation.clone(),
        eff.clone(),
        agent.model_alias.clone(),
        acting_agent.clone(),
        None,
    );
    let dispatch = UpstreamAgentDispatch::resolve(
        invocation,
        &state.upstreams,
        state.agent.assist_read.clone(),
        eff,
        acting_agent,
        &agent.allowed_tools,
    )
    .await;
    let run_cfg = AgentRunConfig {
        max_steps: agent.max_steps.max(1) as u32,
        max_tool_calls: agent.max_tool_calls.max(0) as u32,
        token_budget: agent.token_budget.filter(|t| *t > 0).map(|t| t as u64),
    };

    // System prompt from the agent's tool surface + operator instructions.
    let tool_pairs: Vec<(String, String)> = match dispatch.available_tools().await {
        Ok(tools) => tools
            .into_iter()
            .map(|t| {
                (
                    t.definition.name,
                    t.definition.description.unwrap_or_default(),
                )
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    // Per-page grounding (Contextual Assistant): the docked panel sends the page
    // it's open on; ground the agent in it. resolve_page_context sanitizes any
    // client-supplied page (registered pages use trusted nav labels; unknown
    // ones are slug-sanitized), so a forged value can't smuggle prompt text.
    let page_grounding = req
        .page
        .as_deref()
        .map(|p| crate::page_context::resolve_page_context(p, None).grounding);
    let system_prompt = build_system_prompt(&SystemPromptContext {
        gateway_label: GATEWAY_LABEL,
        tenant: &tenant,
        tools: &tool_pairs,
        operator_instructions: agent.instructions.as_deref(),
        page_context: page_grounding.as_deref(),
    });

    // Resolve / create the conversation (owner-scoped) + load prior history.
    let user_sub = human.sub.clone();
    let store = state.agent.conversations.get().cloned();

    // A resumed conversation stays bound to its ORIGINAL agent: if
    // the caller continues an existing thread with a DIFFERENT agent selected,
    // refuse — otherwise a turn from agent B would land in a thread labeled with
    // agent A. The UI also re-selects the original agent on resume, so this is
    // the server-side backstop for a stale selection / direct API call.
    if let (Some(s), Some(req_id)) = (store.as_ref(), req.conversation_id.as_deref()) {
        if let Ok(cid) = Uuid::parse_str(req_id.trim()) {
            match s.get(&tenant, &user_sub, cid).await {
                Ok(Some(c)) if c.agent_name != agent.name => {
                    return bad(
                        StatusCode::CONFLICT,
                        "this conversation belongs to a different agent — select that agent \
                         or start a new conversation",
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::error!(error = %e, "agent chat: conversation agent-check failed");
                    return bad(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to load conversation",
                    );
                }
            }
        }
    }

    // Persist the originating page on a NEW conversation (Contextual
    // Assistant). Sanitize the client-supplied `page` the same way
    // grounding does — store the canonical nav suffix, never free-form text.
    let origin_page = req
        .page
        .as_deref()
        .and_then(crate::page_context::safe_page_slug);
    let conversation = resolve_conversation(
        store.as_ref(),
        &tenant,
        &user_sub,
        &agent.name,
        req.conversation_id.as_deref(),
        &req.message,
        origin_page.as_deref(),
    )
    .await;
    let history = match (store.as_ref(), conversation) {
        (Some(s), Some(id)) => load_history(s, &tenant, &user_sub, id).await,
        _ => Vec::new(),
    };

    // Seed the transcript: system, prior history, the new user message.
    let user_msg = CanonicalMessage {
        role: Role::User,
        content: vec![ContentPart::Text {
            text: req.message.clone(),
        }],
    };
    let mut transcript: Vec<CanonicalMessage> = Vec::with_capacity(history.len() + 2);
    transcript.push(CanonicalMessage {
        role: Role::System,
        content: vec![ContentPart::Text {
            text: system_prompt,
        }],
    });
    transcript.extend(history);
    transcript.push(user_msg.clone());
    // Everything appended at/after this index is NEW (to be persisted).
    let base_len = transcript.len();

    // Persist the user message up front (so a crash mid-run still records it).
    if let (Some(s), Some(id)) = (store.as_ref(), conversation) {
        persist_message(s, &tenant, &user_sub, id, &user_msg).await;
    }

    // A FRESH per-turn id keys this turn's parked approvals. It is deliberately
    // NOT the conversation id: two turns of the same
    // conversation can overlap (e.g. two browser tabs), and a provider may reuse
    // a tool-call id across turns — keying on the conversation id would then let
    // one turn's approval resolve the other turn's call. A per-turn id makes the
    // `(session_id, call_id)` approval key unique across concurrent turns.
    let session_id = Uuid::new_v4();
    let gate = ChatApprovalGate::new(
        state.agent.chat_approvals.clone(),
        session_id,
        tenant.clone(),
        user_sub.clone(),
    );

    // Drive the loop in a task; stream its events over an unbounded channel that
    // backs the SSE body (so frames reach the browser as the turn progresses).
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
    // `session` is the per-turn approval id (echoed back on approve/reject);
    // `conversation` is the durable thread id (echoed back to continue the
    // thread). They are distinct: approvals must not share a key across turns,
    // but continuation must reuse the same conversation.
    let _ = tx.send(sse(
        "session",
        &json!({ "id": session_id.to_string() }).to_string(),
    ));
    if let Some(id) = conversation {
        let _ = tx.send(sse(
            "conversation",
            &json!({ "id": id.to_string() }).to_string(),
        ));
    }

    let task_store = store.clone();
    tokio::spawn(async move {
        let mut sink = ChannelSink { tx: tx.clone() };
        let outcome = run_agent(
            &model,
            &dispatch,
            &gate,
            &run_cfg,
            &mut transcript,
            &mut sink,
        )
        .await;

        // Persist the new assistant/tool messages this turn produced.
        if let (Some(s), Some(id)) = (task_store.as_ref(), conversation) {
            for m in &transcript[base_len..] {
                persist_message(s, &tenant, &user_sub, id, m).await;
            }
        }

        let terminal = match &outcome {
            Ok(AgentOutcome::Done {
                steps, tool_calls, ..
            }) => sse(
                "done",
                &json!({ "status": "done", "steps": steps, "tool_calls": tool_calls }).to_string(),
            ),
            Ok(AgentOutcome::Stopped {
                reason,
                steps,
                tool_calls,
            }) => sse(
                "done",
                &json!({
                    "status": "stopped",
                    "reason": format!("{reason:?}"),
                    "steps": steps,
                    "tool_calls": tool_calls,
                })
                .to_string(),
            ),
            Err(e) => sse(
                "error",
                &json!({ "error": { "message": e.to_string() } }).to_string(),
            ),
        };
        let _ = tx.send(terminal);
    });

    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|ev| (Ok::<Event, Infallible>(ev), rx))
    });
    let mut resp = Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response();
    // Defeat proxy buffering so SSE frames flush incrementally (nginx, etc.).
    resp.headers_mut().insert(
        "X-Accel-Buffering",
        axum::http::HeaderValue::from_static("no"),
    );
    resp
}

#[derive(Deserialize)]
struct ApproveReq {
    #[serde(default)]
    csrf: String,
    /// The chat-session id from the `session` SSE frame.
    #[serde(default)]
    session_id: String,
    /// The model tool-call id from the `approval_requested` event.
    #[serde(default)]
    call_id: String,
    /// `"approve"` runs the side-effecting tool; anything else rejects it.
    #[serde(default)]
    decision: String,
}

/// `POST /agent_chat/approve` — resolve a parked side-effecting tool call. The
/// loop's `ChatApprovalGate` is blocked on this; resolving unblocks it (approve
/// runs the tool, reject feeds the refusal back to the model). Owner-scoped via
/// the registry — an operator can only resolve their own session's approvals.
async fn agent_chat_approve(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    csrf: Option<Extension<CsrfToken>>,
    Json(req): Json<ApproveReq>,
) -> Response {
    if !csrf_ok(csrf.as_ref(), &req.csrf) {
        return bad(StatusCode::FORBIDDEN, "invalid or missing CSRF token");
    }
    let Some(Extension(human)) = user else {
        return bad(StatusCode::UNAUTHORIZED, "no authenticated session");
    };
    let Ok(session) = Uuid::parse_str(req.session_id.trim()) else {
        return bad(StatusCode::BAD_REQUEST, "invalid `session_id`");
    };
    if req.call_id.trim().is_empty() {
        return bad(StatusCode::BAD_REQUEST, "missing `call_id`");
    }
    let decision = match req.decision.as_str() {
        "approve" => waygate_agent::ApprovalDecision::Approved,
        _ => waygate_agent::ApprovalDecision::Rejected("declined by operator".to_owned()),
    };
    let resolved = state.agent.chat_approvals.resolve(
        session,
        req.call_id.trim(),
        human.tenant.as_str(),
        &human.sub,
        decision,
    );
    if resolved {
        (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
    } else {
        // Unknown / already-decided / not-owned — all collapse to one shape so a
        // caller can't probe another operator's pending approvals.
        bad(StatusCode::NOT_FOUND, "no pending approval for that call")
    }
}

/// `GET /agent_chat/conversations` — the operator's recent conversations
/// (owner-scoped), newest activity first, for the resume list.
async fn agent_chat_conversations(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
) -> Response {
    let Some(Extension(human)) = user else {
        return bad(StatusCode::UNAUTHORIZED, "no authenticated session");
    };
    let Some(store) = state.agent.conversations.get() else {
        // No persistence wired — an empty list, not an error (the UI hides the
        // panel via `history_enabled`, but a direct call still gets a clean []).
        return Json(json!({ "conversations": [] })).into_response();
    };
    match store
        .list(
            human.tenant.as_str(),
            &human.sub,
            CONVERSATION_LIST_LIMIT,
            0,
        )
        .await
    {
        Ok(rows) => {
            let items: Vec<Value> = rows
                .iter()
                .map(|c| {
                    json!({
                        "id": c.id.to_string(),
                        "title": c.title,
                        "agent_name": c.agent_name,
                        // The page the thread began on, or null. Lets the
                        // resume list show / deep-link back to where it started.
                        "origin_page": c.origin_page,
                        "updated_at": c.updated_at.unix_timestamp(),
                    })
                })
                .collect();
            Json(json!({ "conversations": items })).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "agent chat: list conversations failed");
            bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to list conversations",
            )
        }
    }
}

/// `GET /agent_chat/conversations/{id}` — one owned conversation's transcript,
/// flattened to `{role, text}` for display-only resume (owner-scoped; a missing
/// or non-owned id returns an empty transcript, no existence disclosure).
async fn agent_chat_conversation(
    State(state): State<Arc<AdminState>>,
    user: Option<Extension<Principal>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let Some(Extension(human)) = user else {
        return bad(StatusCode::UNAUTHORIZED, "no authenticated session");
    };
    let Ok(conversation_id) = Uuid::parse_str(id.trim()) else {
        return bad(StatusCode::BAD_REQUEST, "invalid conversation id");
    };
    let Some(store) = state.agent.conversations.get() else {
        return Json(json!({ "messages": [] })).into_response();
    };
    match store
        .messages(
            human.tenant.as_str(),
            &human.sub,
            conversation_id,
            HISTORY_LIMIT,
        )
        .await
    {
        Ok(rows) => {
            let messages: Vec<Value> = rows
                .iter()
                .map(|m| json!({ "role": m.role, "text": flatten_message_text(&m.content) }))
                .collect();
            Json(json!({ "messages": messages })).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "agent chat: load conversation failed");
            bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to load conversation",
            )
        }
    }
}

/// Flatten a stored message's `content` (`Vec<ContentPart>` JSON) to display
/// text for resume: text parts verbatim, a tool-use as `↳ called <name>(<args>)`,
/// a tool-result as its content. Unknown shapes degrade to empty.
fn flatten_message_text(content: &Value) -> String {
    let Some(parts) = content.as_array() else {
        return String::new();
    };
    let mut out: Vec<String> = Vec::new();
    for part in parts {
        match part.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(t) = part.get("text").and_then(Value::as_str) {
                    if !t.is_empty() {
                        out.push(t.to_owned());
                    }
                }
            }
            Some("tool_use") => {
                let name = part.get("name").and_then(Value::as_str).unwrap_or("tool");
                let args = part.get("arguments").and_then(Value::as_str).unwrap_or("");
                out.push(format!("↳ called {name}({args})"));
            }
            Some("tool_result") => {
                if let Some(c) = part.get("content").and_then(Value::as_str) {
                    out.push(c.to_owned());
                }
            }
            _ => {}
        }
    }
    out.join("\n")
}

/// The loop's [`AgentEventSink`] over the SSE channel: each [`AgentEvent`] is
/// serialized to one `data:` frame. A closed channel (browser hung up) drops
/// frames silently — the loop still runs to completion to persist the turn.
struct ChannelSink {
    tx: tokio::sync::mpsc::UnboundedSender<Event>,
}

impl AgentEventSink for ChannelSink {
    fn emit(&mut self, event: AgentEvent) {
        let data = serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_owned());
        let _ = self.tx.send(Event::default().data(data));
    }
}

/// Build a typed SSE frame (`event: <name>` + JSON `data`).
fn sse(event: &str, data: &str) -> Event {
    Event::default().event(event).data(data)
}

/// Resolve the conversation to persist into: an existing owned id, or a freshly
/// created one (titled from the first message). `None` ⇒ no store, or create
/// failed (chat still runs, just unpersisted).
async fn resolve_conversation(
    store: Option<&SharedConversationStore>,
    tenant: &str,
    user_sub: &str,
    agent_name: &str,
    requested: Option<&str>,
    first_message: &str,
    origin_page: Option<&str>,
) -> Option<Uuid> {
    let store = store?;
    if let Some(id) = requested.and_then(|s| Uuid::parse_str(s.trim()).ok()) {
        // Verify ownership; an unowned/missing id falls through to a new one.
        // A resumed conversation keeps its ORIGINAL origin_page — only the
        // create branch below records it, so a later turn from a different page
        // never rewrites where the thread began.
        match store.get(tenant, user_sub, id).await {
            Ok(Some(_)) => return Some(id),
            Ok(None) => {}
            Err(e) => {
                tracing::error!(error = %e, "agent chat: conversation lookup failed");
                return None;
            }
        }
    }
    match store
        .create(NewConversation {
            tenant_id: tenant,
            user_sub,
            agent_name,
            title: &conversation_title(first_message),
            origin_page,
        })
        .await
    {
        Ok(c) => Some(c.id),
        Err(e) => {
            tracing::error!(error = %e, "agent chat: conversation create failed");
            None
        }
    }
}

/// A short conversation title derived from the first user message.
fn conversation_title(message: &str) -> String {
    let t = message.trim();
    if t.is_empty() {
        return "New conversation".to_owned();
    }
    let truncated: String = t.chars().take(60).collect();
    if t.chars().count() > 60 {
        format!("{truncated}…")
    } else {
        truncated
    }
}

/// Load a conversation's prior transcript as canonical messages (system rows are
/// never stored, so this is purely user/assistant/tool turns).
async fn load_history(
    store: &SharedConversationStore,
    tenant: &str,
    user_sub: &str,
    id: Uuid,
) -> Vec<CanonicalMessage> {
    match store.messages(tenant, user_sub, id, HISTORY_LIMIT).await {
        Ok(rows) => rows
            .iter()
            .filter_map(|m| stored_to_message(&m.role, &m.content))
            .collect(),
        Err(e) => {
            tracing::error!(error = %e, "agent chat: load history failed");
            Vec::new()
        }
    }
}

/// Persist one canonical message; failures are logged, not fatal to the turn.
async fn persist_message(
    store: &SharedConversationStore,
    tenant: &str,
    user_sub: &str,
    id: Uuid,
    m: &CanonicalMessage,
) {
    let content = serde_json::to_value(&m.content).unwrap_or(Value::Null);
    if let Err(e) = store
        .append_message(tenant, user_sub, id, role_str(m.role), &content)
        .await
    {
        tracing::error!(error = %e, "agent chat: persist message failed");
    }
}

/// Canonical role → stored role string.
fn role_str(r: Role) -> &'static str {
    match r {
        Role::System => "system",
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => "tool",
    }
}

/// Stored `(role, content)` → canonical message. `None` ⇒ unparseable content or
/// an unknown/`system` role (system prompts are regenerated, never replayed).
fn stored_to_message(role: &str, content: &Value) -> Option<CanonicalMessage> {
    let role = match role {
        "user" => Role::User,
        "assistant" => Role::Assistant,
        "tool" => Role::Tool,
        // `system` is regenerated each turn; anything else is unknown.
        _ => return None,
    };
    let parts: Vec<ContentPart> = serde_json::from_value(content.clone()).ok()?;
    Some(CanonicalMessage {
        role,
        content: parts,
    })
}

/// Validate the submitted CSRF token against the per-session token. Absent
/// injection (no auth layer) ⇒ reject.
fn csrf_ok(injected: Option<&Extension<CsrfToken>>, submitted: &str) -> bool {
    match injected {
        Some(Extension(CsrfToken(expected))) => {
            !submitted.is_empty() && csrf_matches(expected, submitted)
        }
        None => false,
    }
}

/// A JSON error response with the given status.
fn bad(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": { "message": message } }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_str_roundtrips_through_stored_to_message() {
        for (role, s) in [
            (Role::User, "user"),
            (Role::Assistant, "assistant"),
            (Role::Tool, "tool"),
        ] {
            assert_eq!(role_str(role), s);
            let m =
                stored_to_message(s, &json!([{ "type": "text", "text": "hi" }])).expect("parse");
            assert_eq!(role_str(m.role), s);
        }
    }

    #[test]
    fn stored_to_message_skips_system_and_unknown_roles() {
        let c = json!([{ "type": "text", "text": "x" }]);
        assert!(stored_to_message("system", &c).is_none());
        assert!(stored_to_message("bogus", &c).is_none());
    }

    #[test]
    fn stored_to_message_parses_tool_use_and_result() {
        let assistant = stored_to_message(
            "assistant",
            &json!([{ "type": "tool_use", "id": "c1", "name": "t", "arguments": "{}" }]),
        )
        .expect("assistant");
        assert!(matches!(assistant.content[0], ContentPart::ToolUse { .. }));
        let tool = stored_to_message(
            "tool",
            &json!([{ "type": "tool_result", "tool_call_id": "c1", "content": "ok" }]),
        )
        .expect("tool");
        assert!(matches!(tool.content[0], ContentPart::ToolResult { .. }));
    }

    #[test]
    fn conversation_title_truncates_long_messages() {
        assert_eq!(conversation_title("  "), "New conversation");
        assert_eq!(conversation_title("hello"), "hello");
        let long = "a".repeat(100);
        let t = conversation_title(&long);
        assert!(t.ends_with('…'));
        assert_eq!(t.chars().count(), 61); // 60 chars + ellipsis
    }

    #[test]
    fn flatten_message_text_renders_each_part_kind() {
        // Text verbatim.
        assert_eq!(
            flatten_message_text(&json!([{ "type": "text", "text": "hello" }])),
            "hello"
        );
        // Tool-use → a readable "called" line.
        assert_eq!(
            flatten_message_text(
                &json!([{ "type": "tool_use", "id": "c1", "name": "send", "arguments": "{\"to\":\"x\"}" }])
            ),
            "↳ called send({\"to\":\"x\"})"
        );
        // Tool-result → its content.
        assert_eq!(
            flatten_message_text(
                &json!([{ "type": "tool_result", "tool_call_id": "c1", "content": "ok" }])
            ),
            "ok"
        );
        // Mixed parts joined; unknown/empty shapes ignored.
        assert_eq!(
            flatten_message_text(&json!([
                { "type": "text", "text": "a" },
                { "type": "image_url", "url": "x" },
                { "type": "text", "text": "b" }
            ])),
            "a\nb"
        );
        // Non-array → empty.
        assert_eq!(flatten_message_text(&json!({ "nope": 1 })), "");
    }

    #[test]
    fn csrf_ok_requires_matching_nonempty_token() {
        let tok = Extension(CsrfToken("expected".into()));
        assert!(csrf_ok(Some(&tok), "expected"));
        assert!(!csrf_ok(Some(&tok), "wrong"));
        assert!(!csrf_ok(Some(&tok), ""));
        assert!(!csrf_ok(None, "expected"));
    }
}
