//! End-to-end proof of MRTR passthrough (SEP-2322) against a real
//! streamable-HTTP upstream — the plan's risk-register spike, kept as the
//! permanent regression suite.
//!
//! The mock upstream's `confirm` tool pauses with an elicitation
//! `input_required` result *only when the request's declared client
//! capabilities include elicitation*, and completes by echoing the retry's
//! `inputResponses` + `requestState` otherwise. The tests drive the pool's
//! `call_tool_response` seam and pin four contracts:
//!
//! - a pause passes through the pool verbatim (requests + opaque state);
//! - a retry's `inputResponses`/`requestState` reach the upstream verbatim;
//! - the per-call ephemeral dial mirrors the downstream caller's declared
//!   capabilities, so the upstream pauses exactly when the caller can
//!   answer — and a caller that declared nothing never invites a pause;
//! - a reuse lane (shared across callers) advertises no capabilities, so a
//!   conforming upstream completes without pausing there.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ClientCapabilities,
    ContentBlock as Content, ElicitRequest, ElicitRequestParams, ElicitationSchema, Implementation,
    InputRequest, InputRequiredResult, InputResponses, ListToolsResult, PaginatedRequestParams,
    ProtocolVersion, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use tokio::net::TcpListener;

use waygate_mcp::catalog::{ToolCallMrtr, UpstreamCatalog};
use waygate_mcp::protocol::RiskTier;
use waygate_upstream::{
    SessionConfig, SessionIsolation, ToolClassification, Transport, UpstreamManifest, UpstreamPool,
};

const UPSTREAM_STATE: &str = "opaque-upstream-state-1";

/// One observed `tools/call`: the elicitation capability the request's
/// `_meta` declared, and the retry payload it carried (if any).
#[derive(Clone, Debug)]
struct ObservedCall {
    caller_declared_elicitation: bool,
    caller_declared_tasks: bool,
    input_responses: Option<InputResponses>,
    request_state: Option<String>,
}

#[derive(Clone, Default)]
struct MrtrUpstream {
    calls: Arc<Mutex<Vec<ObservedCall>>>,
}

impl ServerHandler for MrtrUpstream {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("mrtr-upstream", "0.0.0"))
            .with_protocol_version(ProtocolVersion::LATEST)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let schema = serde_json::json!({"type": "object", "properties": {}})
            .as_object()
            .cloned()
            .unwrap();
        Ok(ListToolsResult::with_all_items(vec![Tool::new(
            "confirm".to_string(),
            "asks for confirmation when the caller can answer".to_string(),
            Arc::new(schema),
        )]))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let caller_declared_elicitation = ctx
            .client_capabilities()
            .is_some_and(|caps| caps.elicitation.is_some());
        let caller_declared_tasks = ctx
            .client_capabilities()
            .is_some_and(|caps| caps.supports_tasks());
        let observed = ObservedCall {
            caller_declared_elicitation,
            caller_declared_tasks,
            input_responses: request.input_responses.clone(),
            request_state: request.request_state.clone(),
        };
        self.calls.lock().unwrap().push(observed);

        // A retry: complete, echoing what arrived so the test can assert
        // the round trip was verbatim.
        if let Some(responses) = request.input_responses {
            let echoed = serde_json::json!({
                "responses": responses,
                "request_state": request.request_state,
            });
            return Ok(CallToolResult::success(vec![Content::text(echoed.to_string())]).into());
        }
        // First round: pause only when this request's declared capabilities
        // say the caller can answer an elicitation.
        if caller_declared_elicitation {
            let elicit = ElicitRequest::new(ElicitRequestParams::FormElicitationParams {
                meta: None,
                message: "confirm the operation".to_owned(),
                requested_schema: ElicitationSchema::builder()
                    .required_string("choice")
                    .build_unchecked(),
            });
            let mut requests = rmcp::model::InputRequests::new();
            requests.insert("q1".to_owned(), InputRequest::Elicitation(elicit));
            return Ok(CallToolResponse::InputRequired(InputRequiredResult::new(
                Some(requests),
                Some(UPSTREAM_STATE.to_owned()),
            )));
        }
        Ok(CallToolResult::success(vec![Content::text("completed-without-elicitation")]).into())
    }
}

async fn spawn_upstream() -> (std::net::SocketAddr, MrtrUpstream) {
    let handler = MrtrUpstream::default();
    let factory = handler.clone();
    let svc = StreamableHttpService::new(
        move || Ok(factory.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_legacy_session_mode(true),
    );
    let app: Router<()> = Router::new().nest_service("/mcp", svc);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, handler)
}

fn manifest(addr: std::net::SocketAddr, isolation: Option<SessionIsolation>) -> UpstreamManifest {
    UpstreamManifest {
        classification_mode: Default::default(),
        approval_mode: Default::default(),
        name: "mock".into(),
        transport: Transport::Http,
        // Default `auto` negotiates 2026-07-28 against this mock — MRTR
        // passthrough only exists on that leg.
        protocol: Default::default(),
        url: Some(format!("http://{addr}/mcp")),
        command: None,
        tools: vec![ToolClassification::new(
            "confirm",
            RiskTier::Low,
            false,
            false,
        )],
        resources: Vec::new(),
        exchange: None,
        auth: None,
        mtls: None,
        tier_a_required: false,
        tier_c_peer: None,
        session: Some(SessionConfig {
            concurrency: Some(1),
            isolation,
            scope: None,
            retry_on_setup_failure: None,
        }),
    }
}

async fn connect(addr: std::net::SocketAddr, isolation: Option<SessionIsolation>) -> UpstreamPool {
    let mut manifests = BTreeMap::new();
    manifests.insert("mock".into(), manifest(addr, isolation));
    UpstreamPool::connect(manifests).await
}

/// The caller declares elicitation AND the SEP-2663 tasks extension — the
/// mirror must forward only the former: the tasks declaration is the
/// caller's contract with the gateway, and advertising it upstream would
/// invite a task envelope the gateway cannot proxy.
fn elicitation_caps() -> ClientCapabilities {
    ClientCapabilities::builder()
        .enable_elicitation()
        .enable_tasks()
        .build()
}

fn mrtr_with_caps() -> ToolCallMrtr {
    ToolCallMrtr {
        input_responses: None,
        request_state: None,
        caller_capabilities: Some(elicitation_caps()),
        approval_gated: false,
    }
}

#[tokio::test]
async fn pause_passes_through_and_the_retry_round_trip_is_verbatim() {
    let (addr, upstream) = spawn_upstream().await;
    let pool = connect(addr, None).await; // HTTP default: per-call isolation
    assert!(pool.is_connected("mock").await);

    // Round 1: a caller that can answer elicitation → the mirrored per-call
    // dial declares it → the upstream pauses, and the pause passes through
    // verbatim (requests + opaque state).
    let pause = match pool
        .call_tool_response("mock", "confirm", None, None, None, mrtr_with_caps())
        .await
        .expect("first round dispatches")
    {
        CallToolResponse::InputRequired(pause) => pause,
        other => panic!("expected a pass-through pause, got {other:?}"),
    };
    assert_eq!(pause.request_state.as_deref(), Some(UPSTREAM_STATE));
    let requests = pause.input_requests.expect("the elicitation ask survives");
    assert!(matches!(
        requests.get("q1"),
        Some(InputRequest::Elicitation(_))
    ));

    // Round 2: the retry carries the answer + echoed state; the upstream
    // must see both exactly as the caller sent them.
    let mut responses = InputResponses::new();
    responses.insert("q1".to_owned(), serde_json::json!({"choice": "yes"}));
    let retry = ToolCallMrtr {
        input_responses: Some(responses.clone()),
        request_state: pause.request_state.clone(),
        caller_capabilities: Some(elicitation_caps()),
        approval_gated: false,
    };
    match pool
        .call_tool_response("mock", "confirm", None, None, None, retry)
        .await
        .expect("retry completes")
    {
        CallToolResponse::Complete(_) => {}
        other => panic!("expected the retry to complete, got {other:?}"),
    }

    let calls = upstream.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2, "one pause round, one retry round");
    assert!(
        calls[0].caller_declared_elicitation,
        "the per-call dial must mirror the caller's declared elicitation",
    );
    assert!(
        calls.iter().all(|c| !c.caller_declared_tasks),
        "the mirror must not forward the caller's tasks extension upstream",
    );
    assert_eq!(calls[1].input_responses.as_ref(), Some(&responses));
    assert_eq!(calls[1].request_state.as_deref(), Some(UPSTREAM_STATE));
}

#[tokio::test]
async fn caller_without_capabilities_never_invites_a_pause() {
    let (addr, upstream) = spawn_upstream().await;
    let pool = connect(addr, None).await;

    // The legacy trait seam dispatches with no caller capabilities: the
    // mirrored dial declares nothing, so the upstream completes instead of
    // pausing — graceful degradation, not a stranded call.
    let result = pool
        .call_tool("mock", "confirm", None, None, None)
        .await
        .expect("completes without elicitation");
    let text = serde_json::to_value(&result).unwrap();
    assert!(text.to_string().contains("completed-without-elicitation"));
    let calls = upstream.calls.lock().unwrap().clone();
    assert!(
        calls.iter().all(|c| !c.caller_declared_elicitation),
        "a caller that declared nothing must not be mirrored as elicitation-capable",
    );
}

#[tokio::test]
async fn reuse_lane_advertises_no_capabilities_even_for_a_capable_caller() {
    let (addr, upstream) = spawn_upstream().await;
    let pool = connect(addr, Some(SessionIsolation::Reuse)).await;

    // A reuse lane is shared across callers, so its (single, boot-time)
    // dial cannot mirror any one caller: it declares nothing, and the
    // upstream completes rather than pausing — even though THIS caller
    // could have answered.
    match pool
        .call_tool_response("mock", "confirm", None, None, None, mrtr_with_caps())
        .await
        .expect("completes on the shared lane")
    {
        CallToolResponse::Complete(_) => {}
        other => panic!("expected completion on the shared lane, got {other:?}"),
    }
    let calls = upstream.calls.lock().unwrap().clone();
    assert!(
        calls.iter().all(|c| !c.caller_declared_elicitation),
        "a shared lane must not advertise one caller's capabilities to all",
    );
}

/// Operator configuration is authoritative over caller-supplied retry
/// fields: an upstream pinned to `protocol: legacy` (the operator's escape
/// hatch) can never have issued an MRTR pause, so a per-call continuation
/// aimed at it is refused before any dial — never used to force a
/// `server/discover` lifecycle the operator disabled, and never dispatched
/// onto a legacy leg that would silently ignore the fields.
#[tokio::test]
async fn per_call_continuation_is_refused_on_a_legacy_pinned_manifest() {
    let (addr, upstream) = spawn_upstream().await;
    let mut manifests = BTreeMap::new();
    let mut legacy_manifest = manifest(addr, None);
    legacy_manifest.protocol = waygate_upstream::UpstreamProtocol::Legacy;
    manifests.insert("mock".into(), legacy_manifest);
    let pool = UpstreamPool::connect(manifests).await;
    assert!(pool.is_connected("mock").await);

    let mut responses = InputResponses::new();
    responses.insert("q1".to_owned(), serde_json::json!({"choice": "yes"}));
    let retry = ToolCallMrtr {
        input_responses: Some(responses.clone()),
        request_state: Some(UPSTREAM_STATE.to_owned()),
        caller_capabilities: Some(elicitation_caps()),
        approval_gated: false,
    };
    let err = pool
        .call_tool_response("mock", "confirm", None, None, None, retry)
        .await
        .expect_err("a legacy-pinned manifest cannot host a continuation");
    assert!(
        err.message.contains("cannot have issued an MRTR pause"),
        "the refusal must name the configuration mismatch: {}",
        err.message,
    );
    assert!(
        upstream.calls.lock().unwrap().is_empty(),
        "the refused continuation must never reach the upstream",
    );
    let _ = responses;
}

/// A reuse lane has one fixed negotiated generation: a continuation must
/// not run on a legacy lane, whose upstream would silently ignore the
/// retry fields — the pool refuses with a teach-through instead.
#[tokio::test]
async fn reuse_lane_refuses_a_continuation_on_a_legacy_leg() {
    let (addr, upstream) = spawn_upstream().await;
    let mut manifests = BTreeMap::new();
    let mut legacy_manifest = manifest(addr, Some(SessionIsolation::Reuse));
    legacy_manifest.protocol = waygate_upstream::UpstreamProtocol::Legacy;
    manifests.insert("mock".into(), legacy_manifest);
    let pool = UpstreamPool::connect(manifests).await;
    assert!(pool.is_connected("mock").await);

    let retry = ToolCallMrtr {
        input_responses: None,
        request_state: Some(UPSTREAM_STATE.to_owned()),
        caller_capabilities: Some(elicitation_caps()),
        approval_gated: false,
    };
    let err = pool
        .call_tool_response("mock", "confirm", None, None, None, retry)
        .await
        .expect_err("a legacy reuse lane cannot deliver a continuation");
    // The configured-legacy manifest is screened before any lane is even
    // consulted; the lane-level check remains for an auto-configured lane
    // that reconnected as legacy mid-window.
    assert!(
        err.message.contains("cannot have issued an MRTR pause"),
        "the refusal must name the configuration mismatch: {}",
        err.message,
    );
    assert!(
        upstream.calls.lock().unwrap().is_empty(),
        "the refused continuation must never reach the upstream",
    );
}
