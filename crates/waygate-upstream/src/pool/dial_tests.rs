//! The pool's dial against a streamable-HTTP upstream that requires a bearer
//! on every request.
//!
//! These tests sit beside [`dial`] rather than in the integration suite
//! because `auth.bearer_env` is read from the process environment, which the
//! integration suite must not change. Each test sets a variable name that no
//! other test reads.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse as _, Response};
use rmcp::model::{
    Implementation, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};

use super::*;

/// A synthetic credential. It must never appear in a dial error.
const FIXTURE_BEARER: &str = "fixture-bearer-4d61e0c2";

#[derive(Clone)]
struct OneToolUpstream;

impl ServerHandler for OneToolUpstream {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("bearer-upstream", "0.0.0"))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let schema = serde_json::json!({"type": "object", "properties": {}});
        Ok(ListToolsResult::with_all_items(vec![Tool::new(
            "ping",
            "answers",
            Arc::new(schema.as_object().cloned().expect("schema is an object")),
        )]))
    }
}

#[derive(Clone, Copy)]
enum ToolsListReply {
    Serve,
    /// Answer `tools/list` with an event stream that ends before any event.
    CloseEventStream,
    /// Answer `tools/list` with one JSON-RPC error that names no request id,
    /// which the SDK cannot route, then end the stream.
    ErrorWithoutId,
    /// Answer `tools/list`, after a successful handshake, with a redirect.
    Redirect,
}

/// What the bearer-gated upstream observed.
#[derive(Default)]
struct Observed {
    /// `params.protocolVersion` of every `initialize`, in arrival order.
    proposed_versions: Mutex<Vec<String>>,
    discovery_probes: AtomicUsize,
    unauthenticated: AtomicUsize,
}

impl Observed {
    fn proposed_versions(&self) -> Vec<String> {
        self.proposed_versions
            .lock()
            .expect("observation lock")
            .clone()
    }
}

/// A legacy-session MCP upstream behind a gate that refuses any request
/// without the fixture bearer, optionally refuses discovery with
/// `discovery_status`, and records what each `initialize` proposed.
async fn spawn_bearer_upstream(
    discovery_status: Option<StatusCode>,
    tools_list: ToolsListReply,
) -> (SocketAddr, Arc<Observed>) {
    let observed = Arc::new(Observed::default());
    let service = StreamableHttpService::new(
        || Ok(OneToolUpstream),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_legacy_session_mode(true),
    );
    let gate_observed = Arc::clone(&observed);
    let app = axum::Router::new()
        .nest_service("/mcp", service)
        .layer(axum::middleware::from_fn(
            move |request: Request, next: Next| {
                let observed = Arc::clone(&gate_observed);
                async move { gate(&observed, discovery_status, tools_list, request, next).await }
            },
        ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test upstream");
    let address = listener.local_addr().expect("test upstream address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (address, observed)
}

async fn gate(
    observed: &Observed,
    discovery_status: Option<StatusCode>,
    tools_list: ToolsListReply,
    request: Request,
    next: Next,
) -> Response {
    let expected = format!("Bearer {FIXTURE_BEARER}");
    let authorized = request
        .headers()
        .get(header::AUTHORIZATION)
        .is_some_and(|value| value.as_bytes() == expected.as_bytes());
    if !authorized {
        observed.unauthenticated.fetch_add(1, Ordering::SeqCst);
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 20)
        .await
        .expect("read request body");
    let message = serde_json::from_slice::<serde_json::Value>(&bytes).ok();
    let method = message
        .as_ref()
        .and_then(|message| message.get("method"))
        .and_then(serde_json::Value::as_str);
    match (method, discovery_status, tools_list) {
        (Some("server/discover"), Some(status), _) => {
            observed.discovery_probes.fetch_add(1, Ordering::SeqCst);
            return (status, "discovery refused").into_response();
        }
        (Some("server/discover"), None, _) => {
            observed.discovery_probes.fetch_add(1, Ordering::SeqCst);
        }
        (Some("initialize"), _, _) => {
            let proposed = message
                .as_ref()
                .and_then(|message| message.pointer("/params/protocolVersion"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<missing>")
                .to_owned();
            observed
                .proposed_versions
                .lock()
                .expect("observation lock")
                .push(proposed);
        }
        (Some("tools/list"), _, ToolsListReply::CloseEventStream) => {
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(Body::empty())
                .expect("event-stream response");
        }
        (Some("tools/list"), _, ToolsListReply::Redirect) => {
            return Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header(header::LOCATION, "http://127.0.0.1:9/elsewhere")
                .body(Body::empty())
                .expect("redirect response");
        }
        (Some("tools/list"), _, ToolsListReply::ErrorWithoutId) => {
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(Body::from(
                    "data: {\"jsonrpc\":\"2.0\",\"id\":null,\"error\":\
                     {\"code\":-32600,\"message\":\"Bad Request: session not ready\"}}\n\n",
                ))
                .expect("event-stream response");
        }
        _ => {}
    }
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

/// Sets a test-only bearer variable for the life of one test.
struct BearerEnv(&'static str);

impl BearerEnv {
    fn set(name: &'static str) -> Self {
        // SAFETY: `set_var` is process-global; the name is unique to one test,
        // so no concurrent reader can observe it.
        unsafe { std::env::set_var(name, FIXTURE_BEARER) };
        Self(name)
    }
}

impl Drop for BearerEnv {
    fn drop(&mut self) {
        // SAFETY: as in `set`, the name is unique to one test.
        unsafe { std::env::remove_var(self.0) };
    }
}

fn manifest(address: SocketAddr, protocol: &str, bearer: &BearerEnv) -> UpstreamManifest {
    serde_yaml::from_str(&format!(
        "name: bearer-upstream\ntransport: http\nurl: http://{address}/mcp\n\
         protocol: \"{protocol}\"\nauth:\n  bearer_env: {}\n",
        bearer.0
    ))
    .expect("test manifest parses")
}

fn tool_names(connection: &Connection) -> Vec<String> {
    connection
        .live_tools
        .iter()
        .map(|tool| tool.name.to_string())
        .collect()
}

#[tokio::test]
async fn a_legacy_bearer_dial_lists_tools_and_proposes_the_newest_version() {
    let bearer = BearerEnv::set("GW_TEST_DIAL_LEGACY_BEARER");
    let (address, observed) = spawn_bearer_upstream(None, ToolsListReply::Serve).await;

    let connection = dial(&manifest(address, "legacy", &bearer), None, None)
        .await
        .expect("a bearer-authenticated legacy upstream connects");

    assert_eq!(tool_names(&connection), vec!["ping".to_owned()]);
    assert_eq!(
        connection.negotiated_protocol.as_deref(),
        Some("2025-11-25")
    );
    assert_eq!(
        observed.proposed_versions(),
        vec![rmcp::model::ProtocolVersion::LATEST.as_str().to_owned()]
    );
    assert_eq!(observed.discovery_probes.load(Ordering::SeqCst), 0);
    assert_eq!(observed.unauthenticated.load(Ordering::SeqCst), 0);
}

/// An upstream that refuses the discovery probe, whether with an
/// authentication failure or a server error, is reached through the `auto`
/// bridge, whose handshake proposes the newest version.
#[tokio::test]
async fn the_auto_bridge_after_a_refused_discovery_proposes_the_newest_version() {
    let bearer = BearerEnv::set("GW_TEST_DIAL_AUTO_BRIDGE_BEARER");
    for status in [StatusCode::UNAUTHORIZED, StatusCode::SERVICE_UNAVAILABLE] {
        let (address, observed) = spawn_bearer_upstream(Some(status), ToolsListReply::Serve).await;

        let connection = dial(&manifest(address, "auto", &bearer), None, None)
            .await
            .unwrap_or_else(|error| panic!("discovery refused with {status}: {error}"));

        assert_eq!(tool_names(&connection), vec!["ping".to_owned()], "{status}");
        assert_eq!(
            connection.negotiated_protocol.as_deref(),
            Some("2025-11-25"),
            "{status}"
        );
        assert_eq!(
            observed.discovery_probes.load(Ordering::SeqCst),
            1,
            "{status}: the bridge follows exactly one refused probe"
        );
        assert_eq!(
            observed.proposed_versions(),
            vec![rmcp::model::ProtocolVersion::LATEST.as_str().to_owned()],
            "{status}"
        );
        assert_eq!(
            observed.unauthenticated.load(Ordering::SeqCst),
            0,
            "{status}"
        );
    }
}

#[tokio::test]
async fn a_tools_list_stream_that_closes_without_a_response_is_named_in_the_dial_error() {
    let bearer = BearerEnv::set("GW_TEST_DIAL_CLOSED_STREAM_BEARER");
    let (address, observed) = spawn_bearer_upstream(None, ToolsListReply::CloseEventStream).await;

    let error = match dial(&manifest(address, "legacy", &bearer), None, None).await {
        Ok(_) => panic!("a catalog that never arrives must fail the dial"),
        Err(error) => error,
    };

    let text = error.to_string();
    assert!(matches!(error, DialError::ListTools(_)), "{text}");
    assert!(
        text.starts_with("tools/list failed: Transport closed; HTTP exchanges on this dial: "),
        "{text}"
    );
    assert!(text.contains("POST initialize -> "), "{text}");
    assert!(
        text.contains(
            "POST tools/list -> event stream, 0 events, 0 data events, \
             no readable answer to this request, ended normally after "
        ),
        "{text}"
    );
    assert!(!text.contains(FIXTURE_BEARER), "{text}");
    assert_eq!(observed.unauthenticated.load(Ordering::SeqCst), 0);
}

/// A redirect that arrives after the handshake is still a refused redirect,
/// reported as the configuration error it is rather than a catalog failure.
#[tokio::test]
async fn a_redirected_tools_list_fails_the_dial_as_a_refused_redirect() {
    let bearer = BearerEnv::set("GW_TEST_DIAL_REDIRECTED_LIST_BEARER");
    let (address, _observed) = spawn_bearer_upstream(None, ToolsListReply::Redirect).await;

    let error = match dial(&manifest(address, "legacy", &bearer), None, None).await {
        Ok(_) => panic!("a redirected catalog must fail the dial"),
        Err(error) => error,
    };

    let text = error.to_string();
    assert!(
        matches!(
            &error,
            DialError::RedirectRefused { server, status }
                if server == "bearer-upstream" && *status == StatusCode::TEMPORARY_REDIRECT
        ),
        "{text}"
    );
    assert_eq!(
        crate::pool::health::UpstreamErrorClass::from_dial_error(&error),
        crate::pool::health::UpstreamErrorClass::Configuration,
    );
    assert!(!text.contains("elsewhere"), "{text}");
    assert!(!text.contains(FIXTURE_BEARER), "{text}");
}

/// The SDK drops an error that names no request id without reporting it, so
/// the dial error alone would say only `Transport closed`. The summary names
/// what the stream carried instead.
#[tokio::test]
async fn a_tools_list_error_without_an_id_is_named_in_the_dial_error() {
    let bearer = BearerEnv::set("GW_TEST_DIAL_ID_LESS_ERROR_BEARER");
    let (address, _observed) = spawn_bearer_upstream(None, ToolsListReply::ErrorWithoutId).await;

    let error = match dial(&manifest(address, "legacy", &bearer), None, None).await {
        Ok(_) => panic!("an unroutable answer must fail the dial"),
        Err(error) => error,
    };

    let text = error.to_string();
    assert!(matches!(error, DialError::ListTools(_)), "{text}");
    assert!(
        text.contains(
            "POST tools/list -> event stream, 1 event, 1 data event, \
             no readable answer to this request, first other data event: \
             error without an id, code -32600: Bad Request: session not ready, \
             ended normally after "
        ),
        "{text}"
    );
    assert!(!text.contains(FIXTURE_BEARER), "{text}");
}

/// Both attempts of an `auto` dial share one record, so a failure after the
/// bridge still shows how discovery failed.
#[tokio::test]
async fn a_failure_after_the_auto_bridge_also_shows_the_refused_discovery() {
    let bearer = BearerEnv::set("GW_TEST_DIAL_SHARED_TRACE_BEARER");
    let (address, _observed) = spawn_bearer_upstream(
        Some(StatusCode::SERVICE_UNAVAILABLE),
        ToolsListReply::CloseEventStream,
    )
    .await;

    let error = match dial(&manifest(address, "auto", &bearer), None, None).await {
        Ok(_) => panic!("a catalog that never arrives must fail the dial"),
        Err(error) => error,
    };

    let text = error.to_string();
    let discovery = text
        .find("POST server/discover -> HTTP 503 after ")
        .unwrap_or_else(|| panic!("the refused probe is recorded: {text}"));
    let bridge = text
        .find("POST initialize -> ")
        .unwrap_or_else(|| panic!("the bridge's handshake is recorded: {text}"));
    assert!(discovery < bridge, "{text}");
    assert!(!text.contains(FIXTURE_BEARER), "{text}");
}

#[tokio::test]
async fn finishing_the_dial_stops_recording_while_the_connection_keeps_working() {
    let bearer = BearerEnv::set("GW_TEST_DIAL_FINISH_BEARER");
    let (address, _observed) = spawn_bearer_upstream(None, ToolsListReply::Serve).await;

    let dialed = transport::connect_with_destination(
        &manifest(address, "legacy", &bearer),
        None,
        None,
        None,
        None,
    )
    .await
    .expect("the upstream connects");
    let recorder = dialed.exchange_recorder();
    assert!(recorder.is_recording());

    let connected = dialed.finish_dial();

    assert!(!recorder.is_recording());
    let listed = list_all_tools(&connected.service)
        .await
        .expect("the established connection still serves requests");
    assert_eq!(listed.tools.len(), 1);
}
