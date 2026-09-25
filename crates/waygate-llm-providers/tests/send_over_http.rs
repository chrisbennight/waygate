//! Exercises the provider client against a loopback HTTP server (no real
//! network, no real provider) — mirrors the `waygate-llm-credentials` and
//! `waygate-upstream` test pattern (ephemeral `TcpListener` + `axum::serve`).
//!
//! Covers the three transport contracts: a unary JSON call forwards the body
//! and a `Bearer` auth header and parses the response; a streaming call yields
//! the provider's SSE `data:` frames (including the `[DONE]` sentinel); and a
//! non-2xx response surfaces as `ProviderError::Status` with the body snippet.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use futures::StreamExt;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use waygate_llm_providers::{
    codex_fp_user_agent, ProviderAuth, ProviderClient, ProviderError, ProviderRequest,
    ProviderResponse, CODEX_FP_DEFAULT_VERSION,
};

#[tokio::test]
async fn images_bounded_transport_refuses_oversized_chunked_responses() {
    let app = Router::new().route(
        "/images/generations",
        post(|| async {
            let chunks = futures::stream::iter([
                Ok::<_, std::io::Error>("{\"data\":[\""),
                Ok("a response too large for the configured byte limit"),
                Ok("\"]}"),
            ]);
            Response::builder()
                .header("content-type", "application/json")
                .body(Body::from_stream(chunks))
                .unwrap()
        }),
    );
    let addr = spawn(app).await;
    let result = ProviderClient::new(reqwest::Client::new())
        .with_single_attempt_http(reqwest::Client::builder())
        .unwrap()
        .send_bounded(
            ProviderRequest {
                base_url: format!("http://{addr}"),
                path: "images/generations".into(),
                bearer: "fixture".into(),
                auth: ProviderAuth::Bearer,
                body: json!({}),
                stream: false,
                account_id: None,
                codex_ua_version: None,
            },
            32,
        )
        .await;
    assert!(
        matches!(result,Err(ProviderError::Protocol(message)) if message.contains("byte limit"))
    );
}

/// What the unary handler captured from the inbound request.
#[derive(Default)]
struct Captured {
    authorization: Option<String>,
    x_api_key: Option<String>,
    anthropic_version: Option<String>,
    anthropic_beta: Option<String>,
    x_app: Option<String>,
    user_agent: Option<String>,
    x_stainless_os: Option<String>,
    x_stainless_arch: Option<String>,
    x_stainless_runtime: Option<String>,
    x_stainless_runtime_version: Option<String>,
    x_stainless_lang: Option<String>,
    x_stainless_retry_count: Option<String>,
    x_stainless_timeout: Option<String>,
    x_stainless_package_version: Option<String>,
    session_id: Option<String>,
    client_request_id: Option<String>,
    body: Option<Value>,
}

async fn unary_handler(
    State(captured): State<Arc<Mutex<Captured>>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    {
        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let mut c = captured.lock().unwrap();
        c.authorization = header("authorization");
        c.x_api_key = header("x-api-key");
        c.anthropic_version = header("anthropic-version");
        c.anthropic_beta = header("anthropic-beta");
        c.x_app = header("x-app");
        c.user_agent = header("user-agent");
        c.x_stainless_os = header("x-stainless-os");
        c.x_stainless_arch = header("x-stainless-arch");
        c.x_stainless_runtime = header("x-stainless-runtime");
        c.x_stainless_runtime_version = header("x-stainless-runtime-version");
        c.x_stainless_lang = header("x-stainless-lang");
        c.x_stainless_retry_count = header("x-stainless-retry-count");
        c.x_stainless_timeout = header("x-stainless-timeout");
        c.x_stainless_package_version = header("x-stainless-package-version");
        c.session_id = header("x-claude-code-session-id");
        c.client_request_id = header("x-client-request-id");
        c.body = serde_json::from_str(&body).ok();
    }
    let resp = json!({
        "id": "chatcmpl-1",
        "model": "served-x",
        "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "hi"}}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 1}
    })
    .to_string();
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Body::from(resp))
        .unwrap()
}

async fn stream_handler() -> Response {
    // Two content deltas, a usage-bearing terminal chunk, then [DONE].
    let sse = concat!(
        "data: {\"choices\":[{\"delta\":{\"content\":\"He\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"llo\"}}]}\n\n",
        "data: {\"choices\":[{\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2}}\n\n",
        "data: [DONE]\n\n",
    );
    Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .body(Body::from(sse))
        .unwrap()
}

async fn error_handler() -> Response {
    Response::builder()
        .status(429)
        .header("retry-after", "7")
        .body(Body::from("rate limited; retry later"))
        .unwrap()
}

async fn big_error_handler() -> Response {
    // A 4 KiB error body — larger than the client's read cap, so the client
    // must bound how much it reads rather than buffer it all.
    Response::builder()
        .status(500)
        .body(Body::from("E".repeat(4096)))
        .unwrap()
}

async fn spawn(app: Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

fn base(addr: SocketAddr) -> String {
    format!("http://{addr}")
}

#[tokio::test]
async fn unary_call_forwards_bearer_and_body_and_parses_response() {
    let captured = Arc::new(Mutex::new(Captured::default()));
    let app = Router::new()
        .route("/chat/completions", post(unary_handler))
        .with_state(captured.clone());
    let addr = spawn(app).await;

    let client = ProviderClient::new(reqwest::Client::new());
    let resp = client
        .send(ProviderRequest {
            base_url: base(addr),
            path: "chat/completions".into(),
            bearer: "tok-123".into(),
            auth: ProviderAuth::Bearer,
            body: json!({"model": "alias", "messages": [{"role": "user", "content": "hi"}]}),
            stream: false,
            account_id: None,
            codex_ua_version: None,
        })
        .await
        .expect("unary call");

    match resp {
        ProviderResponse::Unary(v) => {
            assert_eq!(v["model"], "served-x");
            assert_eq!(v["usage"]["prompt_tokens"], 3);
        }
        other => panic!("expected Unary, got {other:?}"),
    }

    let c = captured.lock().unwrap();
    assert_eq!(c.authorization.as_deref(), Some("Bearer tok-123"));
    assert_eq!(
        c.body.as_ref().unwrap()["messages"][0]["content"],
        "hi",
        "request body must be forwarded verbatim"
    );
}

#[tokio::test]
async fn streaming_call_yields_sse_frames_then_done() {
    let app = Router::new().route("/chat/completions", post(stream_handler));
    let addr = spawn(app).await;

    let client = ProviderClient::new(reqwest::Client::new());
    let resp = client
        .send(ProviderRequest {
            base_url: base(addr),
            path: "chat/completions".into(),
            bearer: "tok".into(),
            auth: ProviderAuth::Bearer,
            body: json!({"model": "m", "stream": true,
                "messages": [{"role": "user", "content": "hi"}]}),
            stream: true,
            account_id: None,
            codex_ua_version: None,
        })
        .await
        .expect("streaming call");

    let events = match resp {
        ProviderResponse::Stream(s) => s.collect::<Vec<_>>().await,
        other => panic!("expected Stream, got {other:?}"),
    };
    let events: Vec<_> = events.into_iter().map(|e| e.expect("frame")).collect();

    // Two deltas + terminal usage chunk + [DONE].
    assert_eq!(events.len(), 4);
    assert!(events[0].data.contains("\"He\""));
    assert!(events[2].data.contains("\"usage\""));
    assert!(events[3].is_done());
    assert!(events[..3].iter().all(|e| !e.is_done()));
}

#[tokio::test]
async fn non_2xx_status_surfaces_as_status_error_with_body() {
    let app = Router::new().route("/chat/completions", post(error_handler));
    let addr = spawn(app).await;

    let client = ProviderClient::new(reqwest::Client::new());
    let err = client
        .send(ProviderRequest {
            base_url: base(addr),
            path: "chat/completions".into(),
            bearer: "tok".into(),
            auth: ProviderAuth::Bearer,
            body: json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]}),
            stream: false,
            account_id: None,
            codex_ua_version: None,
        })
        .await
        .expect_err("should be an HTTP error");

    match err {
        ProviderError::Status {
            status,
            body,
            retry_after,
        } => {
            assert_eq!(status, 429);
            assert!(
                body.contains("rate limited"),
                "body snippet retained: {body}"
            );
            // The `Retry-After: 7` header is parsed (delta-seconds form).
            assert_eq!(retry_after, Some(std::time::Duration::from_secs(7)));
        }
        other => panic!("expected Status error, got {other:?}"),
    }
}

#[tokio::test]
async fn oversized_error_body_is_bounded() {
    let app = Router::new().route("/chat/completions", post(big_error_handler));
    let addr = spawn(app).await;

    let client = ProviderClient::new(reqwest::Client::new());
    let err = client
        .send(ProviderRequest {
            base_url: base(addr),
            path: "chat/completions".into(),
            bearer: "tok".into(),
            auth: ProviderAuth::Bearer,
            body: json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]}),
            stream: false,
            account_id: None,
            codex_ua_version: None,
        })
        .await
        .expect_err("should be an HTTP error");

    match err {
        ProviderError::Status { status, body, .. } => {
            assert_eq!(status, 500);
            // The server sent 4 KiB; the retained snippet is bounded to the
            // documented cap (2048 bytes), proving the body is not fully read.
            assert!(
                body.len() <= 2048,
                "error body must be bounded, got {} bytes",
                body.len()
            );
            assert!(!body.is_empty(), "a snippet is still retained");
        }
        other => panic!("expected Status error, got {other:?}"),
    }
}

#[tokio::test]
async fn anthropic_auth_sends_api_key_and_version_without_oauth_fingerprint() {
    // Anthropic authenticates with a first-party API key (`x-api-key`) +
    // `anthropic-version`. The prior subscription-OAuth / Claude Code device
    // fingerprint (Bearer + anthropic-beta + x-stainless + a session id) was
    // removed (ToS/ban risk), so NONE of it must appear on the wire.
    let captured = Arc::new(Mutex::new(Captured::default()));
    let app = Router::new()
        .route("/messages", post(unary_handler))
        .with_state(captured.clone());
    let addr = spawn(app).await;

    let client = ProviderClient::new(reqwest::Client::new());
    client
        .send(ProviderRequest {
            base_url: base(addr),
            path: "messages".into(),
            bearer: "sk-ant-api03-xyz".into(),
            auth: ProviderAuth::Anthropic,
            body: json!({"model": "claude", "max_tokens": 16,
                "messages": [{"role": "user", "content": "hi"}]}),
            stream: false,
            account_id: None,
            codex_ua_version: None,
        })
        .await
        .expect("anthropic unary call");

    let c = captured.lock().unwrap();
    // The key rides in `x-api-key`, NOT `Authorization: Bearer`.
    assert_eq!(c.x_api_key.as_deref(), Some("sk-ant-api03-xyz"));
    assert_eq!(c.authorization, None, "must not send Authorization: Bearer");
    assert_eq!(c.anthropic_version.as_deref(), Some("2023-06-01"));
    // No Claude Code OAuth/impersonation headers.
    assert_eq!(
        c.anthropic_beta, None,
        "no anthropic-beta (OAuth fingerprint removed)"
    );
    assert_eq!(c.x_app, None, "no X-App: cli");
    assert_eq!(c.x_stainless_os, None, "no x-stainless device fingerprint");
    assert_eq!(c.session_id, None, "no x-claude-code-session-id");
    assert!(
        !c.user_agent
            .as_deref()
            .unwrap_or_default()
            .contains("claude-cli"),
        "no Claude Code User-Agent: {:?}",
        c.user_agent
    );
}

/// Records every inbound header (lowercased) so a test can assert the exact
/// Codex fingerprint without extending the shared `Captured` struct.
async fn header_capture_handler(
    State(captured): State<Arc<Mutex<std::collections::HashMap<String, String>>>>,
    headers: HeaderMap,
) -> Response {
    {
        let mut map = captured.lock().unwrap();
        for (name, value) in headers.iter() {
            if let Ok(v) = value.to_str() {
                map.insert(name.as_str().to_ascii_lowercase(), v.to_string());
            }
        }
    }
    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Body::from(json!({"id": "resp_1"}).to_string()))
        .unwrap()
}

#[tokio::test]
async fn openai_chatgpt_auth_sends_codex_fingerprint_with_account_id() {
    // ChatGPT-backend (Codex) auth: the access token as `Bearer`, the codex
    // originator + User-Agent + residency, a stable session_id mirrored to
    // x-client-request-id, x-codex-window-id = <session>:0, and the workspace id
    // as `chatgpt-account-id`. No `x-api-key`.
    let captured: Arc<Mutex<std::collections::HashMap<String, String>>> = Arc::default();
    let app = Router::new()
        .route("/responses", post(header_capture_handler))
        .with_state(captured.clone());
    let addr = spawn(app).await;

    ProviderClient::new(reqwest::Client::new())
        .send(ProviderRequest {
            base_url: base(addr),
            path: "responses".into(),
            bearer: "codex-access-tok".into(),
            auth: ProviderAuth::OpenAiChatGpt,
            body: json!({"model": "gpt-x", "input": "hi"}),
            stream: false,
            account_id: Some("org-workspace-1".into()),
            codex_ua_version: None,
        })
        .await
        .expect("chatgpt-backend unary call");

    let h = captured.lock().unwrap();
    let get = |k: &str| h.get(k).map(String::as_str);
    assert_eq!(get("authorization"), Some("Bearer codex-access-tok"));
    assert_eq!(get("originator"), Some("codex_cli_rs"));
    assert_eq!(get("chatgpt-account-id"), Some("org-workspace-1"));
    assert_eq!(get("x-openai-internal-codex-residency"), Some("us"));
    assert_eq!(
        get("user-agent"),
        Some(codex_fp_user_agent(CODEX_FP_DEFAULT_VERSION).as_str()),
        "no supplied version ⇒ the compiled default drives the codex User-Agent"
    );
    // session_id, x-client-request-id, and x-codex-window-id are all derived from
    // the one per-credential session id (keyed on the bearer): the first two
    // equal, the window is `:0`.
    let sid = get("session_id").expect("session_id present");
    assert_eq!(get("x-client-request-id"), Some(sid));
    assert_eq!(get("x-codex-window-id"), Some(format!("{sid}:0").as_str()));
    assert_eq!(
        get("x-api-key"),
        None,
        "ChatGPT backend uses Bearer, not x-api-key"
    );
}

#[tokio::test]
async fn openai_chatgpt_auth_omits_account_id_header_when_absent() {
    // A personal (non-workspace) Codex token carries no account id; the
    // `chatgpt-account-id` header must then be absent rather than empty.
    let captured: Arc<Mutex<std::collections::HashMap<String, String>>> = Arc::default();
    let app = Router::new()
        .route("/responses", post(header_capture_handler))
        .with_state(captured.clone());
    let addr = spawn(app).await;

    ProviderClient::new(reqwest::Client::new())
        .send(ProviderRequest {
            base_url: base(addr),
            path: "responses".into(),
            bearer: "codex-access-tok".into(),
            auth: ProviderAuth::OpenAiChatGpt,
            body: json!({"model": "gpt-x", "input": "hi"}),
            stream: false,
            account_id: None,
            codex_ua_version: Some("9.9.9".into()),
        })
        .await
        .expect("chatgpt-backend unary call");

    let h = captured.lock().unwrap();
    assert!(
        !h.contains_key("chatgpt-account-id"),
        "no account id ⇒ header omitted"
    );
    assert_eq!(
        h.get("originator").map(String::as_str),
        Some("codex_cli_rs"),
        "the rest of the fingerprint is still sent"
    );
    assert_eq!(
        h.get("user-agent").map(String::as_str),
        Some(codex_fp_user_agent("9.9.9").as_str()),
        "a supplied version drives the codex User-Agent verbatim"
    );
}

#[tokio::test]
async fn unary_response_limits_cover_fixed_and_chunked_bodies_and_recover() {
    let app = Router::new().route(
        "/bounded",
        post(|headers: HeaderMap| async move {
            let body = "{\"result\":\"ok\"}";
            let mut response = Response::builder().header("content-type", "application/json");
            if headers.contains_key("x-fixed-length") {
                response = response.header("content-length", body.len());
            }
            response
                .body(Body::from_stream(futures::stream::iter([
                    Ok::<_, std::io::Error>(&body[..5]),
                    Ok(&body[5..]),
                ])))
                .unwrap()
        }),
    );
    let addr = spawn(app).await;
    for fixed in [false, true] {
        let mut headers = reqwest::header::HeaderMap::new();
        if fixed {
            headers.insert(
                "x-fixed-length",
                reqwest::header::HeaderValue::from_static("yes"),
            );
        }
        let provider = ProviderClient::new(
            reqwest::Client::builder()
                .default_headers(headers)
                .build()
                .unwrap(),
        );
        for limit in [14, 15, 16] {
            let result = provider
                .send_with_limit(
                    ProviderRequest {
                        base_url: format!("http://{addr}"),
                        path: "bounded".into(),
                        bearer: String::new(),
                        auth: ProviderAuth::None,
                        body: json!({}),
                        stream: false,
                        account_id: None,
                        codex_ua_version: None,
                    },
                    limit,
                )
                .await;
            if limit < "{\"result\":\"ok\"}".len() {
                assert!(
                    matches!(result, Err(ProviderError::Protocol(message)) if message.contains("byte limit"))
                );
            } else {
                assert!(
                    matches!(result, Ok(ProviderResponse::Unary(body)) if body["result"] == "ok")
                );
            }
        }
    }
}

#[tokio::test]
async fn default_chat_limit_refuses_large_body_that_embedding_limit_accepts() {
    let content = "x".repeat(waygate_llm_providers::MAX_CHAT_RESPONSE_BYTES);
    let app = Router::new().route(
        "/large",
        post(move || {
            let content = content.clone();
            async move {
                Response::builder()
                    .header("content-type", "application/json")
                    .body(Body::from_stream(futures::stream::iter([
                        Ok::<_, std::io::Error>("\"".to_owned()),
                        Ok(content),
                        Ok("\"".to_owned()),
                    ])))
                    .unwrap()
            }
        }),
    );
    let addr = spawn(app).await;
    let request = || ProviderRequest {
        base_url: format!("http://{addr}"),
        path: "large".into(),
        bearer: String::new(),
        auth: ProviderAuth::None,
        body: json!({}),
        stream: false,
        account_id: None,
        codex_ua_version: None,
    };
    let provider = ProviderClient::new(reqwest::Client::new());
    assert!(
        matches!(provider.send(request()).await, Err(ProviderError::Protocol(message)) if message.contains("byte limit"))
    );
    assert!(matches!(
        provider
            .send_with_limit(
                request(),
                waygate_llm_providers::MAX_EMBEDDING_RESPONSE_BYTES
            )
            .await,
        Ok(ProviderResponse::Unary(_))
    ));
}
